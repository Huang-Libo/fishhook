# fishhook

## Fork 说明

请参看：<https://huanglibo.gitbook.io/notebook/ios/fishhook>

## Introduction

__fishhook__ is a very simple library that enables **dynamically rebinding symbols in Mach-O** binaries running on iOS in the simulator and on device. This provides functionality that is similar to using [`DYLD_INTERPOSE`][interpose] on OS X.

At Facebook, we've found it useful as a way to hook calls in `libSystem` for **debugging / tracing purposes** (for example, auditing for double-close issues with file descriptors).

[interpose]: https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld-interposing.h.auto.html "<mach-o/dyld-interposing.h>"

## Usage

Once you add `fishhook.h`/`fishhook.c` to your project, you can **rebind symbols** as follows:

```Objective-C
#import <dlfcn.h>
#import <UIKit/UIKit.h>
#import "AppDelegate.h"
#import <fishhook/fishhook.h>
 
static int (*orig_close)(int);
static int (*orig_open)(const char *, int, ...);
 
int my_close(int fd) {
  printf("Calling real close(%d)\n", fd);
  return orig_close(fd);
}
 
int my_open(const char *path, int oflag, ...) {
  va_list ap = {0};
  mode_t mode = 0;
 
  if ((oflag & O_CREAT) != 0) {
    // mode only applies to O_CREAT
    va_start(ap, oflag);
    mode = va_arg(ap, int);
    va_end(ap);
    printf("Calling real open('%s', %d, %d)\n", path, oflag, mode);
    return orig_open(path, oflag, mode);
  } else {
    printf("Calling real open('%s', %d)\n", path, oflag);
    return orig_open(path, oflag, mode);
  }
}

int main(int argc, char * argv[]) {
    NSString * appDelegateClassName;
    @autoreleasepool {
        struct rebinding rebindings[2] = {
            {"close", my_close, (void *)&orig_close},
            {"open", my_open, (void *)&orig_open}
        };
        // Use fishhook to rebind symbols
        rebind_symbols(rebindings, 2);
     
        // Open our own binary and print out first 4 bytes
        // (which is the same for all Mach-O binaries on a given architecture)
        int fd = open(argv[0], O_RDONLY);
        uint32_t magic_number = 0;
        read(fd, &magic_number, 4);
        printf("Mach-O Magic Number: %x \n", magic_number);
        close(fd);

        // Setup code that might create autoreleased objects goes here.
        appDelegateClassName = NSStringFromClass([AppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
```

## Sample output

```plaintext
Calling real open('/var/containers/Bundle/Application/8250D7D8-4893-486C-B5FC-FB55AA110116/Example.app/Example', 0)
Mach-O Magic Number: feedfacf 
Calling real close(3)
...
```

## How it works

`dyld` binds *lazy* and *non-lazy* symbols by **updating pointers in particular sections** of the `__DATA` segment of a Mach-O binary.

__fishhook__ re-binds these symbols by **determining the locations to update** for each of the symbol names passed to `rebind_symbols`(fishhhook's function) and then writing out the corresponding replacements.

For a given image, the `__DATA` segment may contain two *sections* that are relevant for dynamic symbol bindings: `__nl_symbol_ptr` and `__la_symbol_ptr`.

- `__nl_symbol_ptr` is an array of pointers to non-lazily bound data (these are bound at the time a library is loaded) and
- `__la_symbol_ptr` is an array of pointers to imported functions that is generally filled by a routine called `dyld_stub_binder` during the first call to that symbol (it's also possible to tell `dyld` to bind these at launch).

In order to find the name of the symbol that corresponds to a particular location in one of these sections, we have to jump through several layers of indirection.

For the two relevant sections, the section headers (`struct section`s from `<mach-o/loader.h>`) provide an offset (in the `reserved1` field) into what is known as the **indirect symbol table**.

The **indirect symbol table**, which is located in the `__LINKEDIT` segment of the binary, is just **an array of indexes into the symbol table** (also in `__LINKEDIT`) whose order is identical to that of the pointers in the *non-lazy* and *lazy symbol* sections.

---

So, given `struct section nl_symbol_ptr`, the corresponding index in the **symbol table** of the first address in that section is `indirect_symbol_table[nl_symbol_ptr->reserved1]`.

The **symbol table** itself is an array of `struct nlist`s (32-bit) or `struct nlist_64`s (64-bit) (see `<mach-o/nlist.h>`), and each `nlist` / `nlist_64` contains an index into the **string table** in `__LINKEDIT` which where the **actual symbol names** are stored.

So, for each pointer in `__nl_symbol_ptr` and `__la_symbol_ptr`, we are able to find the **corresponding symbol** and then the **corresponding string** to **compare** against the requested symbol names, and if there is a match, we replace the pointer in the section with the replacement.

## Diagram

The process of looking up the name of a given entry in the lazy or non-lazy pointer tables looks like this:

![Visual explanation](fishhook_diagram.png)
