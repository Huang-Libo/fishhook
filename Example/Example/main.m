//
//  main.m
//  Example
//
//  Created by HuangLibo on 2021/9/12.
//

#import <dlfcn.h>
#import <UIKit/UIKit.h>
#import "AppDelegate.h"
#import <fishhook/fishhook.h>
 
static int (*orig_close)(int);
static int (*orig_open)(const char *, int, ...);
static int (*orig_printf)(const char * __restrict, ...);
 
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

int my_printf(const char * __restrict fmt, ...) {
    char *extra = "[hook printf]";
    char *result = malloc(strlen(fmt) + strlen(extra));
    strcpy(result, extra);
    strcat(result, fmt);
    return orig_printf(result);
}

void rebindDemo1(int argc, char * argv[]) {
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
}

void rebindDemo2(void) {
    printf("Before hook printf\n");    
    // Use fishhook to rebind symbols
    struct rebinding rebindings[1] = {
        {"printf", my_printf, (void *)&orig_printf}
    };
    rebind_symbols(rebindings, 1);
    int a = 24;
    printf("rebindDemo2, %d", a);
}

int main(int argc, char * argv[]) {
    NSString * appDelegateClassName;
    @autoreleasepool {
//        rebindDemo1(argc, argv);
        rebindDemo2();
        
        // Setup code that might create autoreleased objects goes here.
        appDelegateClassName = NSStringFromClass([AppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
