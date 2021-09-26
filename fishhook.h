#ifndef fishhook_h
#define fishhook_h

#include <stddef.h>
#include <stdint.h>

// 问题: 这里的 FISHHOOK_EXPORT 需要在别处定义一下吗?
#if !defined(FISHHOOK_EXPORT)
#define FISHHOOK_VISIBILITY __attribute__((visibility("hidden")))
#else
#define FISHHOOK_VISIBILITY __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/*
 * A structure representing a particular intended rebinding from a symbol
 * name to its replacement
 */
struct rebinding { // 这个结构体存储着重绑定一个符号需要的所有信息
  const char *name; // 需要被 hook 的函数名
  void *replacement; // 自定义的函数, 用于替换原函数
  void **replaced; // 用于存储`原始的`函数指针, 因此需使用二级指针
};

/// For each rebinding in `rebindings`, rebinds references to external, indirect
/// symbols with the specified name to instead point at replacement for each
/// image in the calling process as well as for all future images that are loaded
/// by the process. If rebind_functions is called more than once, the symbols to
/// rebind are added to the existing list of rebindings, and if a given symbol
/// is rebound more than once, the later rebinding will take precedence.
/// ---
/// 说明: 这个方法会对当前进程中所有的 image 执行指定符号重绑定
/// ---
/// @param rebindings 结构体数组, 存储的元素是 `struct rebinding`
/// @param rebindings_nel 结构体数组的元素个数
FISHHOOK_VISIBILITY
int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel)  ;

/// Rebinds as above, but only in the specified image. The header should point
/// to the mach-o header, the slide should be the slide offset. Others as above.
/// ---
/// 说明: 与上述方法不同的是, 此方法只对指定的 image 执行指定符号重绑定
/// ---
/// @param header 需要执行重绑定的 image 的 mach-o header
/// @param slide 指定 image 的偏移量
/// @param rebindings 结构体数组, 存储的元素是 `struct rebinding`
/// @param rebindings_nel 结构体数组的元素个数
FISHHOOK_VISIBILITY
int rebind_symbols_image(void *header,
                         intptr_t slide,
                         struct rebinding rebindings[],
                         size_t rebindings_nel) ;

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //fishhook_h

