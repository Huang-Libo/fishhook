// Copyright (c) 2013, Facebook, Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//   * Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//   * Neither the name Facebook nor the names of its contributors may be used to
//     endorse or promote products derived from this software without specific
//     prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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

