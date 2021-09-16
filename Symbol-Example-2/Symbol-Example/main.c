#include <stdio.h>
#include <stdarg.h>
#include "fishhook.h"

static int (*orig_printf)(const char * __restrict, ...);

int my_printf(const char *format, ...)
{
    // 打印额外的前缀
    orig_printf("🤯 ");
    int retVal = 0;
    // 取出变长参数
    va_list args;
    va_start(args, format);
    retVal = vprintf(format, args);
    va_end(args);

    return retVal;
}

int main(int argc, const char * argv[]) {
    printf("Before hook printf\n");
    // Use fishhook to rebind symbols
    struct rebinding rebindings[1] = {
        {"printf", my_printf, (void *)&orig_printf}
    };
    rebind_symbols(rebindings, 1);
    int num = 666;
    char * cStr = "c string!";
    printf("After hook printf, %d, %s\n", num, cStr);
    
    return 0;
}
