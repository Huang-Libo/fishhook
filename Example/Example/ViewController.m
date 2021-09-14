//
//  ViewController.m
//  Example
//
//  Created by HuangLibo on 2021/9/12.
//

#import "ViewController.h"
#import <fishhook/fishhook.h>

// 用于记录原 NSLog 的函数指针
static void (*orig_NSLog)(NSString *format, ...);

@interface ViewController ()
@end

@implementation ViewController

// 自定义的 NSLog
void my_NSLog(NSString *format, ...) {
    if(!format) {
        return;
    }
    // 在原始输出中添加额外的信息
    NSString *extra = @"🤯";
    format = [extra stringByAppendingString:format];
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    // 调用原 NSLog
    orig_NSLog(@"%@", message);
    va_end(args);
}

- (void)viewDidLoad {
    [super viewDidLoad];
    
    NSLog(@"Before hook NSLog\n");
    // 调用 fishhook 来重新绑定 NSLog 对应的符号
    struct rebinding rebindings[1] = {
        {"NSLog", my_NSLog, (void *)&orig_NSLog}
    };
    rebind_symbols(rebindings, 1);
    NSLog(@"After hook NSLog\n");
}

@end
