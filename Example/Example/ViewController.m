//
//  ViewController.m
//  Example
//
//  Created by HuangLibo on 2021/9/12.
//

#import "ViewController.h"
#import <fishhook/fishhook.h>

static void (*orig_NSLog)(NSString *format, ...);

@interface ViewController ()

@end

@implementation ViewController

void my_NSLog(NSString *format, ...) {
    if(!format) {
        return;
    }
    NSString *extra = @"[hook NSLog] ";
    format = [extra stringByAppendingString:format];
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    orig_NSLog(@"%@", message);
    va_end(args);
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    NSLog(@"Before hook NSLog\n");
    struct rebinding rebindings[1] = {
        {"NSLog", my_NSLog, (void *)&orig_NSLog}
    };
    rebind_symbols(rebindings, 1);
    NSLog(@"After hook NSLog\n");
}


@end
