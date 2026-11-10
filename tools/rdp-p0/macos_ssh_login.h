#pragma once
#include <CoreGraphics/CoreGraphics.h>
#include <dispatch/dispatch.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void report_login_display(NSScreen *screen) {
    NSNumber *display = screen.deviceDescription[@"NSScreenNumber"];
    CGRect bounds = display ? CGDisplayBounds(display.unsignedIntValue) : CGRectZero;
    if (!CGRectIsEmpty(bounds)) {
        fprintf(stdout, "remote-display %d %d\n", (int)CGRectGetMidX(bounds), (int)CGRectGetMidY(bounds));
    } else {
        puts("remote-display none");
    }
    fflush(stdout);
}

static NSString *ssh_environment(const char *key) {
    const char *value = getenv(key);
    return value ? ([NSString stringWithUTF8String:value] ?: @"") : @"";
}

static void ssh_hex(const char *input, size_t length, char *output) {
    const char *digits = "0123456789abcdef";
    if (length == 0) { strcpy(output, "-"); return; }
    for (size_t i = 0; i < length; i++) {
        unsigned char byte = (unsigned char)input[i];
        output[2*i] = digits[byte >> 4];
        output[2*i+1] = digits[byte & 15];
    }
    output[2*length] = 0;
}

static BOOL ssh_write_request(LoginForm *form, unsigned port, BOOL clear) {
    NSString *account = form.account.stringValue;
    size_t accountLength = [account lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    const char *user = account.UTF8String;
    if (!user || !accountLength || accountLength > 128 || strlen(user) != accountLength) {
        [form failed:RDP_NS(SshInvalidLogin)];
        return NO;
    }
    char encodedUser[257];
    ssh_hex(user, accountLength, encodedUser);
    if (clear) {
        return fprintf(stdout, "ssh-clear %s %u\n", encodedUser, port) >= 0 && fflush(stdout) == 0;
    }
    NSString *password = form.password.stringValue;
    size_t length = [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    const char *secret = password.UTF8String;
    if (!secret || length > 1000 || strlen(secret) != length || strpbrk(secret, "\r\n")) {
        [form failed:RDP_NS(TooLong)];
        return NO;
    }
    char encoded[2001];
    ssh_hex(secret, length, encoded);
    report_login_display(form.panel.screen);
    BOOL sent = fprintf(stdout, "ssh-connect %s %u %d %d %s\n", encodedUser, port,
        form.remember.state == NSControlStateValueOn, length == 0, encoded) >= 0 && fflush(stdout) == 0;
    for (volatile char *p = encoded; p < encoded + sizeof(encoded); p++) *p = 0;
    return sent;
}

static void ssh_read_reply(LoginForm *form) {
    __weak LoginForm *weakForm = form;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        char line[64];
        NSString *reply = fgets(line, sizeof(line), stdin) ? [NSString stringWithUTF8String:line] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            LoginForm *active = weakForm;
            if (!reply || [reply isEqualToString:@"ok\n"]) {
                [active close];
                [NSApp terminate:nil];
                return;
            }
            NSString *hint = RDP_NS(SshConnectFailed);
            if ([reply isEqualToString:@"auth\n"]) hint = RDP_NS(SshAuthFailed);
            else if ([reply isEqualToString:@"key-changed\n"]) hint = RDP_NS(SshHostKeyChanged);
            else if ([reply isEqualToString:@"key-rejected\n"]) hint = RDP_NS(SshHostKeyRejected);
            else if ([reply isEqualToString:@"read-failed\n"]) hint = RDP_NS(ReadFailed);
            else if ([reply isEqualToString:@"clear-failed\n"]) hint = RDP_NS(ClearFailed);
            else if ([reply isEqualToString:@"cleared\n"]) hint = RDP_NS(Cleared);
            else if ([reply isEqualToString:@"invalid\n"]) hint = RDP_NS(SshInvalidLogin);
            else if ([reply isEqualToString:@"timeout\n"]) hint = RDP_NS(SshLoginTimeout);
            [active failed:hint];
        });
    });
}

int calabi_ssh_login(void) {
    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyAccessory];
        __attribute__((objc_precise_lifetime)) LoginForm *form = [[LoginForm alloc] initWithName:ssh_environment("CALABI_RDP_NAME")
            host:ssh_environment("CALABI_P0_PEER") ssh:YES];
        form.account.stringValue = ssh_environment("CALABI_RDP_ACCOUNT_HINT");
        [form applyPortHint:ssh_environment("CALABI_SSH_PORT")];
        __weak LoginForm *weakForm = form;
        form.submit = ^(unsigned port) {
            LoginForm *active = weakForm;
            if (ssh_write_request(active, port, NO)) ssh_read_reply(active);
            else if (active.connecting) [active failed:RDP_NS(SshConnectFailed)];
        };
        form.forget = ^(unsigned port) {
            LoginForm *active = weakForm;
            if (!ssh_write_request(active, port, YES)) return;
            active.connecting = YES;
            active.account.enabled = active.password.enabled = active.port.enabled = NO;
            active.remember.enabled = active.forgetButton.enabled = active.connectButton.enabled = NO;
            ssh_read_reply(active);
        };
        form.dismiss = ^{
            [weakForm close];
            [NSApp terminate:nil];
        };
        signal(SIGUSR1, SIG_IGN);
        dispatch_source_t focus = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dispatch_get_main_queue());
        if (!focus) return 1;
        dispatch_source_set_event_handler(focus, ^{
            LoginForm *active = weakForm;
            if (active.panel.visible) {
                [active.panel makeKeyAndOrderFront:nil];
                [NSApp activateIgnoringOtherApps:YES];
            }
        });
        dispatch_resume(focus);
        char reply[32];
        if (fputs("ssh-ready 0\n", stdout) == EOF || fflush(stdout) != 0 ||
            !fgets(reply, sizeof(reply), stdin) || strcmp(reply, "ssh-show\n") != 0) {
            dispatch_source_cancel(focus);
            return 1;
        }
        [form show];
        [app run];
        dispatch_source_cancel(focus);
        return 0;
    }
}

int calabi_ssh_confirm(const char *prompt, const char *directory) {
    @autoreleasepool {
        if (access(directory, F_OK) != 0) return 1;
        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyAccessory];
        NSAlert *alert = [NSAlert new];
        alert.alertStyle = NSAlertStyleWarning;
        alert.messageText = RDP_NS(SshConfirmHost);
        alert.informativeText = [NSString stringWithUTF8String:prompt] ?: @"";
        NSButton *cancel = [alert addButtonWithTitle:RDP_NS(Cancel)];
        cancel.keyEquivalent = @"\r";
        NSButton *trust = [alert addButtonWithTitle:RDP_NS(SshTrustHost)];
        trust.keyEquivalent = @"";
        NSTimer *timer = [NSTimer timerWithTimeInterval:0.25 repeats:YES block:^(NSTimer *timer) {
            if (access(directory, F_OK) != 0) [app abortModal];
        }];
        [NSRunLoop.currentRunLoop addTimer:timer forMode:NSModalPanelRunLoopMode];
        [alert.window orderFrontRegardless];
        [app activateIgnoringOtherApps:YES];
        NSModalResponse response = [alert runModal];
        [timer invalidate];
        return response == NSAlertSecondButtonReturn && access(directory, F_OK) == 0 ? 0 : 1;
    }
}
