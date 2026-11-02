// NoAlarmIsland.xm
// 禁止系统闹钟（及可选计时器）上灵动岛（Dynamic Island）。
//
// ── 当前版本定位：自动取证版（1.0.2），零 hook、零注入、绝不进安全模式 ──────
//  上一版（1.0.0）用「动态广撒网 hook」导致真机 SpringBoard 崩溃 → 安全模式。根因是
//  猜符号 + 对管理器类内部/Swift-bridged 方法做 return 早退，破坏事务。本着“不猜、
//  不假阳性”的原则，本版不在没有证据的情况下注入任何 hook。
//
//  本版只做一件事：在 SpringBoard 内枚举真实存在的「灵动岛派发类 / 闹钟内容类」，
//  把候选的 present/add/insert 方法与 MobileTimer 的 Alarm/Timer 内容类名，
//  写入文件 + syslog。整个过程【没有任何 MSHookMessageEx】，因此不可能崩溃。
//
//  用户只需：装好本 deb（不会崩）→ 用 Filza 打开
//    /var/mobile/Documents/NoAlarmIsland_diag.txt
//  把内容发给我 → 我用其中的真实符号填 kTargets，出 1.0.3 精确阻断版。
//
// ── 后续精确阻断（1.0.3+）──────────────────────────────────────────────
//  kTargets 非空时，只 hook 这些【已用证据确认】的方法，命中闹钟/计时器内容才 return，
//  其余原样放行。Discovery 开关（默认关）可开启窄范围日志观察，仍保持零崩溃。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <substrate.h>
#include <os/log.h>
#include <dispatch/dispatch.h>

#pragma mark - Log
static os_log_t NASLog(void) {
    static os_log_t l = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ l = os_log_create("com.jumping.noalarmisland", "diag"); });
    return l;
}

#pragma mark - Preferences（实时读取，无需 respring）
static BOOL gEnabled    = YES;
static BOOL gBlockAlarm = YES;
static BOOL gBlockTimer = NO;
static BOOL gDiscovery  = NO;

static void NASReloadPrefs(void) {
    CFStringRef dom = CFSTR("com.jumping.noalarmisland");
    CFPreferencesAppSynchronize(dom);
    Boolean valid; Boolean b;
    b = CFPreferencesGetAppBooleanValue(CFSTR("Enabled"),    dom, &valid); if (valid) gEnabled    = b;
    b = CFPreferencesGetAppBooleanValue(CFSTR("BlockAlarm"), dom, &valid); if (valid) gBlockAlarm = b;
    b = CFPreferencesGetAppBooleanValue(CFSTR("BlockTimer"), dom, &valid); if (valid) gBlockTimer = b;
    b = CFPreferencesGetAppBooleanValue(CFSTR("Discovery"),  dom, &valid); if (valid) gDiscovery  = b;
}

// ── 精确 hook 点：留空 = 不做任何阻断（由取证版收集证据）──────────────────
// 取证完成后，把真实 {类, selector} 填进来即可启用阻断，例如：
//   @[@{@"class": @"PillManager", @"sel": @"presentPill:"}]
static NSArray<NSDictionary *> *kTargets(void) {
    return @[];
}

// 取证模式扫描的候选类（仅在 Discovery 开启、且 kTargets 为空时使用）。
static NSArray<NSString *> *kDiscoveryClasses(void) {
    return @[@"PillManager", @"IslandManager", @"SBDynamicIslandManager",
             @"SBIslandManager", @"DynamicIslandManager"];
}
static NSArray<NSString *> *kDiscoveryKeywords(void) {
    return @[@"island", @"pill", @"liveactivity"];
}

#pragma mark - 自动取证（纯枚举，零 hook，绝不崩）
static void NASWriteDiag(NSString *content) {
    NSArray *paths = @[
        @"/var/mobile/Documents/NoAlarmIsland_diag.txt",
        @"/var/mobile/Library/NoAlarmIsland_diag.txt",
        @"/tmp/NoAlarmIsland_diag.txt"
    ];
    for (NSString *p in paths) {
        NSError *e = nil;
        [content writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:&e];
        if (!e) { os_log(NASLog(), "diag -> %{public}s", p.UTF8String); return; }
    }
    os_log(NASLog(), "diag write FAILED (all paths)");
}

static void NASDiagnose(void) {
    @try {
        NSMutableString *s = [NSMutableString string];
        [s appendFormat:@"=== NoAlarmIsland 取证 @ %@ ===\n", [NSDate date]];

        // 尝试强制加载灵动岛 / 闹钟相关私有框架，使其类注册进 runtime
        const char *fwk[] = {
            "/System/Library/PrivateFrameworks/Pill.framework/Pill",
            "/System/Library/PrivateFrameworks/Island.framework/Island",
            "/System/Library/PrivateFrameworks/DynamicIsland.framework/DynamicIsland",
            "/System/Library/PrivateFrameworks/MobileTimer.framework/MobileTimer",
            NULL
        };
        for (int i = 0; fwk[i]; i++) {
            void *h = dlopen(fwk[i], RTLD_LAZY | RTLD_LOCAL);
            [s appendFormat:@"dlopen %s -> %p\n", fwk[i], h];
        }

        unsigned int n = 0; Class *cls = NULL;
        n = objc_getClassList(NULL, 0);
        if (n) { cls = (Class *)malloc(sizeof(Class) * n); n = objc_getClassList(cls, n); }

        NSArray *mgrKw = @[@"Pill", @"Island", @"DynamicIsland"];
        NSArray *diKw  = @[@"pill", @"island", @"liveactivity", @"content"];
        NSArray *verb  = @[@"present", @"add", @"insert", @"show"];

        [s appendString:@"\n--- [1] 候选派发类及其 present/add/insert/show 方法 ---\n"];
        for (unsigned int i = 0; i < n; i++) {
            Class c = cls[i]; if (!c) continue;
            NSString *cn = @(class_getName(c));
            BOOL mgr = NO;
            for (NSString *k in mgrKw)
                if ([cn containsString:k] && ([cn containsString:@"Manager"] || [cn containsString:@"Controller"])) { mgr = YES; break; }
            if (!mgr) continue;
            unsigned int mc = 0; Method *ms = class_copyMethodList(c, &mc);
            for (unsigned int j = 0; j < mc; j++) {
                NSString *sel = @(sel_getName(method_getName(ms[j])));
                NSString *ls = sel.lowercaseString;
                if ([ls hasPrefix:@"set"] || [ls hasPrefix:@"nas_"]) continue;
                BOOL look = NO;
                for (NSString *k in diKw) if ([ls containsString:k]) { look = YES; break; }
                if (!look) continue;
                BOOL v = NO;
                for (NSString *x in verb) if ([ls containsString:x]) { v = YES; break; }
                if (!v) continue;
                [s appendFormat:@"  %@ %@\n", cn, sel];
            }
            if (ms) free(ms);
        }

        [s appendString:@"\n--- [2] MobileTimer 中与 Alarm/Timer/Island/LiveActivity/Pill 相关的类 ---\n"];
        for (unsigned int i = 0; i < n; i++) {
            Class c = cls[i]; if (!c) continue;
            NSString *cn = @(class_getName(c));
            if (![cn containsString:@"MobileTimer"] && ![cn containsString:@"MT"]) continue;
            if ([cn containsString:@"Alarm"] || [cn containsString:@"Timer"] ||
                [cn containsString:@"Island"] || [cn containsString:@"LiveActivity"] ||
                [cn containsString:@"Pill"])
                [s appendFormat:@"  %@\n", cn];
        }

        if (cls) free(cls);
        [s appendString:@"\n=== END（把以上内容发给我即可）===\n"];
        NASWriteDiag(s);
        os_log(NASLog(), "diagnosis complete, %lu bytes", (unsigned long)s.length);
    } @catch (id e) {
        os_log(NASLog(), "diagnosis ERROR: %{public}@", [e description]);
    }
}

#pragma mark - 预留：精确阻断 / 取证日志（1.0.3+ 启用，本版不调用）
static NSMutableDictionary<NSString *, NSValue *> *gOrigByKey = nil;
static NSMutableSet<NSString *> *gHookedKeys = nil;

static NSString *NASKey(Class cls, SEL sel) {
    return [NSString stringWithFormat:@"%s/%@", class_getName(cls), NSStringFromSelector(sel)];
}
static BOOL NASIsVoidObjectMethod(Method m) {
    if (!m) return NO;
    unsigned int nargs = method_getNumberOfArguments(m);
    if (nargs != 3) return NO;
    const char *ret = method_copyReturnType(m);
    char *arg2 = method_copyArgumentType(m, 2);
    BOOL ok = (ret && strcmp(ret, "v") == 0 && arg2 && arg2[0] == '@');
    free((void *)ret); free(arg2);
    return ok;
}
static IMP NASOriginal(Class cls, SEL sel) {
    NSString *key = NASKey(cls, sel);
    NSValue *v = gOrigByKey[key];
    return v ? (IMP)[v pointerValue] : NULL;
}
static BOOL NASHookMethod(Class cls, SEL sel, int mode) {
    if (!cls || !sel) return NO;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m || ![cls instancesRespondToSelector:sel]) return NO;
    if (!NASIsVoidObjectMethod(m)) return NO;
    NSString *key = NASKey(cls, sel);
    if ([gHookedKeys containsObject:key]) return NO;
    IMP orig = NULL;
    MSHookMessageEx(cls, sel, (IMP)(mode == 0 ? NULL : NULL), &orig); // 占位，1.0.3 接入真实 replacement
    if (!orig) return NO;
    gOrigByKey[key] = [NSValue valueWithPointer:(void *)orig];
    [gHookedKeys addObject:key];
    return YES;
}

static void NASPrefsChanged(CFNotificationCenterRef center, void *observer, CFNotificationName name, const void *object, CFDictionaryRef userInfo) {
    NASReloadPrefs();
}

%ctor {
    @try {
        NASReloadPrefs();
        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(), NULL, NASPrefsChanged,
            CFSTR("com.jumping.noalarmisland/preferencesChanged"), NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately);

        NSArray *targets = kTargets();
        if (targets.count > 0) {
            // 精确阻断模式（1.0.3+）：此处将接入真实 replacement，本版 targets 为空不触发。
            os_log(NASLog(), "init(precise): %lu targets (未实现，等待 1.0.3)", (unsigned long)targets.count);
        } else {
            // 自动取证：延迟 3s 执行，避免拖慢 SpringBoard 启动；纯枚举，零 hook，绝不崩。
            os_log(NASLog(), "init(diagnosis): 3s 后枚举真实符号并写文件，本版零注入");
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC),
                           dispatch_get_main_queue(), ^{
                NASDiagnose();
            });
        }
    } @catch (id e) {
        os_log(NASLog(), "init ERROR: %{public}@", [e description]);
    }
}
