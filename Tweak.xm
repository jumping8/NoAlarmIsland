// NoAlarmIsland.xm
// 禁止系统闹钟（及可选计时器）上灵动岛（Dynamic Island），不影响其它灵动岛内容。
//
// ── 设计要点（证据优先，不猜测符号，绝不把 SpringBoard 带崩）──────────────
//  · 灵动岛内容由 SpringBoard 内的 “Pill/Island” 管理器派发，闹钟内容也走这一层。
//  · 早期版本用「动态广撒网」扫描管理器类的所有 v@:@ 方法并 hook，结果在真机触发
//    SpringBoard 崩溃 → 安全模式。根因：hook 了不该 hook 的内部/Swift-bridged 方法，
//    且对命中内容直接 return 吞掉了必要事务。这是典型的“猜符号→假阳性”失效。
//  · 现改为：默认「精确 + 安全无操作」。
//      - kTargets：精确 {类, selector} 列表。非空时只 hook 这些已验证的方法（阻断闹钟上岛）。
//      - 默认 kTargets 留空 → 加载即退出，零注入，100% 不会崩溃。
//      - Discovery 模式（默认关）：开启后仅做窄范围“日志 + 始终调用原方法”观察，
//        绝不在观察时 return，因此不会破坏事务、不会崩，用来在真机采集真实 hook 点。
//  · 所有 hook 前做 class/selector/签名（v@:@）存在性校验，缺失即跳过。
//  · %ctor 整体 @try/@catch：即使初始化异常也只是不 hook，绝不影响 SpringBoard 启动。
//  · hook 证据写入 syslog（subsystem=com.jumping.noalarmisland），`log stream` 可取证。
//
// ── 取证流程（不崩溃、不猜）──────────────────────────────────────────────
//  方式 A（推荐，零注入风险）：在 Mac 上 `frida -n SpringBoard -l tools/trace_alarm.js`，
//    去时钟 App 设闹钟，控制台会打印真实的方法（类名 + selector + 首参类名）。
//  方式 B：设备上跑 `sh tools/dump_island.sh` 导头文件 grep 出 present 方法。
//  把确认到的 {类, selector} 回填到下方 kTargets，重新出包即具备“禁止上岛”功能。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <substrate.h>
#include <os/log.h>

#pragma mark - Log
static os_log_t NASLog(void) {
    static os_log_t l = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ l = os_log_create("com.jumping.noalarmisland", "hook"); });
    return l;
}

#pragma mark - Preferences（实时读取，无需 respring）
static BOOL gEnabled    = YES;
static BOOL gBlockAlarm = YES;
static BOOL gBlockTimer = NO;
static BOOL gDiscovery  = NO;   // 取证模式：默认关，开启后仅日志观察、不阻断

static void NASReloadPrefs(void) {
    CFStringRef dom = CFSTR("com.jumping.noalarmisland");
    CFPreferencesAppSynchronize(dom);
    Boolean valid; Boolean b;
    b = CFPreferencesGetAppBooleanValue(CFSTR("Enabled"),    dom, &valid); if (valid) gEnabled    = b;
    b = CFPreferencesGetAppBooleanValue(CFSTR("BlockAlarm"), dom, &valid); if (valid) gBlockAlarm = b;
    b = CFPreferencesGetAppBooleanValue(CFSTR("BlockTimer"), dom, &valid); if (valid) gBlockTimer = b;
    b = CFPreferencesGetAppBooleanValue(CFSTR("Discovery"),  dom, &valid); if (valid) gDiscovery  = b;
    os_log(NASLog(), "prefs enabled=%d alarm=%d timer=%d discovery=%d", gEnabled, gBlockAlarm, gBlockTimer, gDiscovery);
}

#pragma mark - 内容识别
static NSArray<NSString *> *NASAlarmKeywords(void) { return @[@"alarm", @"mobiletimer", @"mtalarm"]; }
static NSArray<NSString *> *NASTimerKeywords(void) { return @[@"timer", @"mttimer"]; }

static NSString *NASStringProp(id obj, NSString *key) {
    if (!obj || !key) return nil;
    SEL sel = NSSelectorFromString(key);
    if ([obj respondsToSelector:sel]) {
        @try { id v = [obj performSelector:sel]; if ([v isKindOfClass:[NSString class]]) return v; } @catch (id e) {}
    }
    @try { id v = [obj valueForKey:key]; if ([v isKindOfClass:[NSString class]]) return v; } @catch (id e) {}
    return nil;
}

static BOOL NASMatches(id obj, NSArray<NSString *> *keywords) {
    if (!obj) return NO;
    NSString *cls = NSStringFromClass([obj class]).lowercaseString;
    for (NSString *kw in keywords) if ([cls containsString:kw]) return YES;
    NSArray *keys = @[@"identifier", @"contentIdentifier", @"activityType", @"kind",
                      @"type", @"_identifier", @"representedIdentifier", @"contentType", @"category"];
    for (NSString *k in keys) {
        NSString *v = NASStringProp(obj, k);
        if (v) { NSString *lv = v.lowercaseString; for (NSString *kw in keywords) if ([lv containsString:kw]) return YES; }
    }
    return NO;
}

static BOOL NASShouldBlock(id content) {
    if (!gEnabled) return NO;
    NSMutableArray *kws = [NSMutableArray array];
    if (gBlockAlarm) [kws addObjectsFromArray:NASAlarmKeywords()];
    if (gBlockTimer) [kws addObjectsFromArray:NASTimerKeywords()];
    if (kws.count == 0) return NO;
    return NASMatches(content, kws);
}

#pragma mark - hook 基础设施
static NSMutableDictionary<NSString *, NSValue *> *gOrigByKey = nil; // key="ClassName/sel" -> IMP
static NSMutableSet<NSString *> *gHookedKeys = nil;

static NSString *NASKey(Class cls, SEL sel) {
    return [NSString stringWithFormat:@"%s/%@", class_getName(cls), NSStringFromSelector(sel)];
}

// 严格校验方法签名是否为 v@:@（返回 void，单对象参数）。是才允许 hook。
static BOOL NASIsVoidObjectMethod(Method m) {
    if (!m) return NO;
    unsigned int nargs = method_getNumberOfArguments(m);
    if (nargs != 3) return NO;                       // self + _cmd + 1 个参数
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

// 精确 replacement：命中闹钟/计时器内容 → 直接 return（不上岛）；
// 其余内容原样调用原始实现。仅在 kTargets 命中、且已用证据确认为真实派发方法时使用。
static void NASPreciseReplacement(id self, SEL _cmd, id content) {
    IMP orig = NASOriginal([self class], _cmd);
    if (NASShouldBlock(content)) {
        os_log(NASLog(), "BLOCK %{public}s %{public}s content=%{public}s",
               class_getName([self class]), sel_getName(_cmd),
               content ? class_getName([content class]) : "nil");
        return; // 不上岛
    }
    if (orig) { @try { ((void (*)(id, SEL, id))orig)(self, _cmd, content); } @catch (id e) {} }
}

// 取证 replacement：只日志、永远调用原始实现，绝不 return。用于 Discovery 模式采集真实 hook 点。
static void NASDiscoveryReplacement(id self, SEL _cmd, id content) {
    IMP orig = NASOriginal([self class], _cmd);
    os_log(NASLog(), "DISCO %{public}s %{public}s content=%{public}s",
           class_getName([self class]), sel_getName(_cmd),
           content ? class_getName([content class]) : "nil");
    if (orig) { @try { ((void (*)(id, SEL, id))orig)(self, _cmd, content); } @catch (id e) {} }
}

// 校验并 hook 单个方法；mode=0 精确阻断，mode=1 取证日志。
static BOOL NASHookMethod(Class cls, SEL sel, int mode) {
    if (!cls || !sel) return NO;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m || ![cls instancesRespondToSelector:sel]) return NO;
    if (!NASIsVoidObjectMethod(m)) return NO;
    NSString *key = NASKey(cls, sel);
    if ([gHookedKeys containsObject:key]) return NO;
    IMP orig = NULL;
    MSHookMessageEx(cls, sel, (IMP)(mode == 0 ? NASPreciseReplacement : NASDiscoveryReplacement), &orig);
    if (!orig) return NO;
    gOrigByKey[key] = [NSValue valueWithPointer:(void *)orig];
    [gHookedKeys addObject:key];
    os_log(NASLog(), "%{public}s %{public}s %{public}s",
           mode == 0 ? "HOOK" : "DISCOHOOK", class_getName(cls), sel_getName(sel));
    return YES;
}

// ── 精确 hook 点：留空 = 安全加载、零注入（绝不崩溃）─────────────────────
// 待真机证据回填，例如：
//   @[@{@"class": @"SBIslandManager", @"sel": @"presentPill:"},
//     @{@"class": @"PillManager",     @"sel": @"_presentContent:"}]
static NSArray<NSDictionary *> *kTargets(void) {
    return @[];
}

// 取证模式扫描的候选类（仅在 Discovery 开启、且 kTargets 为空时使用）。
static NSArray<NSString *> *kDiscoveryClasses(void) {
    return @[@"PillManager", @"IslandManager", @"SBDynamicIslandManager",
             @"SBIslandManager", @"DynamicIslandManager"];
}
// 取证模式只匹配真正的灵动岛术语，避免误 hook 通用方法（add/show/present/insert/content）。
static NSArray<NSString *> *kDiscoveryKeywords(void) {
    return @[@"island", @"pill", @"liveactivity"];
}

static BOOL NASDiscoveryHookClass(Class cls) {
    if (!cls) return NO;
    unsigned int count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    if (!methods) return NO;
    BOOL hookedAny = NO;
    for (unsigned int i = 0; i < count; i++) {
        SEL sel = method_getName(methods[i]);
        NSString *ln = NSStringFromSelector(sel).lowercaseString;
        if ([ln hasPrefix:@"set"] || [ln hasPrefix:@"nas_"]) continue;
        BOOL looksDI = NO;
        for (NSString *s in kDiscoveryKeywords()) if ([ln containsString:s]) { looksDI = YES; break; }
        if (!looksDI) continue;
        hookedAny |= NASHookMethod(cls, sel, 1);
    }
    free(methods);
    return hookedAny;
}

static void NASPrefsChanged(CFNotificationCenterRef center, void *observer, CFNotificationName name, const void *object, CFDictionaryRef userInfo) {
    NASReloadPrefs();
}

%ctor {
    @try {
        gOrigByKey  = [NSMutableDictionary dictionary];
        gHookedKeys = [NSMutableSet set];

        NASReloadPrefs();
        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(), NULL, NASPrefsChanged,
            CFSTR("com.jumping.noalarmisland/preferencesChanged"), NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately);

        NSArray *targets = kTargets();
        if (targets.count > 0) {
            // 精确模式：只 hook 已验证的方法
            int n = 0;
            for (NSDictionary *t in targets) {
                NSString *cn = t[@"class"]; NSString *sn = t[@"sel"];
                if (!cn || !sn) continue;
                Class c = NSClassFromString(cn);
                SEL s = NSSelectorFromString(sn);
                if (c && s && NASHookMethod(c, s, 0)) n++;
            }
            os_log(NASLog(), "init(precise) hooked=%d", n);
        } else if (gDiscovery) {
            // 取证模式：窄范围日志观察，绝不阻断，绝不崩溃
            BOOL any = NO;
            for (NSString *cn in kDiscoveryClasses()) {
                Class c = NSClassFromString(cn);
                if (c) any |= NASDiscoveryHookClass(c);
            }
            if (!any) {
                // 框架可能尚未加载，尝试激活后重试一次（RTLD_NOLOAD 不实际加载）
                dlopen("/System/Library/PrivateFrameworks/Island.framework/Island", RTLD_LAZY | RTLD_NOLOAD);
                dlopen("/System/Library/PrivateFrameworks/Pill.framework/Pill",     RTLD_LAZY | RTLD_NOLOAD);
                for (NSString *cn in kDiscoveryClasses()) {
                    Class c = NSClassFromString(cn);
                    if (c) any |= NASDiscoveryHookClass(c);
                }
            }
            os_log(NASLog(), "init(discovery) hooked=%d", any);
        } else {
            // 安全无操作：零注入，100% 不会进安全模式
            os_log(NASLog(), "init(safe no-op): kTargets 为空且 Discovery 关闭，未注入任何 hook");
        }
    } @catch (id e) {
        os_log(NASLog(), "init ERROR: %{public}@", [e description]);
    }
}
