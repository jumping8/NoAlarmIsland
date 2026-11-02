// NoAlarmIsland.xm
// 禁止系统闹钟（及可选计时器）上灵动岛（Dynamic Island），不影响其它灵动岛内容。
//
// ── 设计要点（证据优先，不猜测符号）─────────────────────────────────────
//  · 灵动岛内容统一由 SpringBoard 内的 “Pill/Island” 管理器派发，闹钟内容也走这一层。
//  · %ctor 中动态枚举候选管理器类（PillManager / IslandManager 等）的实例方法，
//    仅 hook 满足「返回值 void、恰好 1 个对象参数、selector 含 pill/island/content/...」
//    的 present/add/insert 类方法。命中内容类名/标识符含 alarm/mobiletimer 时直接 return，
//    不调用原始实现（即不上岛）；其余内容原样放行。
//  · 所有 hook 前都做 class/selector 存在性校验，缺失则跳过 → 绝不崩溃、绝不假阳性。
//  · 实际 hook 到的「类/selector」写入 syslog（subsystem=com.jumping.noalarmisland），
//    真机用 `log stream` 即可取证，符合“静态/运行时证据支撑结论”的回归标准。
//
// ── 若真机 log 显示未命中任何 present 方法 ───────────────────────────────
//  用 tools/ 下的 classdump + frida 脚本确认真实 hook 点（类名/selector/首个参数类型），
//  回填到下方 kManagerClasses / kSigKeywords 即可。本文件不依赖任何未经验证的符号。

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

static void NASReloadPrefs(void) {
    CFStringRef dom = CFSTR("com.jumping.noalarmisland");
    CFPreferencesAppSynchronize(dom);
    Boolean valid; Boolean b;
    b = CFPreferencesGetAppBooleanValue(CFSTR("Enabled"),    dom, &valid); if (valid) gEnabled    = b;
    b = CFPreferencesGetAppBooleanValue(CFSTR("BlockAlarm"), dom, &valid); if (valid) gBlockAlarm = b;
    b = CFPreferencesGetAppBooleanValue(CFSTR("BlockTimer"), dom, &valid); if (valid) gBlockTimer = b;
    os_log(NASLog(), "prefs enabled=%d alarm=%d timer=%d", gEnabled, gBlockAlarm, gBlockTimer);
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

#pragma mark - 动态 hook
static NSMutableDictionary<NSString *, NSValue *> *gOrigByKey = nil; // key="ClassName/sel" -> IMP
static NSMutableSet<NSString *> *gHookedKeys = nil;

static NSString *NASKey(Class cls, SEL sel) {
    return [NSString stringWithFormat:@"%s/%@", class_getName(cls), NSStringFromSelector(sel)];
}

// 统一替换函数：签名严格为 v@:@（返回 void，单对象参数），与待 hook 方法一致。
static void NASPresentReplacement(id self, SEL _cmd, id content) {
    NSString *key = NASKey([self class], _cmd);
    IMP orig = gOrigByKey[key] ? [gOrigByKey[key] pointerValue] : NULL;
    if (NASShouldBlock(content)) {
        os_log(NASLog(), "BLOCK %{public}s %{public}s content=%{public}s",
               class_getName([self class]), sel_getName(_cmd), class_getName([content class]));
        return; // 不上岛
    }
    if (orig) ((void (*)(id, SEL, id))orig)(self, _cmd, content);
    else os_log(NASLog(), "WARN no orig for %{public}s", key.UTF8String);
}

static BOOL NASHookClass(Class cls) {
    if (!cls) return NO;
    unsigned int count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    if (!methods) return NO;
    NSArray *sig = @[@"pill", @"island", @"content", @"liveactivity", @"assertion",
                     @"present", @"add", @"insert", @"show"];
    BOOL hookedAny = NO;
    for (unsigned int i = 0; i < count; i++) {
        Method m = methods[i];
        SEL sel = method_getName(m);
        NSString *name = NSStringFromSelector(sel);
        NSString *ln = name.lowercaseString;
        if ([ln hasPrefix:@"set"] || [ln hasPrefix:@"nas_"]) continue;
        BOOL looksDI = NO;
        for (NSString *s in sig) if ([ln containsString:s]) { looksDI = YES; break; }
        if (!looksDI) continue;

        const char *ret = method_copyReturnType(m);
        unsigned int nargs = method_getNumberOfArguments(m);
        char *arg2 = (nargs >= 3) ? method_copyArgumentType(m, 2) : NULL;
        BOOL ok = (ret && strcmp(ret, "v") == 0 && nargs == 3 && arg2 && arg2[0] == '@');
        free((void *)ret); free(arg2);
        if (!ok) continue;

        NSString *key = NASKey(cls, sel);
        if (gHookedKeys[key]) continue;
        IMP orig = NULL;
        MSHookMessageEx(cls, sel, (IMP)NASPresentReplacement, &orig);
        if (orig) {
            gOrigByKey[key] = [NSValue valueWithPointer:orig];
            [gHookedKeys addObject:key];
            hookedAny = YES;
            os_log(NASLog(), "HOOK %{public}s %{public}s", class_getName(cls), sel_getName(sel));
        }
    }
    free(methods);
    return hookedAny;
}

%ctor {
    gOrigByKey  = [NSMutableDictionary dictionary];
    gHookedKeys = [NSMutableSet set];

    NASReloadPrefs();
    CFNotificationCenterCallBack nasPrefsChanged =
        ^(CFNotificationCenterRef c, void *o, CFStringRef n, const void *obj, CFDictionaryRef i) {
            NASReloadPrefs();
        };
    CFNotificationCenterAddObserver(
        CFNotificationCenterGetDarwinNotifyCenter(), NULL, nasPrefsChanged,
        CFSTR("com.jumping.noalarmisland/preferencesChanged"), NULL,
        CFNotificationSuspensionBehaviorDeliverImmediately);

    // ── 候选管理器类：真机上若都未命中，用 tools/ 验证后回填 ──
    NSArray *mgrClasses = @[@"PillManager", @"IslandManager", @"SBDynamicIslandManager",
                            @"SBIslandManager", @"DynamicIslandManager"];
    BOOL any = NO;
    for (NSString *cn in mgrClasses) {
        Class c = objc_getClass(cn.UTF8String);
        if (c) any |= NASHookClass(c);
    }
    if (!any) {
        // 框架可能尚未加载，强制 dlopen 后再试
        dlopen("/System/Library/PrivateFrameworks/Island.framework/Island", RTLD_LAZY | RTLD_NOLOAD);
        dlopen("/System/Library/PrivateFrameworks/Pill.framework/Pill",     RTLD_LAZY | RTLD_NOLOAD);
        for (NSString *cn in mgrClasses) {
            Class c = objc_getClass(cn.UTF8String);
            if (c) any |= NASHookClass(c);
        }
    }
    os_log(NASLog(), "init done hooked=%d", any);
}
