// frida -n SpringBoard -l tools/trace_alarm.js
// 在真机上运行：先启动本脚本，然后去「时钟」App 设一个闹钟/计时器，
// 观察控制台输出的 [NAS] 行，即可定位真实 hook 点：
//   - 哪一类（PillManager / IslandManager / ...）负责派发
//   - 哪个 selector 传入了闹钟/计时器内容（arg1 的类名含 Alarm/Timer/MobileTimer）
//
// 把确认到的 类名 补进 Tweak.xm 的 mgrClasses，把 selector 特征补进 sig 数组即可。

const TARGET = /Pill|Island|LiveActivity|Assertion|Alarm|MobileTimer|Timer/i;
const seen = {};

function trace(cls) {
  const k = cls.name;
  if (seen[k]) return;
  seen[k] = 1;
  cls.methods.forEach(method => {
    const sel = method.selector;
    const ln = sel.toLowerCase();
    if (!/pill|island|content|liveactivity|assertion|present|add|insert|show|alarm|timer/.test(ln)) return;
    if (ln.startsWith('set')) return;
    try {
      Interceptor.attach(method.implementation, {
        onEnter(args) {
          const self = new ObjC.Object(args[0]);
          let arg1cls = '?';
          try { if (!args[2].isNull()) arg1cls = new ObjC.Object(args[2]).$className; } catch (e) {}
          console.log(`[NAS] ${k} ${sel}  arg1=${arg1cls}`);
        }
      });
    } catch (e) { /* ignore */ }
  });
}

function scan() {
  for (const cls of ObjC.classes) {
    if (TARGET.test(cls.name)) trace(cls);
  }
}

scan();
console.log('[NAS] tracing started; 现在去时钟 App 设一个闹钟/计时器并观察上方输出。');
