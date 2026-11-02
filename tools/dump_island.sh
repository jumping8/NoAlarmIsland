#!/bin/sh
# 在越狱设备上运行（建议通过 SSH 从 Mac 执行，或用 NewTerm 等终端）。
# 目的：导出 Island/Pill/SpringBoard/MobileTimer 的头文件，grep 出与灵动岛和闹钟相关的
#       类/方法，作为回填 Tweak.xm 中 kManagerClasses / kSigKeywords 的证据。
#
# 依赖：classdump-dyld（Sileo 源里搜 classdump-dyld 安装）。
set -e
OUT=/tmp/nas_dump
rm -rf "$OUT"; mkdir -p "$OUT"

FRAMEWORKS="/System/Library/PrivateFrameworks/Island.framework \
/System/Library/PrivateFrameworks/Pill.framework \
/System/Library/PrivateFrameworks/MobileTimer.framework \
/System/Library/CoreServices/SpringBoard.app"

for f in $FRAMEWORKS; do
  [ -e "$f" ] || { echo "skip (not found): $f"; continue; }
  name=$(basename "$f" | sed 's/\.framework$//;s/\.app$//')
  echo ">> dumping $f"
  classdump-dyld -H "$f" -o "$OUT/$name" 2>/dev/null || echo "   classdump failed for $f"
done

echo
echo "===== [1] 候选管理器类（Pill/Island Manager）及其 present/add/insert 方法 ====="
grep -rhiE "interface .*(Pill|Island)Manager" "$OUT" --include=*.h | head -n 40
grep -rhiE "\-(void).*(present|add|insert|show|content|pill|island)" "$OUT" --include=*.h \
  | grep -iE "pill|island|content|liveactivity|assertion" | head -n 80

echo
echo "===== [2] MobileTimer 中与 Island / LiveActivity / Alarm 相关的类 ====="
grep -rhiE "interface .*(LiveActivity|Island|Alarm)" "$OUT/MobileTimer" --include=*.h 2>/dev/null | head -n 40

echo
echo "===== [3] 含 Alarm/Timer 的内容类名（用于确认识别关键词） ====="
grep -rhiE "interface .*(Alarm|Timer)" "$OUT/MobileTimer" --include=*.h 2>/dev/null | head -n 60

echo
echo "结果已落在 $OUT ，按上面 [1][2][3] 把真实类名/方法回填到 Tweak.xm。"
