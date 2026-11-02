#!/bin/sh
# 一键打包 NoAlarmIsland 为 rootless .deb
# 用法：在装有 theos 的 macOS 上执行 ./build_deb.sh
#
# 说明：
#  - 优先走 theos（make package），它会自动编译 dylib 并产出 rootless deb。
#  - 若环境无 theos，但你已经手动把编译好的 NoAlarmIsland.dylib
#    放到 deb/var/jb/Library/MobileSubstrate/DynamicLibraries/ 下，
#    脚本会直接用 dpkg-deb 打包（适用于 CI / 无 theos 的机器）。
set -e

cd "$(dirname "$0")"

DYLIB=deb/var/jb/Library/MobileSubstrate/DynamicLibraries/NoAlarmIsland.dylib

# 1) 优先 theos
if [ -n "$THEOS" ] && command -v make >/dev/null 2>&1 && [ -f Makefile ]; then
    echo ">> theos 检测到，执行 make package"
    make package FINALPACKAGE=1
    echo ">> 产物在 packages/"
    ls -1 packages/ 2>/dev/null || true
    exit 0
fi

# 2) 兜底：dpkg-deb（需先有编译好的 dylib）
if [ ! -f "$DYLIB" ]; then
    echo "!! 未找到编译好的 dylib：$DYLIB"
    echo "   请先用 theos 编译（make），或把 NoAlarmIsland.dylib 放到该路径后再运行本脚本。"
    exit 1
fi

# 确保 control 权限正确
chmod 0644 deb/DEBIAN/control 2>/dev/null || true

OUT="NoAlarmIsland_1.0.0_iphoneos-arm64.deb"
rm -f "$OUT"
dpkg-deb --root-owner-group --build deb "$OUT"
echo ">> 已生成 $OUT"
ls -l "$OUT"
