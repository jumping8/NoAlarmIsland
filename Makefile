ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:16.0

# rootless 打包方案（Dopamine / palera1n rootless / Serotonin）
THEOS_PACKAGE_SCHEME = rootless
INSTALL_TARGET = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = NoAlarmIsland
NoAlarmIsland_FILES = Tweak.xm
NoAlarmIsland_CFLAGS = -fobjc-arc -Wno-error
NoAlarmIsland_FRAMEWORKS = Foundation UIKit
NoAlarmIsland_PRIVATE_FRAMEWORKS = MobileTimer
NoAlarmIsland_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	@install.exec "killall -9 SpringBoard" 2>/dev/null || true
