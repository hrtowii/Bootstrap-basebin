#!/bin/sh

set -e

PREV_DIR=$(pwd)
WORK_DIR=$(dirname -- "$0")
cd "$WORK_DIR"

cd ChOma-main
make clean-all && make TARGET=ios
cd -

cd ldid
make clean && make
cd -

cd fastPathSign
make clean && make
cd -

cd uicache
make clean && make package
cd -

cd rebuildapp
make clean && make package
cd -

cd preload
make clean && make package
cd -

cd bootstrap
make clean && make package
cd -

cd bootstrapd
make clean && make package
cd -

cd devtest
make clean && make package
cd -

cd hooks
echo "[*] Building launchd hook"
make -C launchdhook

# echo "[*] Signing launchd hook"
# $(CTBYPASS) -i launchdhook/.theos/obj/debug/launchdhook.dylib -r -o launchdhook/launchdhooksigned.dylib

echo "[*] Building general hook"
make -C generalhook

# echo "[*] Signing general hook"
# $(CTBYPASS) -i generalhook/.theos/obj/debug/generalhook.dylib -r -o generalhook/generalhook.dylib

echo "[*] Building xpcproxyhook"
make -C xpcproxyhook

# echo "[*] Signing xpcproxyhook"
# $(LDID) -Sxpcproxyhook/.theos/obj/debug/xpcproxyhook.dylib
# $(CTBYPASS) -i xpcproxyhook/.theos/obj/debug/xpcproxyhook.dylib -r -o xpcproxyhook/xpcproxyhook.dylib

echo "[*] Building jitter"
make -C launchdhook/jitter
mv launchdhook/jitter/.theos/obj/debug/jitter launchdhook/jitter/jitterd

echo "[*] building cfprefsdshim"
make -C cfprefsdshim
cd -

echo "**** rebuild successful ****"

./copy.sh

cd "$PREV_DIR"
