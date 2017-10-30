#!/bin/sh

# XXX These parameters are currently hardcoded in the board configuration.
# XXX The script assumes an x86 host with an arm-none-eabi toolchain.

QEMU_EXE=qemu-system-arm

NR_CPUS=4
RAM=64

X15=$PWD/x15
TMPDIR=$(mktemp -d)
BIN=$TMPDIR/x15.bin
IMG=$TMPDIR/flash.img

arm-none-eabi-objcopy -O binary x15 $BIN
dd if=/dev/zero of=$IMG bs=1M seek=64 count=0
dd if=$BIN of=$IMG conv=notrunc

$QEMU_EXE \
-d int \
-D debug.log \
        -M virt-2.8 \
        -ctrl-grab \
        -gdb tcp::1234 \
        -m $RAM \
        -smp $NR_CPUS \
        -monitor stdio \
        -drive file=$IMG,if=pflash,format=raw

rm -rf $TMPDIR
