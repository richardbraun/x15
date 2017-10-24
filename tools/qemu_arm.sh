#!/bin/sh

# Amount of physical memory
# XXX The kernel configuration must use the same value or less.
RAM=64

# Number of processors. Keep this below the number of physical processors
# because the kernel doesn't replace spinning with sleeping from within
# a virtual machine, which causes performance to collapse.
NR_CPUS=4

# QEMU system emulator
QEMU_EXE=qemu-system-arm

# KVM options
KVM="-enable-kvm -cpu host"
KVM=


# Don't change from here unless you know what you're doing


X15=$PWD/x15
TMPDIR=$(mktemp -d)
BIN=$TMPDIR/x15.bin
IMG=$TMPDIR/flash.img

arm-none-eabi-objcopy -O binary x15 $BIN
dd if=/dev/zero of=$IMG bs=1M seek=64 count=0
dd if=$BIN of=$IMG conv=notrunc

$QEMU_EXE $KVM \
          -M virt-2.8 \
          -ctrl-grab \
          -gdb tcp::1234 \
          -m $RAM \
          -smp $NR_CPUS \
          -monitor stdio \
          -drive file=$IMG,if=pflash,format=raw

rm -rf $TMPDIR
