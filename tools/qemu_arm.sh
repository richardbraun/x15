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
FLASH=$TMPDIR/flash

arm-none-eabi-objcopy -O binary x15 x15.bin
dd if=/dev/zero of=flash.img bs=1M count=64
dd if=x15.bin of=flash.img conv=notrunc

$QEMU_EXE $KVM \
          -M virt-2.8 \
          -ctrl-grab \
          -gdb tcp::1234 \
          -m $RAM \
          -smp $NR_CPUS \
          -monitor stdio \
          -pflash flash.img

rm -rf $TMPDIR
