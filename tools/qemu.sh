#!/bin/sh

# Amount of physical memory
RAM=1024

# Number of processors. Keep this below the number of physical processors
# because the kernel doesn't replace spinning with sleeping from within
# a virtual machine, which causes performance to collapse.
NR_CPUS=4

# QEMU system emulator
QEMU_EXE=qemu-system-i386
QEMU_EXE=qemu-system-x86_64

# KVM options
KVM=
KVM="-enable-kvm -cpu host"


# Don't change from here unless you know what you're doing


X15=$PWD/x15
TMPDIR=$(mktemp -d)

objcopy -O elf32-i386 $X15 $TMPDIR/x15

cd $TMPDIR
$QEMU_EXE $KVM \
          -ctrl-grab \
          -gdb tcp::1234 \
          -m $RAM \
          -smp $NR_CPUS \
          -monitor stdio \
          -kernel x15 \
          -append "console=atcons"

rm -rf $TMPDIR
