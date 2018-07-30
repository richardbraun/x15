#!/bin/sh

# Amount of physical memory
RAM=1024

# Number of processors. Keep this below the number of physical processors
# because the kernel doesn't replace spinning with sleeping from within
# a virtual machine, which causes performance to collapse.
NR_CPUS=4


# Don't change from here unless you know what you're doing

# QEMU system emulator
QEMU_EXE=qemu-system-x86_64

OBJCOPY="$1"
NATIVE_ARCH=$(uname -m | sed -e s/i.86/x86/ -e s/x86_64/x86/)

if [ "$NATIVE_ARCH" != x86 ]; then
    KVM=
elif lsmod | grep -q '^kvm'; then
    KVM="-enable-kvm -cpu host"
fi

X15=$PWD/x15
TMPDIR=$(mktemp -d)

$OBJCOPY -O elf32-i386 $X15 $TMPDIR/x15

cd $TMPDIR
$QEMU_EXE $KVM \
          -ctrl-grab \
          -gdb tcp::1234 \
          -m $RAM \
          -smp $NR_CPUS \
          -nographic \
          -kernel x15 \
          -append "console=uart0"

rm -rf $TMPDIR
