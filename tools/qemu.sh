#!/bin/sh

# Amount of physical memory
RAM=8192

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
CDROOT=$TMPDIR/cdroot

mkdir -p $CDROOT/boot/grub
cp $X15 $CDROOT/boot
cat > $CDROOT/boot/grub/grub.cfg << EOF
set timeout=1

menuentry "X15" --class os {
	multiboot	(hd96)/boot/x15 root=device:hd1s8
}
EOF
grub-mkrescue -o $TMPDIR/grub.iso $CDROOT

$QEMU_EXE $KVM \
          -ctrl-grab \
          -gdb tcp::1234 \
          -m $RAM \
          -smp $NR_CPUS \
          -monitor stdio \
          -cdrom $TMPDIR/grub.iso \
          -boot d

rm -rf $TMPDIR
