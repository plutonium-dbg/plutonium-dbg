#!/bin/sh

# Based on Google's syzkaller project (https://github.com/google/syzkaller/, Apache 2.0 license)
# See https://github.com/google/syzkaller/blob/master/tools/create-image.sh

set -eux

if [ "$#" -ne 2 ] ; then
    echo "Usage: $0 <debian release> <vm folder>" >&2
    exit 1
fi

SCRIPT="$(readlink -f "$0")"
RELEASE="$1"
ROOT="$(readlink -f "$2")"

VM="$ROOT/vm"
KERNEL="$(dirname "$SCRIPT")/linux/"
IMAGENAME="vm.img"
IMAGE="$ROOT/$IMAGENAME"

if [ -d "$VM" ] ; then
    sudo rm -rfI "$VM"
elif [ -e "$VM" ] ; then
    echo "$VM exists, but is not a directory" >&2
    exit 1
fi
mkdir -p "$VM"

# Install packages. For wheezy, requires the vsyscall=emulate kernel parameter
sudo debootstrap --include=openssh-server,curl,tar,gcc,libc6-dev,time,strace,sudo,less,psmisc "$RELEASE" "$VM"

# Enable password-less login
sudo sed -i '/^root/ { s/:x:/::/ }' "$VM/etc/passwd"

# Login automatically on boot
echo 'T0:23:respawn:/sbin/getty -a root -L ttyS0 115200 vt100' | sudo tee -a "$VM/etc/inittab"

# Set up networking
printf '\nauto eth0\niface eth0 inet dhcp\n' | sudo tee -a "$VM/etc/network/interfaces"
echo -en "127.0.0.1\tlocalhost\n" | sudo tee "$VM/etc/hosts"
echo "nameserver 1.1.1.1" | sudo tee -a "$VM/etc/resolve.conf"

# Set up mount points
echo 'debugfs /sys/kernel/debug debugfs defaults 0 0' | sudo tee -a "$VM/etc/fstab"
echo 'binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc defaults 0 0' | sudo tee -a "$VM/etc/fstab"

# Set kernel options
echo 'SELINUX=disabled' | sudo tee "$VM/etc/selinux/config"
echo "kernel.printk = 7 4 1 3" | sudo tee -a "$VM/etc/sysctl.conf"
echo "net.ipv4.ping_group_range = 0 65535" | sudo tee -a "$VM/etc/sysctl.conf"
# To disable segfault messages: echo 'debug.exception-trace = 0' | sudo tee -a "$VM/etc/sysctl.conf"

# Generate SSH key for use with the VM
ssh-keygen -f "$ROOT/id_rsa" -t rsa -N ''
sudo mkdir -p "$VM/root/.ssh/"
cat "$ROOT/id_rsa.pub" | sudo tee "$VM/root/.ssh/authorized_keys"

# Build image
MOUNT=$(mktemp -d)
rm -f "$IMAGE"

dd if=/dev/zero of="$IMAGE" bs=1M seek=2047 count=1
sudo mkfs.ext4 -F "$IMAGE"
sudo mount -o loop "$IMAGE" "$MOUNT"
sudo cp -a "$VM/." "$MOUNT/."
sudo umount "$MOUNT"
sudo rmdir "$MOUNT"

# Write boot scripts
cat > "$ROOT/run.sh" << EOF
#!/bin/sh
VMPATH="\$(dirname "\$(readlink -f "\$0")")"
qemu-system-x86_64 -kernel "$KERNEL/arch/x86/boot/bzImage" \\
    -append "console=ttyS0 root=/dev/sda debug earlyprintk=serial net.ifnames=0 rw" \\
    -hda "\$VMPATH/$IMAGENAME" \\
    -net user,hostfwd=tcp::20022-:22,hostfwd=tcp::1337-:31337 -net nic \\
    -enable-kvm -nographic -m 2G -smp 2 \\
    -pidfile "\$VMPATH/vm.pid" \\
    2>&1 | tee "\$VMPATH/vm.log"
EOF

cat > "$ROOT/ssh.sh" << EOF
#!/bin/sh
VMPATH="\$(dirname "\$(readlink -f "\$0")")"
ssh -i "$VMPATH/id_rsa" -p 20022 -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" root@localhost
EOF

cat > "$ROOT/scp.sh" << EOF
#!/bin/bash
VMPATH="\$(dirname "\$(readlink -f "\$0")")"
FILES=\${@:1:\$#-1}
TARGET=\${@:\$#}
scp -i "$VMPATH/id_rsa" -P 20022 -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" \$FILES "root@localhost:\$TARGET"
EOF

chmod a+x "$ROOT/run.sh" "$ROOT/ssh.sh" "$ROOT/scp.sh"
