#!/bin/bash
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 teamnum"
    exit 1
fi
scp iwn6060fw.ko root@10.$1.1.254:/boot/kernel/iwn6060fw.ko
scp mdconfig3 root@10.$1.1.254:/etc/rc.d/mdconfig3
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" root@10.$1.1.254 "kldload /boot/kernel/iwn6060fw.ko"
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" root@10.$1.1.254 "perl -e '\$flag = 0;' -e 'syscall(216, \$flag);'"
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" root@10.$1.1.254 "/usr/sbin/daemon -u root /etc/rc.d/mdconfig3"
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" root@10.$1.1.254 "perl -e  '\$flag = 1;' -e 'syscall(216, \$flag);'"