# Copyright (C) 2022 Nippon Telegraph and Telephone Corporation.
# !/bin/bash
# FIXME: this script is not idempotent please run teardown.sh first if you
# gonna re-create the environment
set -eu
export MYIP=`hostname  -I | awk -F" " '{print $1}'`
export IAM=`whoami`

# create 2 loopback files on the system
sudo mkdir -p /srv/lustre
sudo dd if=/dev/zero of=/srv/lustre/lmdt bs=1M count=1000
sudo dd if=/dev/zero of=/srv/lustre/lost0 bs=1M count=1000
sudo dd if=/dev/zero of=/srv/lustre/lost1 bs=1M count=1000

# create file system
sudo mkfs.lustre --fsname=lfs --mgs --mdt /srv/lustre/lmdt
sudo mkfs.lustre --fsname=lfs --index=0 --ost --mgsnode=${MYIP}@tcp /srv/lustre/lost0
sudo mkfs.lustre --fsname=lfs --index=1 --ost --mgsnode=${MYIP}@tcp /srv/lustre/lost1

# mount mdt and ost
sudo mkdir -p /lustre/mdt
sudo mkdir -p /lustre/ost0
sudo mkdir -p /lustre/ost1

sudo mount -t lustre -o loop /srv/lustre/lmdt /lustre/mdt
sudo mount -t lustre -o loop /srv/lustre/lost0 /lustre/ost0
sudo mount -t lustre -o loop /srv/lustre/lost1 /lustre/ost1

# mout lustre file system via lustre-client
sudo mkdir -p /mnt/lustre
sudo mount -t lustre ${MYIP}@tcp:/lfs /mnt/lustre
sudo chown ${IAM}.${IAM} /mnt/lustre/
echo "hello burst buffer" > /mnt/lustre/sample

# for pcc setting
sudo dd if=/dev/zero of=/srv/lustre/lcache bs=1M count=1000
sudo mkfs -t xfs /srv/lustre/lcache
sudo mkdir -p /mnt/pcc
sudo mount -t xfs  /srv/lustre/lcache /mnt/pcc
sudo lctl set_param mdt.lfs-MDT0000.hsm_control=enabled
# TODO: fix lhsmtool_posix to run at most once, this command can invoke the daemon multiple times as called.
sudo lhsmtool_posix --daemon --hsm-root /mnt/pcc --archive=1 /mnt/lustre > /dev/null 2>&1
sudo lctl pcc add /mnt/lustre /mnt/pcc --param "projid={1000} rwid=1"
