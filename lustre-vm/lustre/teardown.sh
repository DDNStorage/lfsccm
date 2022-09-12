# Copyright (C) 2022 Nippon Telegraph and Telephone Corporation.
# !/bin/bash

sudo killall lhsmtool_posix

sudo umount -f /mnt/lustre
sudo umount -f /mnt/pcc
sudo umount -f /lustre/ost0
sudo umount -f /lustre/ost1
sudo umount -f /lustre/mdt

sudo rm -rf /srv/lustre
