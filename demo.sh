# Copyright (C) 2022 Nippon Telegraph and Telephone Corporation.
#!/bin/bash

# fist startup will fail by timeout because of repo mismatch
limactl start lustre-vm/lustre.yaml

set -eu
# then require repository url change
limactl shell lustre sh -c "sudo sed -i 's/^mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-Linux-*"
limactl shell lustre sh -c "sudo sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-Linux-*"

limactl stop lustre
limactl start lustre

# setup lustre environ
# those scripts refers to https://wiki.lustre.org/Installing_the_Lustre_Software
limactl shell lustre sh lustre-vm/lustre/pre-install.sh

limactl stop lustre
limactl start lustre

limactl shell lustre sh lustre-vm/lustre/install.sh

limactl stop lustre
limactl start lustre

limactl shell lustre sh lustre-vm/lustre/setup.sh

# setup slurm environ
limactl shell lustre sh lustre-vm/slurm/install.sh

# run demo script
limactl shell lustre bash -c "sbatch -o ~/result lustre-vm/sample_jobs/fetch.sh"
limactl shell lustre bash -c "cat ~/result"
