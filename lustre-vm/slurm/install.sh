# Copyright (C) 2022 Nippon Telegraph and Telephone Corporation.
#!/bin/bash

set -eu

export SLURM_SOURCE="slurm-21.08.8-2.tar.bz2"
export PACKAGE_DIR=`pwd`

# install dependencies
sudo yum install -y rpmdevtools wget gcc make systemd munge munge-libs python38 readline-devel mysql-devel perl lua lua-socket pam-devel
sudo yum install -y --enablerepo=powertools munge-devel lua-devel
# NOTE: centos8's json-c is 0.13, it seems to be ok for use.
sudo yum install -y json-c json-c-devel

# setup munged
sudo sh -c "dd if=/dev/urandom bs=1 count=1024 > /etc/munge/munge.key"
sudo chmod 600 /etc/munge/munge.key
sudo chown munge.munge /etc/munge/munge.key
sudo systemctl enable --now munge

# download bz2 slurm source file
cd ${HOME}
wget https://download.schedmd.com/slurm/${SLURM_SOURCE}
rpmbuild -ta ${SLURM_SOURCE}

# install slurm software via rpm
sudo yum localinstall -y ${HOME}/rpmbuild/RPMS/x86_64/*.rpm

# setup config for slurm-all-in-one
sudo cp /etc/slurm/slurm.conf.example /etc/slurm/slurm.conf
sudo sed -i 's/SlurmctldHost=linux0/SlurmctldHost=lima-lustre/g' /etc/slurm/slurm.conf
sudo sed -i 's/SlurmUser=slurm/SlurmUser=root/g' /etc/slurm/slurm.conf
sudo sed -i 's/NodeName=linux\[1-32\] CPUs=1/NodeName=lima-lustre CPUs=4 CoresPerSocket=4/g' /etc/slurm/slurm.conf
sudo cp /etc/slurm/cgroup.conf.example /etc/slurm/cgroup.conf

sudo pip3.8 install -r ${PACKAGE_DIR}/lfsccm/requirements.txt
sudo pip3.8 install ${PACKAGE_DIR}/lfsccm
sudo sh -c "echo 'Directive=PCC' > /etc/slurm/burst_buffer.conf"
sudo sh -c "echo 'NodeName=lima-lustre rwid=1 roid=1' > /etc/slurm/lfsccm.conf"
if ! grep -qF 'BurstBufferType=burst_buffer/lua' /etc/slurm/slurm.conf; then
    sudo sed -i '/^TaskPlugin=.*/a BurstBufferType=burst_buffer\/lua' /etc/slurm/slurm.conf
fi

sudo systemctl enable --now slurmctld
sudo systemctl enable --now slurmd
# if you find the compute node is now down state, run following command to update the status
# sudo scontrol update nodename=lima-lustre-centos8 state=idle

# TODO: investigate the way to resolve the remote node state via ssh intead of no pass phrase keys
sudo ssh-keygen -N "" -f /root/.ssh/id_rsa
sudo sh -c "cat /root/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys"
# for idempotent way, remove older host entity from known_hosts file
set +e
sudo ssh-keygen -R lima-lustre
set -e
sudo ssh -o StrictHostKeyChecking=no root@lima-lustre exit
