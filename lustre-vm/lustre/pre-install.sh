# Copyright (C) 2022 Nippon Telegraph and Telephone Corporation.
#!/bin/bash
set -eu

# disable SELinux to setup loopback device for lustre mdt
sudo sed -i 's/^SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config

sudo sh -c "cat > /etc/yum.repos.d/lustre.repo <<\__EOF
[lustre-server]
name=lustre-server
baseurl=https://downloads.whamcloud.com/public/lustre/lustre-2.14.0/el8.3/server
# exclude=*debuginfo*
gpgcheck=0

[lustre-client]
name=lustre-client
baseurl=https://downloads.whamcloud.com/public/lustre/lustre-2.14.0/el8.3/client/
# exclude=*debuginfo*
gpgcheck=0

[e2fsprogs-wc]
name=e2fsprogs-wc
baseurl=https://downloads.whamcloud.com/public/e2fsprogs/latest/el8
# exclude=*debuginfo*
gpgcheck=0
__EOF"

sudo yum update -y --exclude=kernel* --exclude=centos*

sudo yum -y install epel-release

sudo yum -y --nogpgcheck --disablerepo=* --enablerepo=e2fsprogs-wc \
    install e2fsprogs

sudo yum -y --nogpgcheck --disablerepo=base,extras,updates \
  --enablerepo=powertools,lustre-server install \
    kernel \
    kernel-devel \
    kernel-headers \
    kernel-tools \
    kernel-tools-libs \
    kernel-tools-libs-devel
