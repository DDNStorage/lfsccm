# Copyright (C) 2022 Nippon Telegraph and Telephone Corporation.
#!/bin/bash
set -eu

sudo yum -y --nogpgcheck --enablerepo=ha,lustre-server install \
   kmod-lustre \
   kmod-lustre-osd-ldiskfs \
   lustre-osd-ldiskfs-mount \
   lustre \
   lustre-resource-agents

# TODO: add verification script for lustre installation
