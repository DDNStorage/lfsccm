#!/bin/bash
#PCC --path=/mnt/lustre/sample --mode=rw

cat /mnt/lustre/sample
lfs pcc state /mnt/lustre/sample
