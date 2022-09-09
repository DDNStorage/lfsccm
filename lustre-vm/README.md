TBD

require [lima](https://github.com/lima-vm/lima)

```
limactl start lustre-centos8.yaml

(wait on booting)

# if the starting process would halted on waiting ssh connection,
# run `limactl stop lustre-centos8` and then `limactl start lustre-centos8` again
# the halt/start would help to avoid sshfs errors on the limaprocess

# after launching, run install/setup processes as follows (now testing)

limactl shell lustre-centos8 lustre/pre-install.sh
limactl shell lustre-centos8 sudo reboot
limactl shell lustre-centos8 lustre/install.sh
limactl shell lustre-centos8 lustre/setup.sh

# if you want to recreate lustre environment, run
# limactl shell lustre-centos8 lustre/teardown.sh
# and then,
# limactl shell lustre-centos8 lustre/setup.sh
# again. Note that all of files in the lustre will be erased.

limactl shell lustre-centos8 slurm/install.sh

# congrats, now you have slurm/lustre environment in the centos lima vm.
# if you want to log-in the vm, just run
# limactl shell lustre-centos8

