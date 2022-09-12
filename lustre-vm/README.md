Test Environment Setup Scripts

require [lima](https://github.com/lima-vm/lima)

```
limactl start lustre.yaml

(wait on booting)

# if the starting process would halted on waiting ssh connection,
# you may need to update repository url for yum packages. See demo.sh
# for updating the source file.

# after launching, run install/setup processes as follows

limactl shell lustre lustre/pre-install.sh
limactl stop lustre
limactl start lustre
limactl shell lustre lustre/install.sh
limactl stop lustre
limactl start lustre
limactl shell lustre lustre/setup.sh

# if you want to recreate lustre environment, run
# limactl shell lustre lustre/teardown.sh
# and then,
# limactl shell lustre lustre/setup.sh
# again. Note that all of files in the lustre will be erased.

limactl shell lustre slurm/install.sh

# congrats, now you have slurm/lustre environment in the centos lima vm.
# if you want to log-in the vm, just run
# limactl shell lustre
