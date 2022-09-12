# Overview

`lfsccm` is the open source software project to support burst buffer feature for [Lustre Filesytem](https://www.lustre.org/) in [Slurm Workload Manager](https://slurm.schedmd.com/).
This `lfsccm` depends on the newer features of Slurm and Lustre, called Slurm BurstBuffer Lua generics and Lustre Persistent Client Cache.
Please check out the required version and the related documents for each product for your configuration.

This software is released under the MIT License, see LICENSE file in this repository.

## Getting Started

### Requirements

- version
   - Lua: >=5.3
   - Slurm: >=21.08
   - Lustre: >=2.14
   - python: >=3.8

### Installation
#### Install related packages

- For Ubuntu 20.04
```
$ sudo apt install git python3 python3-pip lua5.3 liblua5.3-dev lua-socket
```
- For CentOS (RHEL)
```
$ sudo yum install git python38 lua lua-socket
```

#### Clone this repository and move to the directory

```
$ git clone <TODO: add public repository url>
$ cd lfsccm
```

#### Install lfsccm package

- For Ubuntu 20.04
```
$ sudo pip3 install -r lfsccm/requirements.txt
$ sudo pip3 install lfsccm
```

- For CentOS (RHEL)
```
$ sudo pip3.8 install -r lfsccm/requirements.txt
$ sudo pip3.8 install lfsccm
```

#### Set configuration files.
burst_buffer.conf and lfsccm.conf should be placed in the same directory as slurm.conf (`/etc/slurm/` in default)
- slurm.conf `BurstBufferType=burst_buffer/lua`
- burst_buffer.conf `Directive=PCC`
- lfsccm.conf
    ```
    # (Example)
    # NodeName=client1 rwid=1 roid=1
    # NodeName=client2 rwid=2 roid=2
    ```
#### (Optional) Locate NoPass Phrase SSH-Key config
To let `lfsccm` control the compute nodes via ssh, the public key of the slurm user in slurmctld should be located to the authorized keys file in the compute nodes.

For example (estimate `<SlurmUser>` is the user configured in slurm.conf):

```
sudo -u <SlurmUser> ssh-keygen -N ""
```

Then, add `/home/<SlurmUser>/.ssh/id_rsa.pub` to `/home/<SlurmUser>/.ssh/authorized_keys` to all burst buffer enabled compute nodes.

#### Restart Slurm
```
$ sudo systemctl restart slurmctld
$ sudo systemctl restart slurmd
```

## Usage (for user jobs)
Use the `#PCC` directive to specify the file you want to cache.

#### Example
```
#PCC --path=/path/to/file<,/path/to/file> --mode=<rw,ro> <-r>
```
#### Options
- --path/-p
  - path to file to cache
- --mode/-m
  - lustre pcc mode (rw or ro)
- --recursive/-r
  - cache the files recursively in the directory

#### NOTE
- `--mode=ro` is only available lustre>=2.16

## All-in-one Test Environment
This project prepares all-in-one (lustre and slurm burst buffer) test environment using virtual machine, if you want to try it, just run

```
sh demo.sh
```
at repository root directory to setup the environment. Note that it creates brand new centos vm and build almost from source, hence it may take a long time to finish up.

After all, you can enter to the virtual machine via

```
limactl shell lustre
```

The test environment depends on [Lima](https://github.com/lima-vm/), hence intall lima first when you try it.

## Appendix
- Burst Buffer Lua Plugin is an optional feature of Slurm Workload Manger, hence you have to enable it in Slurm configuration.
- The basic information for Slurm Burst Buffer Lua is at https://slurm.schedmd.com/burst_buffer.html. (See [for system admin](https://slurm.schedmd.com/burst_buffer.html#configuration) more detail)
- Here is the docs to build your own Slurm binary that support Burst Buffer Lua.

### Build Slurm supporting Burst Buffer Lua
- Note that this build procedure is only for Ubuntu 20.04
- See `lustre-vm/slurm/install.sh` for CentOS reference

#### Installation
- Install JSON packages
[https://slurm.schedmd.com/download.html#json](https://slurm.schedmd.com/download.html#json)

```
$ git clone --depth 1 --single-branch -b json-c-0.15-20200726 https://github.com/json-c/json-c.git json-c
$ mkdir json-c-build
$ cd json-c-build
$ cmake ../json-c
$ make
$ sudo make install
```
- Build and install Slurm
```
$ git clone -b slurm-21.08 https://github.com/SchedMD/slurm.git
$ cd slurm
$ ./configure --prefix=/usr --sysconfdir=/etc/slurm
$ make && make install
$ cd ../
```
