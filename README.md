# eBPF Load balancer
Linux eBPF load balancer to attach into REUSE_PORT socket group.

## Dependencies
This project uses autotools, gcc and clang to compile.

On Ubuntu:
```shell
$ sudo apt-get install autoconf libtool make automake gcc pkg-config
```

On Centos (tested on `Centos 8`):
```shell
$ sudo yum install autoconf libtool make automake pkgconf
```

### eBPF Dependencies

To use eBPF loadbalancing `Python3` is needed for eBPF compilation.

On Ubuntu:
```shell
$ sudo apt install linux-headers-$(uname -r) clang libbpf-dev linux-tools-$(uname -r)
```

On Centos (tested on `Centos 8`):
```shell
$ sudo yum install kernel-headers clang
$ sudo dnf --enablerepo=powertools install libbpf-devel
$ sudo dnf install bpftool
```

## Install
To install src code:
```shell
$ ./bootstrap
$ ./configure       # See ./configure --help for options
$ make
$ make install      # Usually needs sudo permissions
```

## Running
TODO:

## Debug
To show the maps:
(`sudo` may needed)
```shell
$ bpftool map dump name tcp_balancing_t
$ bpftool map dump name udp_balancing_t
```

## Contributors
This repository is based on [reuseport](https://github.com/eduarrrd/reuseport), a loadbalancer used in pmacct.
