# eBPF Load balancer
Linux eBPF load balancer to be attached into REUSE_PORT socket group.
This eBPF program allows load balance packets based on their src IP. All packets from the same src IP will land into the same collector.

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
Another requirement is `libbpf` (github.com/libbpf/libbpf) >= 0.4.0.

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

### Configure options
There are some custom `./configure` options :
- `--with-pkgconfigdir=[/own_path/pkgconfig]`: overwrite pkgconfig directory to install .pc file [default: ${PREFIX}/lib/pkgconfig]
- `--with-linux=[/own_path/linux/src]`: linux source code necesary for eBPF compilation [default: /usr/src/linux]. (On Ubuntu use /usr/src/<linux>-generic version)

## Running
To test the loadbalancer, multiple instances should be launched. In this example, messages will be loadbalanced to 3 instances based on their src IP.
To run 3 collectors:
```shell
$ cd src
$ sudo bash -c 'ulimit -l unlimited; ./main 10.0.2.15 10001 0 3'   // first collector
$ sudo bash -c 'ulimit -l unlimited; ./main 10.0.2.15 10001 1 3'   // second collector
$ sudo bash -c 'ulimit -l unlimited; ./main 10.0.2.15 10001 2 3'   // third collector
```

To see the loadbalancer working, you should instance multiple publishers sending from different src ips, otherwise, all packets will be hashed to the same collector.
Publisher:
```shell
$ cd src
$ ./src/udp_publisher 10.0.2.15 10001 100
```

## Debug
To show the maps:
(`sudo` may needed)
```shell
$ bpftool map dump name tcp_balancing_t
$ bpftool map dump name udp_balancing_t
```

## Contributors
This repository is based on [reuseport](https://github.com/eduarrrd/reuseport), a loadbalancer used in pmacct.
