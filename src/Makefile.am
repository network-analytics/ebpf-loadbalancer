AM_LDFLAGS = $(EXTRA_LDFLAGS)

if DEBUG
DEBUG_FLAGS=-D_LOG_DEBUG
endif

ACLOCAL_AMFLAGS = -I m4

EBPF_CLDFLAGS=-fcolor-diagnostics -D_FILE_OFFSET_BITS=64 -Wall -Winvalid-pch -g -fPIC -g -O2 -D__KERNEL__ -D__TARGET_ARCH_x86 --target=bpf -Wall -Wno-macro-redefined -D__BPF_TRACING__

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

unyte_reuseport_kern.o: unyte_reuseport_kern.c vmlinux.h
	clang $(EBPF_CLDFLAGS) $(DEBUG_FLAGS) -o $@ -c $<

all-local: unyte_reuseport_kern.o

unyte_reuseport_kern_odir = $(libdir)
unyte_reuseport_kern_o_DATA = \
	unyte_reuseport_kern.o \
	$(NULL)

unyteincludedir = $(includedir)/unyte-reuseport-loadbalancer
unyteinclude_HEADERS = 		\
    unyte_reuseport_user.h  \
    $(NULL)

bin_PROGRAMS = main udp_publisher

main_SOURCES = main.c unyte_reuseport_user.c
main_CFLAGS = -I$(srcdir)/../../src -Wextra -Wall -ansi -g -std=c11 -D_GNU_SOURCE -fPIC -pthread $(DEBUG_FLAGS)
# main_LDADD = $(srcdir)/../../src/libunyte-reuseport-loadbalancer.la

udp_publisher_SOURCES = udp_publisher.c
udp_publisher_CFLAGS = -I$(srcdir)/../../src -Wextra -Wall -ansi -g -std=c11 -D_GNU_SOURCE -fPIC -pthread $(DEBUG_FLAGS)

lib_LTLIBRARIES = libunyte-reuseport-loadbalancer.la

libunyte_reuseport_loadbalancer_la_SOURCES = \
    unyte_reuseport_user.c           \
    unyte_reuseport_user.h           \
    $(NULL)

libunyte_reuseport_loadbalancer_la_CFLAGS = -Wextra -Wall -ansi -g -std=c11 -D_GNU_SOURCE -fPIC $(DEBUG_FLAGS)
