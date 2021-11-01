AC_INIT([unyte_ebpf_loadbalancer], m4_esyscmd_s(cat VERSION), [alex.huang-feng@insa-lyon.fr])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AC_CONFIG_MACRO_DIR([m4])
AC_PREFIX_DEFAULT([/usr/local])

AM_PROG_AR
LT_INIT

AC_LANG([C])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC([gcc])

AC_PROG_LN_S

AC_ARG_WITH([pkgconfigdir],
    [AS_HELP_STRING([--with-pkgconfigdir], [pkg-config directory to install the .pc file.])],
    [ with_pkgconfigdir=$with_pkgconfigdir ],
    [ with_pkgconfigdir=$libdir/pkgconfig ]
)

PKGCONFIG_USER=$with_pkgconfigdir
AC_SUBST([PKGCONFIG_USER])

AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug], [Enable debug logs in eBPF program.])],
    [ debug_enabled=yes ],
    [ debug_enabled=no ]
)
AM_CONDITIONAL(DEBUG, test "x$debug_enabled" = "xyes")

dnl eBPF example
AC_CHECK_LIB(bpf, bpf_object__find_map_by_name, [], [
    echo "*** Error! You need to install libbpf first. ***"
    exit -1
])

AC_CHECK_PROG([CCLANG], [clang], [yes])
AS_IF([ test "x$CCLANG" != xyes ], [
    echo "*** Error! eBPF needs CLANG as dependency. Please install it first. ***"
    exit -1
])
AC_CHECK_PROG([BPFTOOL], [bpftool], [yes])
AS_IF([ test "x$BPFTOOL" != xyes ], [
    echo "*** Error! eBPF needs bpftool as dependency. Please install it first. ***"
    exit -1
])

AC_CHECK_FILE([/sys/kernel/btf/vmlinux], [], [
    echo "*** Error! eBPF needs vmlinux to compile the eBPF program. ***"
    exit -1
])

AC_ARG_WITH([linux],
    [AS_HELP_STRING([--with-linux], [Linux source headers [[default: /usr/src/linux]]])],
    [LINUX_HEADERS="$withval"],
    [LINUX_HEADERS=/usr/src/linux]
)
AC_SUBST([LINUX_HEADERS])
dnl linux source headers
AC_CHECK_FILES([
    $LINUX_HEADERS/include/uapi/linux
    $LINUX_HEADERS/arch/x86/include
    $LINUX_HEADERS/arch/x86/include/generated
    $LINUX_HEADERS/include
    $LINUX_HEADERS/arch/x86/include/uapi
    $LINUX_HEADERS/arch/x86/include/generated/uapi
    $LINUX_HEADERS/include/uapi
    $LINUX_HEADERS/include/generated/uapi
    ], [], [
        echo "*** Error! eBPFa needs linux source to compile the eBPF program. ***"
        echo "*** Linux sources were not found in $LINUX_HEADERS ***"
        exit -1
    ]
)

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    unyte-reuseport-loadbalancer.pc
])
AC_OUTPUT
