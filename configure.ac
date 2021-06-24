AC_PREREQ([2.69])
AC_INIT([ppp],
        [2.4.10],
        [https://github.com/ppp-project/ppp])

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE([enable])

AC_LANG(C)
AC_CONFIG_SRCDIR([pppd/main.c])
AC_CONFIG_HEADERS([pppd/config.h pppd/pppdconf.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_LN_S

PKG_PROG_PKG_CONFIG

AC_CANONICAL_HOST
build_linux=no
build_sunos=no

case "${host_os}" in
    linux*)
	build_linux=yes
	;;
    solaris2*)
	build_sunos=yes
	;;
    *)
	AC_MSG_ERROR(["OS ${host_os} not supported"])
	;;
esac

AM_CONDITIONAL([LINUX], [test "${build_linux}" = "yes" ])
AM_CONDITIONAL([SUNOS], [test "${build_sunos}" = "yes" ])
AM_COND_IF([SUNOS],
      CFLAGS="$CFLAGS -DSOL2 -DSRV4")

#
# Checks for header files, these will set the HAVE_[FILE]_H macros in config.h
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([  \
    asm/types.h     \
    crypt.h         \
    paths.h         \
    shadow.h        \
    sys/dlpi.h      \
    sys/ioctl.h     \
    sys/socket.h    \
    sys/time.h      \
    sys/uio.h       \
    time.h          \
    unistd.h        \
    utmp.h])

#
# Check for linux specific headers, required by pppoe, or pppol2tp
AM_COND_IF([LINUX], [
    AC_CHECK_HEADERS([          \
        net/bpf.h               \
        net/if.h                \
        net/if_types.h          \
        net/if_arp.h            \
        linux/if.h              \
        linux/if_ether.h        \
        linux/if_packet.h       \
        netinet/if_ether.h      \
        netpacket/packet.h])])

AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned long)
AC_CHECK_SIZEOF(unsigned short)

# Checks for library functions.
AC_CHECK_FUNCS([    \
    mmap            \
    logwtmp         \
    strerror])

#
# If libc doesn't provide logwtmp, check if libutil provides logwtmp(), and if so link to it.
AS_IF([test "x${ac_cv_func_logwtmp}" != "xyes"], [
    AC_CHECK_LIB([util], [logwtmp], [
        AC_DEFINE(HAVE_LOGWTMP, 1, ["System provides the logwtmp() function"])
        AC_SUBST([UTIL_LIBS], ["-lutil"])
    ])
])

#
# Check if libcrypt have crypt() function
AC_CHECK_LIB([crypt], [crypt],
    AC_SUBST([CRYPT_LIBS], ["-lcrypt"]))

#
# Should pppd link with -lsystemd (Linux only)
AC_ARG_ENABLE([systemd],
    AS_HELP_STRING([--enable-systemd], [Enable support for systemd notification]))
AM_CONDITIONAL(WITH_SYSTEMD, test "x${enable_systemd}" = "xyes")
AM_COND_IF([WITH_SYSTEMD],
    AC_DEFINE([SYSTEMD], 1, [Enable support for systemd notifications]))

#
# Enable Callback Protocol Support, disabled by default
AC_ARG_ENABLE([cbcp],
    AS_HELP_STRING([--enable-cbcp], [Enable Callback Protocol]))
AM_CONDITIONAL(WITH_CBCP, test "x${enable_cbcp}" = "xyes")
AM_COND_IF([WITH_CBCP],
    AC_DEFINE([CBCP_SUPPORT], 1, [Have Callback Protocol support]))

#
# Disable support for IPX control protocol
AC_ARG_ENABLE([ipxcp],
    AS_HELP_STRING([--enable-ipxcp], [Enable IPX Control Protocol support]))
AM_CONDITIONAL(WITH_IPXCP, test "x${enable_ipxcp}" = "xyes")
AM_COND_IF(WITH_IPXCP,
    AC_DEFINE([IPX_CHANGE], 1, ["Have IPX Control Protocol"]))
AS_IF([test "x${build_sunos}" = "xyes" && test "x${enable_ipxcp}" = "xyes"],
    [AC_MSG_ERROR([IPXCP is not supported on SunOS, disable using --disable-ipxcp])])

#
# Disable support for limiting session duration by maximum octets
AC_ARG_ENABLE([maxoctets],
    AS_HELP_STRING([--disable-maxoctets], [Disable support for limiting session by maximum octets]))
AS_IF([test "x$enable_maxoctets" != "xno"],
    AC_DEFINE([MAXOCTETS], 1, ["Limit sessions by maximum number of octets"]))

#
# Disable Microsoft extensions will remove CHAP and MPPE support
AC_ARG_ENABLE([microsoft-extensions],
    AS_HELP_STRING([--disable-microsoft-extensions], [Disable Microsoft CHAP / MPPE extensions]))

AM_CONDITIONAL(WITH_CHAPMS, test "x${enable_microsoft_extensions}" != "xno")
AM_COND_IF([WITH_CHAPMS],
    AC_DEFINE([CHAPMS], 1, ["Have Microsoft CHAP support"]))

AM_CONDITIONAL(WITH_MPPE, test "x${enable_microsoft_extensions}" != "xno")
AM_COND_IF([WITH_MPPE],
    AC_DEFINE([MPPE], 1, ["Have Microsoft MPPE support"]))

#
# Enable Microsoft LAN Manager support, depends on Microsoft Extensions
AC_ARG_ENABLE([mslanman],
    AS_HELP_STRING([--enable-mslanman], [Enable Microsoft LAN Manager support]))
AS_IF([test "x${enable_mslanman}" = "xyes" && test "x${enable_microsoft_extensions}" != "xno"],
    AC_DEFINE([MSLANMAN], 1, ["Have Microsoft LAN Manager support"]))

#
# Disable IPv6 support
AC_ARG_ENABLE([ipv6-support],
    AS_HELP_STRING([--disable-ipv6-support], [Disable IPv6 support]))
AM_CONDITIONAL(WITH_INET6, test "x${enable_ipv6_support}" != "xno")
AM_COND_IF([WITH_INET6],
    AC_DEFINE(INET6, 1, ["Have IPv6 support"]))

#
# Disable Multilink support
AC_ARG_ENABLE([multilink],
    AS_HELP_STRING([--enable-multilink], [Enable multilink support]))
AM_CONDITIONAL(WITH_MULTILINK, test "x${enable_multilink}" = "xyes")
AM_COND_IF([WITH_MULTILINK],
    AC_DEFINE([HAVE_MULTILINK], 1, ["Have multilink support"]))
AS_IF([test "x${build_sunos}" = "xyes" && test "x${enable_multilink}" = "xyes"],
    [AC_MSG_ERROR([Multilink is not supported on SunOS])])

#
# Multilink require Trivial Database Support
AM_CONDITIONAL(WITH_TDB, test "x${enable_multilink}" = "xyes")
AM_COND_IF([WITH_TDB],
    AC_DEFINE([USE_TDB], 1, ["Include TDB support"]))

#
# Enable support for loadable plugins
AC_ARG_ENABLE([plugins],
    AS_HELP_STRING([--disable-plugins], [Disable support for loadable plugins]))
AS_IF([test "x$enable_plugins" != "xno"],
    AC_DEFINE([PLUGIN], 1, ["Have support for loadable plugins"]))
AM_CONDITIONAL(WITH_PLUGINS, test "${enable_plugins}" != "no")

#
# Disable EAP-TLS support
AC_ARG_ENABLE([eaptls],
    AS_HELP_STRING([--disable-eaptls], [Disable EAP-TLS authentication support]))
AS_IF([test "x$enable_eaptls" != "xno"],
    AC_DEFINE([USE_EAPTLS], 1, ["Have EAP-TLS authentication support"]))
AM_CONDITIONAL(WITH_EAPTLS, test "${enable_eaptls}" != "no")

#
# Disable OpenSSL engine support
AC_ARG_ENABLE([openssl-engine],
    AS_HELP_STRING([--disable-openssl-engine], [Disable OpenSSL engine support]))
AS_IF([test "x$enable_openssl_engine" != "xno"], [],
    AC_DEFINE([OPENSSL_NO_ENGINE], 1, ["OpenSSL engine support"]))

#
# Specify runtime directory
AC_ARG_ENABLE([plugin-dir],
	AC_HELP_STRING([--with-plugin-dir=DIR], [Specify the plugin directory for pppd]))
AS_IF([test -n "$with_plugin_dir"],
	[PPPD_PLUGIN_DIR="$with_plugin_dir"],
	[PPPD_PLUGIN_DIR="${libdir}/pppd/$VERSION"])
AC_SUBST(PPPD_PLUGIN_DIR, "$PPPD_PLUGIN_DIR", [The pppd plugin directory])

#
# Specify runtime directory
AC_ARG_ENABLE([runtime-dir],
	AC_HELP_STRING([--with-runtime-dir=DIR], [Specify the runtime directory for pppd]))
AS_IF([test -n "$with_runtime_dir"],
	[PPPD_RUNTIME_DIR="$with_runtime_dir"],
	[PPPD_RUNTIME_DIR="${localstatedir}/run/pppd"])
AC_SUBST(PPPD_RUNTIME_DIR)

#
# Specify runtime directory
AC_ARG_ENABLE([logfile-dir],
	AC_HELP_STRING([--with-logfile-dir=DIR], [Specify the log directory for pppd]))
AS_IF([test -n "$with_logfile_dir"],
	[PPPD_LOGFILE_DIR="$with_logfile_dir"],
	[PPPD_LOGFILE_DIR="${localstatedir}/log/pppd"])
AC_SUBST(PPPD_LOGFILE_DIR)

#
# Check for OpenSSL
AX_CHECK_OPENSSL
AM_CONDITIONAL(WITH_OPENSSL, test "${with_openssl}" != "no")

#
# Check if OpenSSL has compiled in support for various ciphers
AS_IF([test "${with_openssl}" != "no" ], [
    AX_CHECK_OPENSSL_DEFINE([OPENSSL_NO_MD4], [md4])
    AX_CHECK_OPENSSL_DEFINE([OPENSSL_NO_MD5], [md5])
    AX_CHECK_OPENSSL_DEFINE([OPENSSL_NO_DES], [des])
    AX_CHECK_OPENSSL_DEFINE([OPENSSL_NO_SHA], [sha])
], [
    AS_IF([test "x$enable_eaptls" != "xno"],
        [AC_MSG_ERROR([OpenSSL not found, and if this is your intention then run configure --disable-eaptls])])
])

AM_CONDITIONAL([OPENSSL_HAVE_MD4], test "x${ac_cv_openssl_md4}" != "xno")
AM_COND_IF([OPENSSL_HAVE_MD4],,
    AC_DEFINE([USE_MD4], 1, [Use included md4 included with pppd]))

AM_CONDITIONAL([OPENSSL_HAVE_MD5], test "x${ac_cv_openssl_md5}" != "xno")
AM_COND_IF([OPENSSL_HAVE_MD5],,
    AC_DEFINE([USE_MD5], 1, [Use included md5 included with pppd]))

AM_CONDITIONAL([OPENSSL_HAVE_SHA], test "x${ac_cv_openssl_sha}" != "xno")
AM_COND_IF([OPENSSL_HAVE_SHA],,
    AC_DEFINE([USE_SHA], 1, [Use included sha included with pppd]))

AM_CONDITIONAL([OPENSSL_HAVE_DES], test "x${ac_cv_openssl_des}" != "xno")
AM_COND_IF([OPENSSL_HAVE_DES],,
    AC_DEFINE([USE_CRYPT], 1, [Use included des included with pppd]))

#
# If OpenSSL doesn't support DES, then use the one from libcrypt (glibc dropped support for this in 2.27).
AS_IF([test "${ac_cv_openssl_des}" = "no" ], [
    AC_CHECK_LIB([crypt], [encrypt],
        [LIBS="$LIBS -lcrypt"],
        [AC_MSG_ERROR([OpenSSL not found or does not support DES, and libcrypt also doesn't support encrypt])]
    )
])

#
# With libsrp support
AX_CHECK_SRP

#
# With libatm support
AX_CHECK_ATM

#
# With libpam support
AX_CHECK_PAM(AC_DEFINE([USE_PAM], 1, ["Support for Pluggable Authentication Modules"]))
AM_CONDITIONAL(WITH_PAM, test "x${with_pam}" = "xyes")

#
# With libpcap support, activate pppd on network activity
AX_CHECK_PCAP(
    [AC_DEFINE([PPP_FILTER], 1, ["Have packet activity filter support"])])
# AS_IF([test "x${build_sunos}" = "xyes" && test "x${with_pcap}" != "xno"],
#    [AC_MSG_ERROR([Filter is not supported on SunOS])])

#
# Some contributions require GTK/GLIB
AC_ARG_WITH([gtk], AS_HELP_STRING([--with-gtk], [Build contributions with the GTK+ interface]))
if test "x${with_gtk}" = "xyes"; then
    PKG_CHECK_MODULES([GTK], [gtk+-2.0])
    PKG_CHECK_MODULES([GLIB], [glib-2.0])
fi
AM_CONDITIONAL([WITH_GTK], test "x${with_gtk}" = "xyes")


AC_CONFIG_FILES([
    Makefile
    chat/Makefile
    contrib/Makefile
    contrib/pppgetpass/Makefile
    common/Makefile
    include/Makefile
    modules/Makefile
    pppd/Makefile
    pppd/pppd.pc
    pppd/plugins/Makefile
    pppd/plugins/pppoe/Makefile
    pppd/plugins/pppoatm/Makefile
    pppd/plugins/pppol2tp/Makefile
    pppd/plugins/radius/Makefile
    pppdump/Makefile
    pppstats/Makefile
    scripts/Makefile
    ])
AC_OUTPUT


AS_IF([test "x${build_sunos}" = "xyes" ], [[
    echo "Setting up SunOS kernel module(s)"
    mkmkf() {
        rm -f $2
        if [ -f $1 ]; then
            echo "  $2 <= $1"
            sed -e "s,@DESTDIR@,$prefix,g" \
                -e "s,@SYSCONF@,$sysconfdir,g" \
                -e "s,@CC@,$CC,g" \
                -e "s|@CFLAGS@|$CFLAGS|g" $1 > $2
        fi
    }

    release=`uname -r`
    karch=`/usr/bin/isainfo -k`
    makext="sol2"
    archvariant=

    case "$karch" in
        amd64)
            archvariant='-64x'
            ;;
        sparcv9)
            archvariant='-64'
            ;;
        *)
            ;;
    esac

    usegcc=$CC
    if [ -x /opt/SUNWspro/bin/cc -a "$usegcc" != gcc ] &&
       /opt/SUNWspro/bin/cc -flags >/dev/null 2>&1; then
      if [ "$archvariant" = "-64x" ]; then
        ( cd /tmp; echo "int x;" > ppp$$.c
	  /opt/SUNWspro/bin/cc -c -errwarn -xchip=opteron -m64 ppp$$.c >/dev/null 2>&1 || (
	    echo "WorkShop C is unable to make 64 bit modules, and your $karch system needs"
	    echo "them.  Consider upgrading cc on this machine."
	    rm -f ppp$$.c
	    exit 1
	  ) || exit 1
	  rm -f ppp$$.c ppp$$.o
        ) || exit 1
      fi
    elif gcc --version >/dev/null 2>&1; then
      archvariant=gcc$archvariant
      compiletype=.gcc
      if [ "$archvariant" = "gcc-64" -o"$archvariant" = "gcc-64x" ]; then
        ( cd /tmp; touch ppp$$.c
	  gcc -c -m64 ppp$$.c >/dev/null 2>&1 || (
	    echo "gcc is unable to make 64 bit modules, and your $karch system needs them."
	    echo "Consider upgrading gcc on this machine, or switching to Sun WorkShop."
	    rm -f ppp$$.c
	    exit 1
	  ) || exit 1
	  rm -f ppp$$.c ppp$$.o
        ) || exit 1
      fi
    else
      echo "C compiler not found; hoping for the best."
    fi

    mkmkf solaris/Makedefs$compiletype Makedefs.com
    mkmkf solaris/Makefile.sol2$archvariant solaris/Makefile
]])

echo "
$PACKAGE_NAME version $PACKAGE_VERSION
    Prefix...............: $prefix
    Runtime Dir..........: $PPPD_RUNTIME_DIR
    Logfile Dir..........: $PPPD_LOGFILE_DIR
    Plugin Dir...........: $PPPD_PLUGIN_DIR
    With OpenSSL.........: ${with_openssl:-yes}
    With libatm..........: ${with_atm:-no}
    With libpam..........: ${with_pam:-no}
    With libpcap.........: ${with_pcap:-no}
    With libsrp..........: ${with_srp:-no}
    C Compiler...........: $CC $CFLAGS
    Linker...............: $LD $LDFLAGS $LIBS

Features enabled
    Microsoft Extensions.: ${enable_microsoft_extensions:-yes}
    Multilink............: ${enable_multilink:-no}
    Plugins..............: ${enable_plugins:-yes}
    CBCP.................: ${enable_cbcp:-no}
    IPXCP................: ${enable_ipxcp:-no}
    EAP-TLS..............: ${enable_eaptls:-yes}
"
