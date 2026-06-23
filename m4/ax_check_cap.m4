# SYNOPSIS
#
#   AX_CHECK_CAP([action-if-found[, action-if-not-found]])
#
# DESCRIPTION
#
#   Look for libcap in a number of default locations, or in a provided location
#   (via --with-libcap=). Sets
#       CAP_CFLAGS
#       CAP_LDFLAGS
#       CAP_LIBS
#
#   and calls ACTION-IF-FOUND or ACTION-IF-NOT-FOUND appropriately
#
# LICENSE
#
#   Copyright (c) 2025 PPP Project
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 1

AC_DEFUN([AX_CHECK_CAP], [
    AC_ARG_WITH([libcap],
        [AS_HELP_STRING([--with-libcap=yes|no|DIR],
            [With libcap (capabilities) support for fine-grained privilege management])])

    AS_CASE(["$with_libcap"],
        [ye|y], [with_libcap=yes],
        [n], [with_libcap=no])

    AS_IF([test "x$with_libcap" != "xno"], [
        AS_CASE(["$with_libcap"],
            [""|yes], [PKG_CHECK_MODULES([CAP], [libcap], [capdirs=],
                        [capdirs="/usr/local /usr/lib /usr"])],
            [capdirs="$with_libcap"])

        AS_IF([test -n "$capdirs"], [
            CAP_LIBS="-lcap"
            for capdir in $capdirs; do
                AC_MSG_CHECKING([for sys/capability.h in $capdir])
                if test -f "$capdir/include/sys/capability.h"; then
                    CAP_CFLAGS="-I$capdir/include"
                    CAP_LDFLAGS="-L$capdir/lib"
                    AC_MSG_RESULT([yes])
                    break
                else
                    AC_MSG_RESULT([no])
                fi
            done
        ])

        # try the preprocessor and linker with our new flags,
        # being careful not to pollute the global LIBS, LDFLAGS, and CPPFLAGS

        AC_MSG_CHECKING([if compiling and linking against libcap works])

        save_LIBS="$LIBS"
        save_LDFLAGS="$LDFLAGS"
        save_CPPFLAGS="$CPPFLAGS"
        LDFLAGS="$LDFLAGS $CAP_LDFLAGS"
        LIBS="$CAP_LIBS $LIBS"
        CPPFLAGS="$CAP_CFLAGS $CPPFLAGS"
        AC_LINK_IFELSE(
            [AC_LANG_PROGRAM(
                [#include <sys/capability.h>],
                [cap_t cap = cap_get_pid(0);])],
            [
                AC_MSG_RESULT([yes])
                with_libcap=yes
                $1
            ], [
                AC_MSG_RESULT([no])
                with_libcap="no"
                $2
            ])
        CPPFLAGS="$save_CPPFLAGS"
        LDFLAGS="$save_LDFLAGS"
        LIBS="$save_LIBS"

        AC_SUBST([CAP_CFLAGS])
        AC_SUBST([CAP_LIBS])
        AC_SUBST([CAP_LDFLAGS])
    ])
    AM_CONDITIONAL(WITH_LIBCAP, test "x${with_libcap}" = "xyes")
])
