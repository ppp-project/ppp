#!/bin/sh

# This script modifies the kernel sources in /sys to install
# ppp-2.3.  It is intended to be run in the ppp-2.3 directory.
#
# Paul Mackerras	11-Dec-95

ARCH=$(uname -m)
CONF=$(uname -v | sed 's/.*(\(.*\)).*/\1/')
SYS=/sys
ARCHDIR=$SYS/arch/$ARCH
CFILE=$ARCHDIR/conf/$CONF
SRC=netbsd-1.1
DOCONF=
DOMAKE=

# Work out whether to use config or config.old
if grep -q '^[ 	]*timezone' $CFILE; then
  CONFIG=config.old
else
  CONFIG=config
fi

# Copy new versions of files into /sys/net

for f in include/net/if_ppp.h include/net/ppp-comp.h include/net/ppp_defs.h \
         $SRC/bsd-comp.c $SRC/ppp-deflate.c \
	 $SRC/if_ppp.c $SRC/if_pppvar.h $SRC/ppp_tty.c \
	 $SRC/slcompress.c $SRC/slcompress.h common/zlib.c common/zlib.h; do
  dest=$SYS/net/$(basename $f)
  if [ -f $dest ]; then
    if ! diff -qBI '[ 	]\$[IN][de].*:.*\$' $f $dest >/dev/null; then
      echo "Copying $f to $dest"
      mv -f $dest $dest.orig && echo " (old version saved in $dest.orig)"
      cp $f $dest
      DOMAKE=yes
    fi
  else
    echo "Copying $f to $dest"
    cp $f $dest
    DOMAKE=yes
  fi
done

OLDFILES=files.oldconf
NEWFILES=files
OLDCONFIG=config.old
NEWCONFIG=config

if [ -f $SYS/conf/$OLDFILES ]; then
  if ! grep -q ppp-deflate $SYS/conf/$OLDFILES; then
    echo "Patching $SYS/conf/$OLDFILES"
    patch -N $SYS/conf/$OLDFILES <$SRC/files.oldconf.patch
    if [ $CONFIG = $OLDCONFIG ]; then
      DOCONF=yes
    fi
  fi
fi
if [ -f $SYS/conf/$NEWFILES ]; then
  if ! grep -q ppp-deflate $SYS/conf/$NEWFILES; then
    echo "Patching $SYS/conf/$NEWFILES"
    patch -N $SYS/conf/$NEWFILES <$SRC/files.patch
    if [ $CONFIG = $NEWCONFIG ]; then
      DOCONF=yes
    fi
  fi
fi

# Tell the user to add a pseudo-device line to the configuration file
# and remake the kernel, if necessary.

if [ -f $CFILE ]; then
  if ! grep -q '^[ 	]*pseudo-device[ 	][ 	]*ppp' $CFILE; then
    echo
    echo "The currently-running kernel was built from configuration file"
    echo "$CFILE, which does not include PPP."
    echo "You need either to add a line like 'pseudo-device ppp 2' to"
    echo "this file, or use another configuration file which includes"
    echo "a line like this."
    DOCONF=yes
  fi
fi

if [ $DOCONF ]; then
  echo
  echo "You need to configure and build a new kernel."
  echo "The procedure for doing this involves the following commands:"
  echo "(\"$CONF\" may be replaced by the name of another config file.)"
  echo
  echo "	cd $ARCHDIR/conf"
  echo "	/usr/sbin/$CONFIG $CONF"
  echo "	cd ../compile/$CONF"
  echo "	make depend"
  DOMAKE=yes
elif [ $DOMAKE ]; then
  echo
  echo "You need to build a new kernel."
  echo "The procedure for doing this involves the following commands:"
  echo
  echo "	cd $ARCHDIR/compile/$CONF"
fi
if [ $DOMAKE ]; then
  echo "	make"
  echo
  echo "Then copy the new kernel ($ARCHDIR/compile/$CONF/netbsd)"
  echo "to /netbsd and reboot.  (Keep a copy of the old /netbsd,"
  echo "just in case.)"
fi
