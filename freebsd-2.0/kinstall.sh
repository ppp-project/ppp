#!/bin/sh

# This script modifies the kernel sources in /sys to install
# ppp-2.3.  It is intended to be run in the ppp-2.3 directory.
#
# Paul Mackerras	17-Mar-95
#
# Modified to match the output of the uname command for FreeBSD 2.1.0
# and 2.1.5 (and perhaps later).
#
# John Lind (john@starfire.mn.org) 18-Nov-96

KPATH=$(uname -v | sed 's/.*://')
CONF=$(echo $KPATH | sed 's;.*compile/;;')
SYS=$(echo $KPATH | sed 's;/compile/.*$;;')
ARCHDIR=$SYS/i386
CFILE=$ARCHDIR/conf/$CONF
SRC=freebsd-2.0
DOCONF=
DOMAKE=
CONFIG=config

# Copy new versions of files into /sys/net

for f in include/net/if_ppp.h include/net/ppp-comp.h \
         $SRC/ppp_defs.h $SRC/bsd-comp.c $SRC/ppp-deflate.c \
	 $SRC/if_ppp.c $SRC/if_pppvar.h $SRC/ppp_tty.c \
	 $SRC/pppcompress.c $SRC/pppcompress.h common/zlib.c common/zlib.h; do
  dest=$SYS/net/$(basename $f)
  if [ -f $dest ]; then
    if ! cmp -s $f $dest; then
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

# Add extra stuff to /sys/conf/files

if [ -f $SYS/conf/files ]; then
  if ! grep -q ppp_tty $SYS/conf/files; then
    echo "Patching $SYS/conf/files"
    patch -p -N -d $SYS/conf <$SRC/files.patch
    DOCONF=yes
  elif ! grep -q ppp-deflate $SYS/conf/files; then
    echo "Patching $SYS/conf/files"
    patch -N $SYS/conf/$OLDFILES <$SRC/files-2.2.patch
    DOCONF=yes
  fi
fi

# Tell the user to add a pseudo-device line to the configuration file.

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
  echo "The procedure for doing this involves the following commands."
  echo "(\"$CONF\" may be replaced by the name of another config file.)"
  echo
  echo "	cd $ARCHDIR/conf"
  echo "	/usr/sbin/$CONFIG $CONF"
  echo "	cd ../../compile/$CONF"
  echo "	make depend"
  DOMAKE=yes
elif [ $DOMAKE ]; then
  echo "You need to build a new kernel."
  echo "The procedure for doing this involves the following commands."
  echo
  echo "	cd $KPATH"
fi
if [ $DOMAKE ]; then
  echo "	make"
  echo
  echo "Then copy the new kernel ($KPATH/kernel) to /"
  echo "and reboot.  (Keep a copy of the old /kernel, just in case.)"
fi
