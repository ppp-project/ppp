#!/bin/sh

# This script modifies the kernel sources in /usr/src/sys to install
# ppp-2.3.  It is intended to be run in the ppp-2.3 directory.
#
# This works for FreeBSD 2.2.8
# Most of the kernel files are already part of the kernel source
# but, this updates them for synchronous HDLC operation
#
# Paul Fulghum		19-Apr-99

KPATH=$(uname -v | sed 's/.*://')
CONF=$(echo $KPATH | sed 's;.*compile/;;')
SYS=$(echo $KPATH | sed 's;/compile/.*$;;')
ARCHDIR=$SYS/i386
CFILE=$ARCHDIR/conf/$CONF
SRC=freebsd-2.2.8
DOCONF=
DOMAKE=
CONFIG=config

# Patch files in /usr/src/sys/net

for f in if_ppp.h if_ppp.c ppp_tty.c ; do
  dest=$SYS/net/$f
  patch=$SRC/patch.$f
  if [ -f $dest ]; then
     echo -n "Patching $dest..."
     if patch -s -C -N $dest < $patch 2> /dev/null; then
	patch -s -N $dest < $patch
        echo "successful."
        DOMAKE=yes
     else
        if patch -s -C -R $dest < $patch 2> /dev/null; then
           echo "already applied."
        else
           echo "failed (incorrect version or already applied)."
        fi
     fi
  else
    echo "Warning, file $dest not found"
  fi
done

for f in if_ppp.h ; do
  dest=/usr/include/net/$f
  patch=$SRC/patch.$f
  if [ -f $dest ]; then
     echo -n "Patching $dest..."
     if patch -s -C -N $dest < $patch 2> /dev/null; then
	patch -s -N $dest < $patch
        echo "successful."
        DOMAKE=yes
     else
        if patch -s -C -R $dest < $patch 2> /dev/null; then
           echo "already applied."
        else
           echo "failed (incorrect version or already applied)."
        fi
     fi
  else
    echo "Warning, file $dest not found"
  fi
done

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
