#!/bin/sh
#
#  kinstall.sh -- install updated kernel PPP driver in Linux kernel source
#     Michael Callahan callahan@maths.ox.ac.uk 17 May 1995
#
#  This script is complicated because we want to avoid installing a driver
#  in a kernel if it won't work in that kernel.  This means two things:
#    1) we check the version of the kernel and refuse to install if the
#       kernel is too old;
#    2) we check that the files already in the kernel aren't more recent
#       than the one we're about to install.
#  If either 1) or 2) occurs then we exit with an error message and don't
#  touch anything.
#
#  In addition, we have to edit the Makefile in the drivers/net
#  directory to add support for the ppp-comp compression option.
#
#  Finally, we have to check that certain include file stubs in
#  /usr/include/net exist, or else pppd won't compile.  Phew!

LINUXSRC=/usr/src/linux

if [ $# -gt 1 ]; then
   echo usage: $0 [linux-source-directory]
   exit 1
fi

if [ $# -eq 1 ]; then
   LINUXSRC=$1
fi

#
#  Make sure we can find the kernel source

LINUXMK=$LINUXSRC/Makefile

if [ ! -r $LINUXMK -o ! -d $LINUXSRC/drivers ]; then
  echo There appears to be no kernel source distribution in $LINUXSRC.
  echo Give the top-level kernel source directory as the argument to
  echo this script.
  echo usage: $0 [linux-source-directory]
  exit 1
fi

#
#  Check that the kernel source Makefile includes the 
#    VERSION, PATCHLEVEL, SUBLEVEL version-numbering scheme
#    introduced in 1.0.1
if [ `egrep '^VERSION|^PATCHLEVEL|^SUBLEVEL' $LINUXMK | wc -l` -ne 3 ]; then
  echo You appear to have a very old kernel. You must upgrade.
  echo It is recommended that you upgrade to the most recent 1.2.X kernel.
  exit 1
fi

#
#  Set the VERSION, PATCHLEVEL, SUBLEVEL variables
VERSION=`egrep '^VERSION' $LINUXMK | sed 's/[^0-9]//g'`
PATCHLEVEL=`egrep '^PATCHLEVEL' $LINUXMK | sed 's/[^0-9]//g'`
SUBLEVEL=`egrep '^SUBLEVEL' $LINUXMK | sed 's/[^0-9]//g'`

KERNEL=$VERSION.$PATCHLEVEL.$SUBLEVEL

#
#  Pass judgement on the kernel version
if [ $VERSION -eq 1 ]; then
  if [ $PATCHLEVEL -eq 0 -o $PATCHLEVEL -eq 1 -a $SUBLEVEL -lt 14 ]; then
    echo You appear to be running $KERNEL. There is no support for
    echo kernels predating 1.1.14.  It is recommended that you upgrade
    echo to the most recent 1.2.X kernel.
    exit 1
  fi
  if [ $PATCHLEVEL -eq 1 ]; then
    echo You appear to be running $KERNEL. It is recommended that you
    echo upgrade to the most recent 1.2.X kernel.
    echo However, installation will proceed.
  fi
fi

echo
echo Installing into kernel version $KERNEL in $LINUXSRC
echo

#
# convenience function to exit if the last command failed

function bombiffailed () {
  STATUS=$?
  if [ $STATUS -ne 0 ]; then
    echo "=== kinstall.sh exiting with failure status $STATUS"
    exit $STATUS
  fi
}

#
# convenience function to compare two files marked with ==FILEVERSION
# version numbers; returns success if $1 is newer than $2

function newer () {
  if [ -r $1 ] && f1rev=`fgrep "==FILEVERSION " $1 | sed 's/[^0-9]//g'`; then
    if [ -r $2 ] && f2rev=`fgrep "==FILEVERSION " $2 | sed 's/[^0-9]//g'`; then
      if [ "$f1rev" != "" ]; then
        # return true if f2rev is empty or f1rev => f2rev
        [ "$f2rev" = "" ] || [ $f1rev -ge $f2rev ]
      else
        # f1rev is empty, so false
        false
      fi
    else
      true  # no FILEVERSION in $2, so $1 is newer
    fi
  else
    false  # no FILEVERSION in $1, so not newer
  fi
}

#
#  Change the USE_SKB_PROTOCOL for correct operation on 1.3.x
function update_ppp () {
  mv $LINUXSRC/drivers/net/ppp.c $LINUXSRC/drivers/net/ppp.c.in
  if [ "$VERSION.$PATCHLEVEL" = "1.3" ]; then
    sed 's/#define USE_SKB_PROTOCOL 0/#define USE_SKB_PROTOCOL 1/' <$LINUXSRC/drivers/net/ppp.c.in >$LINUXSRC/drivers/net/ppp.c
  else
    sed 's/#define USE_SKB_PROTOCOL 1/#define USE_SKB_PROTOCOL 0/' <$LINUXSRC/drivers/net/ppp.c.in >$LINUXSRC/drivers/net/ppp.c
  fi
  rm $LINUXSRC/drivers/net/ppp.c.in
}

#
#  Install the files.

function installfile () {
  BASE=`basename $1`
  if newer $1 $BASE; then
    echo $1 is newer than $BASE, skipping
    return 0
  fi
  BACKUP=`echo $1 | sed 's/.c$/.old.c/;s/.h$/.old.h/'`
  if [ -f $1 -a $BACKUP != $1 ]; then
    echo Saving old $1 as `basename $BACKUP`
    mv $1 $BACKUP
    bombiffailed
  fi
  echo Installing new $1
  cp $BASE $1
  bombiffailed
  touch $1
  bombiffailed
  if [ "$2" = "yes" ]; then
    update_ppp
  fi
}

if [ -f $LINUXSRC/drivers/net/ppp.h ]; then
  echo Moving old $LINUXSRC/drivers/net/ppp.h file out of the way
  mv $LINUXSRC/drivers/net/ppp.h $LINUXSRC/drivers/net/ppp.old.h
  bombiffailed
fi

for FILE in $LINUXSRC/drivers/net/bsd_comp.c \
            $LINUXSRC/include/linux/if_ppp.h \
            $LINUXSRC/include/linux/if_pppvar.h \
            $LINUXSRC/include/linux/ppp-comp.h \
            $LINUXSRC/include/linux/ppp_defs.h
  do
  installfile $FILE no
done

installfile $LINUXSRC/drivers/net/ppp.c yes

for FILE in if.h if_arp.h route.h
  do
  if [ ! -f $LINUXSRC/include/linux/$FILE ]; then
    echo Installing new $1
    cp $FILE $LINUXSRC/include/linux/$FILE
    bombiffailed
    touch $LINUXSRC/include/linux/$FILE
    bombiffailed
  fi
done

echo -n 'Adding BSD compression module to drivers makefile...'
NETMK=$LINUXSRC/drivers/net/Makefile
fgrep bsd_comp.o $NETMK >/dev/null
if [ ! "$?" = "0" ]; then
   echo -n '.'
   rm -f $NETMK.orig $NETMK.rej
   if [ "$VERSION.$PATCHLEVEL" = "1.2" ]; then
      (cd $LINUXSRC; patch -p1 -f -F30 -s) <patch-1.2
      if [ ! "$?" = "0" ]; then
         touch $NETMK.rej
      fi
   else
      if [ "$VERSION.$PATCHLEVEL" = "1.3" ]; then
         (cd $LINUXSRC; patch -p1 -f -F30 -s) <patch-1.3
         if [ ! "$?" = "0" ]; then
            touch $NETMK.rej
         fi
      else
         touch $NETMK.rej
      fi
   fi
#
   if [ -e $NETMK.rej ]; then
      rm -f $NETMK.rej
      if [ -e $NETMK.orig ]; then
         mv $NETMK.orig $NETMK
      fi
      sed 's/ppp.o$/ppp.o bsd_comp.o/g' <$NETMK >$NETMK.temp
      bombiffailed
      echo -n '.'
      mv $NETMK $NETMK.orig
      bombiffailed
      echo -n '.'
      mv $NETMK.temp $NETMK
      bombiffailed
   fi
#
   if [ -e $NETMK.orig ]; then
      mv $NETMK.orig $NETMK.old
   fi
else
   echo -n '(already there--skipping)'
fi
echo

#
# install header stub files in /usr/include/net

for FILE in if_ppp.h \
            if_pppvar.h \
            ppp-comp.h \
	    if.h \
            if_arp.h \
	    route.h \
            ppp_defs.h
  do
  if [ ! -f /usr/include/net/$FILE ]; then
    echo Installing stub include file in /usr/include/net/$FILE
    echo "#include <linux/$FILE>" > /usr/include/net/$FILE
    bombiffailed
    chown 0:0 /usr/include/net/$FILE
    bombiffailed
    chmod 444 /usr/include/net/$FILE
    bombiffailed
    touch /usr/include/net/$FILE
    bombiffailed
  fi
done

for FILE in ip.h \
	    tcp.h
  do
  if [ ! -f /usr/include/netinet/$FILE ]; then
    echo Installing stub include file in /usr/include/netinet/$FILE
    if [ ! -f $LINUXSRC/include/linux/$FILE ]; then
      echo "#include \"$LINUXSRC/net/inet/$FILE\"" >/usr/include/netinet/$FILE
    else
      echo "#include <linux/$FILE>" > /usr/include/netinet/$FILE
    fi
    chown 0:0 /usr/include/netinet/$FILE
    bombiffailed
    chmod 444 /usr/include/netinet/$FILE
    bombiffailed
    touch /usr/include/netinet/$FILE
    bombiffailed
  fi
done

echo "Kernel driver files installation done."
exit 0
