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
  echo It is recommended that you upgrade to the most recent 2.0.x kernel.
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
if [ $VERSION -lt 2 ]; then
    echo You appear to be running $KERNEL. There is no support for
    echo kernels predating 2.0.0.  It is recommended that you upgrade
    echo to the most recent 2.0.x kernel.
    exit 1
fi

#
# convenience function to exit if the last command failed

bombiffailed () {
  STATUS=$?
  if [ $STATUS -ne 0 ]; then
    echo "=== kinstall.sh exiting with failure status $STATUS"
    exit $STATUS
  fi
}

#
# convenience function to compare two files marked with ==FILEVERSION
# version numbers; returns success if $1 is not older than $2

newer () {
  file1=$1
  file2=$2
  pat='==FILEVERSION[ \t]+[0-9]+[ \t]*=='

  # Find the revision in the kernel
  f1rev=""
  if [ -r $file1 ]; then
    f1rev=`egrep "$pat" $file1 | head -1 | sed 's/[^0-9]//g'`
  fi

  # Find the revision of the local file
  f2rev=""
  if [ -r $file2 ]; then
    f2rev=`egrep "$pat" $file2 | head -1 | sed 's/[^0-9]//g'`
  fi

  # Make the strings the same length to avoid comparison problems
  f1rev=`echo "0000000000"$f1rev | tail -c 10`
  f2rev=`echo "0000000000"$f2rev | tail -c 10`

  # Test the order of the two revisions
  if [ $f1rev -ge $f2rev ]; then
    true ; return
  fi

  false ; return
}

#
#  Install the files.

installfile () {
  BASE=`basename $1`
  if [ ! -e $BASE ]; then
    if [ -e ../include/linux/$BASE ]; then
      BASE=../include/linux/$BASE
    else
      echo Could not find source file $BASE !
      false ; return
    fi
  fi
  if newer $1 $BASE; then
    echo $1 is not older than $BASE, skipping
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
}

#
# Check for the root user
test_root() {
  my_uid=`id -u`
  my_name=`id -u -n`
  if [ $my_uid -ne 0 ]; then
    echo
    echo "********************************************************************"
    echo "Hello, $my_name. Since you are not running as the root user, it"
    echo "is possible that this script will fail to install the needed files."
    echo "If this happens then please use the root account and re-execute the"
    echo "'make kernel' command.  (This script is paused for 10 seconds.)"
    echo "********************************************************************"
    echo
    sleep 10s
  fi
}

test_root

echo
echo "Notice to the user:"
echo
echo "It is perfectly legal for this script to run without making any changes"
echo "to your system. This means that the system currently contains the"
echo "necessary changes to support this package. Please do not attempt to"
echo "force this script to replace any file nor make any patch. If you do so"
echo "then it is probable that you are actually putting older, buggier, code"
echo "over the newer, fixed, code. Thank you."
echo
echo Installing into kernel version $KERNEL in $LINUXSRC
echo

if [ -f $LINUXSRC/drivers/net/ppp.h ]; then
  echo Moving old $LINUXSRC/drivers/net/ppp.h file out of the way
  mv $LINUXSRC/drivers/net/ppp.h $LINUXSRC/drivers/net/ppp.old.h
  bombiffailed
fi

for FILE in $LINUXSRC/drivers/net/bsd_comp.c \
	    $LINUXSRC/drivers/net/ppp_deflate.c \
	    $LINUXSRC/drivers/net/zlib.c \
	    $LINUXSRC/drivers/net/zlib.h \
            $LINUXSRC/include/linux/if_ppp.h \
            $LINUXSRC/include/linux/if_pppvar.h \
            $LINUXSRC/include/linux/ppp-comp.h \
            $LINUXSRC/include/linux/ppp_defs.h
  do
  installfile $FILE no
done

installfile $LINUXSRC/drivers/net/ppp.c yes

echo -n 'Adding BSD compression module to drivers makefile...'
NETMK=$LINUXSRC/drivers/net/Makefile
fgrep bsd_comp.o $NETMK >/dev/null
if [ ! "$?" = "0" ]; then
   if [ -f $NETMK.orig ]; then
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
else
   echo -n '(already there--skipping)'
fi
echo
echo -n 'Adding Deflate compression module to drivers makefile...'
NETMK=$LINUXSRC/drivers/net/Makefile
fgrep ppp_deflate.o $NETMK >/dev/null
if [ ! "$?" = "0" ]; then
   echo -n '.'
   sed 's/bsd_comp.o$/bsd_comp.o ppp_deflate.o/g' <$NETMK >$NETMK.temp
   bombiffailed
   echo -n '.'
   mv $NETMK $NETMK.orig
   bombiffailed
   echo -n '.'
   mv $NETMK.temp $NETMK
   bombiffailed
else
   echo -n '(already there--skipping)'
fi
echo

# #
# # install header stub files in /usr/include/net

# for FILE in if_ppp.h \
#             if_pppvar.h \
#             ppp-comp.h \
# 	    if.h \
#             ppp_defs.h
#   do
#   if [ ! -f /usr/include/net/$FILE ]; then
#     echo Installing stub include file in /usr/include/net/$FILE
#     echo "#include <linux/$FILE>" > /usr/include/net/$FILE
#     bombiffailed
#     chown 0:0 /usr/include/net/$FILE
#     bombiffailed
#     chmod 444 /usr/include/net/$FILE
#     bombiffailed
#     touch /usr/include/net/$FILE
#     bombiffailed
#   fi
# done

echo "Kernel driver files installation done."

exit 0
