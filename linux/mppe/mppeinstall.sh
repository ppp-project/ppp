#!/bin/sh
#
# A quickie script to install MPPE into the 2.2.19+ or 2.4.18+ kernel.
# Does very little error checking!!!
#

mppe_files="sha1.[ch] arcfour.[ch] ppp_mppe_compress.c"

if [ -z "$1" -o ! -d "$1" ]; then
    echo "Usage: $0 <linux-source-dir>" >&2
    exit 1
fi

# strip any trailing /
set -- ${1%/}
# strip leading /path/to/linux- and trailing -release
ver=`echo "${1##*/}" | sed -e 's/linux-//' -e 's/-.*//'`
if ! expr "$ver" : 2.[24] >/dev/null ; then
    echo "$0: Unable to determine kernel version ($ver)" >&2
    exit 1
fi

# build patch files list
patchdir=`pwd`
patchfiles=
if expr $ver : 2.2 >/dev/null ; then
    patchfiles=$patchdir/linux-2.2.*.patch
elif expr $ver : 2.4 >/dev/null ; then
    patchfiles=`echo $patchdir/linux-2.4.18-{include,make}.patch`
    # need to differentiate a bit
    typeset -i rel=${ver##*.}
    if [ $rel -eq 18 ]; then
	patchfiles="$patchfiles $patchdir/linux-2.4.18-pad.patch"
    elif [ $rel -gt 18 ]; then
	patchfiles="$patchfiles $patchdir/linux-2.4.19-pad.patch"
    else
	echo "$0: unable to determine kernel version" >&2
	exit 1
    fi
fi

echo "Detected kernel version $ver"
echo "I will now patch the kernel in directory $1"
echo -n "Press ret to continue, CTRL-C to exit: "
read

pushd "$1" >/dev/null
for patch in $patchfiles; do
    patch -p1 < $patch
done

for file in $mppe_files; do
    cp -v $patchdir/$file drivers/net
done

popd >/dev/null

exit 0
