#!/bin/sh
#
# A quickie script to install MPPE into the 2.2.20 kernel.
# Does no error checking!!!
#

mppe_files="sha1.[ch] arcfour.[ch] ppp_mppe.c"

[ $1 ] || exit 1
[ -d "$1" ] || exit 1

echo "I will now patch the kernel in directory $1"
echo -n "Press ret to continue, CTRL-C to exit: "
read

patchdir=`pwd`
pushd "$1" >/dev/null
for patch in $patchdir/linux*.patch; do
    patch -p1 < $patch
done

for file in $mppe_files; do
    cp $patchdir/$file drivers/net
done

popd >/dev/null

exit 0
