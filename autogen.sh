#!/bin/sh
# autogen.sh - generates configure using the autotools

libtoolize --force --copy
#libtoolize14  --force --copy
aclocal-1.9 -I m4
autoheader
automake-1.9 --add-missing --copy --foreign
autoconf
rm -rf autom4te.cache
