#! /bin/sh
aclocal -I acinclude && autoheader && automake --add-missing --copy && autoconf
