#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif

#ifndef HAVE_MKSTEMP

#include <cstring>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "mkstemp.h"

int mkstemp(char *t)
{
	_mktemp(t);
	return _open(t, _O_CREAT|_O_EXCL);
}

#endif
