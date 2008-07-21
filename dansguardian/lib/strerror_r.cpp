#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif

#ifndef HAVE_STRERROR_R

#include <windows.h>
#include <cstring>

#include "strerror_r.h"

CRITICAL_SECTION strerror_r_section;

char *strerror_r(int errnum, char *buf, size_t bufflen)
{
	EnterCriticalSection(&strerror_r_section);
	char *result = strerror(errnum);
	strncpy(buf, result, bufflen - 1);
	buf[bufflen - 1] = '\0';
	LeaveCriticalSection(&strerror_r_section);
	return buf;
}

#endif
