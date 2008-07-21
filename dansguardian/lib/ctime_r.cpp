#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif

#ifndef HAVE_CTIME_R

#include <windows.h>
#include <ctime>
#include "ctime_r.h"

// Sadly, MinGW doesn't provide ctime_s in its headers or libs, so we have to use
// the old, thread-unsafe ctime() and a critical section.

CRITICAL_SECTION ctime_r_section;

char *ctime_r(const time_t *timep, char *buf)
{
	EnterCriticalSection(&ctime_r_section);
	char *result = ctime(timep);
	strncpy(buf, result, 25);
	buf[25] = '\0';
	LeaveCriticalSection(&ctime_r_section);
	return buf;
}

#endif
