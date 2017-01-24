#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif

#ifndef HAVE_LOCALTIME_R

#include <windows.h>
#include <ctime>

#include "localtime_r.h"

CRITICAL_SECTION localtime_r_section;

struct tm *localtime_r(const time_t *timep, struct tm *result)
{
	EnterCriticalSection(&localtime_r_section);
	(*result) = *(localtime(timep));
	LeaveCriticalSection(&localtime_r_section);
	return result;
}

#endif
