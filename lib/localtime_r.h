#ifndef __H_LOCALTIME_R
#define __H_LOCALTIME_R

#ifndef HAVE_LOCALTIME_R
struct tm *localtime_r(const time_t *timep, struct tm *result);
#endif

#endif
