#ifndef __H_CTIME_R
#define __H_CTIME_R

#ifndef HAVE_CTIME_R
char *ctime_r(const time_t *timep, char *buf);
#endif

#endif
