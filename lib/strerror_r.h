#ifndef __H_STRERROR_R
#define __H_STRERROR_R

#ifndef HAVE_STRERROR_R
char *strerror_r(int errnum, char *buf, size_t bufflen);
#endif

#endif
