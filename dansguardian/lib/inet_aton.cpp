#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif

#ifndef HAVE_INET_ATON

#ifdef WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include "inet_aton.h"

int inet_aton(const char *cp, struct in_addr *inp)
{
	inp->s_addr = inet_addr(cp);
	if (inp->s_addr == INADDR_NONE)
		return 0;
	else
		return 1;
}

#endif
