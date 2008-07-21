//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.
//For support go to http://groups.yahoo.com/group/dansguardian
// Original author Philip Allison <philip.allison@smoothwall.net>

//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

// Provide a replacement syslog-style facility
// for platforms which lack it, by logging entries
// directly to file.


// INCLUDES

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif

#include <sys/types.h>
#include <ctime>
#ifndef HAVE_CTIME_R
#include "ctime_r.h"
#endif
#include <cstdarg>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <fstream>

#include "syslog.h"

#ifdef WIN32
#include <process.h>
#else
#include <sys/types.h>
#include <unistd.h>
#endif


// GLOBALS

// Output stream to replace syslog
std::ofstream syslogstream;
// Whether it's been opened
bool syslogstream_opened = false;
// Options given to openlog
int openlog_logopt = LOG_NDELAY;
const char *openlog_ident = NULL;


// IMPLEMENTATION

void openlog(const char *ident, int logopt, int facility)
{
	openlog_logopt = logopt;
	openlog_ident = ident;
	if ((logopt & LOG_NDELAY) || !(logopt & LOG_ODELAY))
	{
		syslogstream.close();
		syslogstream.open(__LOGLOCATION "syslog.log");
		syslogstream_opened = true;
	}
	if (logopt & LOG_PID)
	{
	}
}

void syslog(int priority, const char* format, ...)
{
	if (!syslogstream_opened)
	{
		openlog_logopt |= LOG_ODELAY;
		openlog(openlog_ident, openlog_logopt, 0);
	}

	char s[1024];
	va_list vl;
	va_start(vl, format);
	vsnprintf(s, 1024, format, vl);
	va_end(vl);

	std::ostringstream preamble;
	time_t now = time(NULL);
	char cbuf[26];
	ctime_r(&now, cbuf);
	preamble << cbuf;
	if (openlog_ident)
		preamble << openlog_ident;

	if (openlog_logopt & LOG_PID)
	{
#ifdef WIN32
		int openlog_pid = _getpid();
#else
		pid_t openlog_pid = getpid();
#endif
		preamble << '[' << openlog_pid << ']';
	}

	preamble << ": ";

	syslogstream << preamble.str() << s << std::endl;
	if (openlog_logopt & LOG_CONS)
		std::cout << preamble.str() << s << std::endl;
}
