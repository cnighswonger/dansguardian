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

#ifndef __HPP_SYSLOG_REPL
#define __HPP_SYSLOG_REPL 1

#define LOG_DEBUG 0
#define LOG_INFO 1
#define LOG_NOTICE 2
#define LOG_WARNING 3
#define LOG_ERR 4
#define LOG_CRIT 5
#define LOG_ALERT 6
#define LOG_EMERG 7

#define LOG_USER 0
#define LOG_LOCAL0 1
#define LOG_LOCAL1 2
#define LOG_LOCAL2 3
#define LOG_LOCAL3 4
#define LOG_LOCAL4 5
#define LOG_LOCAL5 6
#define LOG_LOCAL6 7
#define LOG_LOCAL7 8

#define LOG_PID 1
#define LOG_CONS 2
#define LOG_NDELAY 4
#define LOG_ODELAY 8
#define LOG_NOWAIT 16

void openlog(const char *ident, int logopt, int facility);
void syslog(int priority, const char* format, ...);

#endif
