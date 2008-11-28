//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.
//Written by Daniel Barron (daniel@jadeb//.com).
//For support go to http://groups.yahoo.com/group/dansguardian

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


// INCLUDES

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif

#include <csignal>
#include <ctime>
#include <sys/stat.h>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <sys/time.h>
#include <istream>
#include <map>
#include <sys/types.h>
#include <pthread.h>
#include <queue>
#include <memory>

#ifdef WIN32
#include "../lib/syslog.h"
#else
#include <syslog.h>
#endif

#ifndef HAVE_STRERROR_R
#include "../lib/strerror_r.h"
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifndef WIN32
#include <sys/select.h>
#include <sys/wait.h>
#else
#include <winsock2.h>
#endif

#ifdef ENABLE_SEGV_BACKTRACE
#include <execinfo.h>
#endif

#include "FatController.hpp"
#include "ConnectionHandler.hpp"
#include "DynamicURLList.hpp"
#include "DynamicIPList.hpp"
#include "String.hpp"
#include "SocketArray.hpp"
#include "SysV.hpp"


// GLOBALS

// these are used in signal handlers - "volatile" indicates they can change at
// any time, and therefore value reading on them does not get optimised. since
// the values can get altered by outside influences, this is useful.
static volatile bool ttg = false;
static volatile bool gentlereload = false;
volatile bool reloadconfig = false;

extern OptionContainer o;
extern bool is_daemonised;

pthread_t *childrenids;  // so when one exits we know who
int *childrenstates;  // so we know what they're up to
int failurecount;
int numchildren;
int serversocketcount;
SocketArray serversockets;  // the sockets we will listen on for connections

// Condition & mutex for accepting new client connections in child threads
extern pthread_cond_t connevent;
extern pthread_mutex_t connmutex;
// Queue of recently accepted client connections
std::queue<Socket*> connqueue;

// Similar for logger
extern pthread_cond_t logevent;
extern pthread_mutex_t logmutex;
std::queue<logentry*> logqueue;

// Mutexes for accessing the URL and client IP caches
extern pthread_mutex_t urlcachemutex;
extern pthread_mutex_t ipcachemutex;

// Condition variable for waking up the IP stats thread before its 3 minute interval is up
extern pthread_cond_t ipcacheevent;

DynamicIPList *ipcache = NULL;
DynamicURLList urlcache;


// DECLARATIONS

// Signal handlers
#ifndef WIN32
extern "C"
{
	void sig_chld(int signo);
	void sig_term(int signo);  // This is so we can kill our children
	void sig_hup(int signo);  // This is so we know if we should re-read our config.
	void sig_usr1(int signo);  // This is so we know if we should re-read our config but not kill current connections
#ifdef ENABLE_SEGV_BACKTRACE
	void sig_segv(int signo); // Generate a backtrace on segfault
#endif
}
#endif

#ifndef WIN32
// fork off into background
bool daemonise();
#endif

// create specified amount of child processes
int prefork(int num);

// child thread main loop - sits waiting for incoming connections & processes them
void* handle_connections(void *arg);

// add known info about a child to our info lists
void addchild(int pos, pthread_t child_pid);
// find an empty slot in our child info lists
int getchildslot();
// cull up to this number of non-busy children
void cullchildren(int num);
// clean up any dead child processes
void mopup_afterkids();

#ifndef WIN32
// tidy up resources for a brand new child process (uninstall signal handlers, delete copies of unnecessary data, etc.)
void tidyup_forchild();
#endif


// IMPLEMENTATION

#ifndef WIN32
// signal handlers
extern "C"
{	// The kernel knows nothing of objects so
	// we have to have a lump of c
	void sig_term(int signo)
	{
		ttg = true;  // its time to go
	}
	void sig_hup(int signo)
	{
		reloadconfig = true;
#ifdef DGDEBUG
		std::cout << "HUP received." << std::endl;
#endif
	}
	void sig_usr1(int signo)
	{
		gentlereload = true;
#ifdef DGDEBUG
		std::cout << "USR1 received." << std::endl;
#endif
	}
#ifdef ENABLE_SEGV_BACKTRACE
	void sig_segv(int signo)
	{
#ifdef DGDEBUG
		std::cout << "SEGV received." << std::endl;
#endif
		// Generate backtrace
		void *addresses[10];
		char **strings;
		int c = backtrace(addresses, 10);
		strings = backtrace_symbols(addresses,c);
		printf("backtrace returned: %d\n", c);
		for (int i = 0; i < c; i++) {
			syslog(LOG_ERR, "%d: %zX ", i, (size_t)addresses[i]);
			syslog(LOG_ERR, "%s", strings[i]);
		}
		// Kill off the current process
		raise(SIGTERM);
	}
#endif
}
#endif

#ifndef WIN32
// Fork ourselves off into the background
bool daemonise()
{

	if (o.no_daemon) {
		return true;
	}
#ifdef DGDEBUG
	return true;  // if debug mode is enabled we don't want to detach
#endif

	if (is_daemonised) {
		return true;  // we are already daemonised so this must be a
		// reload caused by a HUP
	}
	int nullfd = -1;
	if ((nullfd = open("/dev/null", O_WRONLY, 0)) == -1) {
		syslog(LOG_ERR, "%s", "Couldn't open /dev/null");
		return false;
	}

	pid_t pid;
	if ((pid = fork()) < 0) {
		return false;
	}
	else if (pid != 0) {
		if (nullfd != -1) {
			close(nullfd);
		}
		exit(0);  // parent goes bye-bye
	}
	// child continues
	dup2(nullfd, 0);  // stdin
	dup2(nullfd, 1);  // stdout
	dup2(nullfd, 2);  // stderr
	close(nullfd);

	setsid();  // become session leader
	chdir("/");  // change working directory
	umask(0);  // clear our file mode creation mask

	is_daemonised = true;

	return true;
}
#endif


// *
// *
// *  child process code
// *
// *

// prefork specified num of children and set them handling connections
int prefork(int num)
{
#ifdef DGDEBUG
	std::cout << "attempting to prefork: " << num << std::endl;
#endif
	pthread_t child_threadid;
	while (num--) {
		int rc = pthread_create(&child_threadid, NULL, &handle_connections, NULL);

		if (rc != 0) {
			char errstr[1024];
			syslog(LOG_ERR, "Unable to pthread_create() any more: %s", strerror_r(rc, errstr, 1024));
#ifdef DGDEBUG
			std::cout << "Unable to pthread_create() any more." << std::endl;
			std::cout << errstr << std::endl;
			std::cout << "numchildren:" << numchildren << std::endl;
#endif
			failurecount++;  // log the error/failure
			// A DoS attack on a server allocated
			// too many children in the conf will
			// kill the server.  But this is user
			// error.
#ifdef WIN32
			Sleep(1000);  // need to wait until we have a spare slot
#else
			sleep(1);  // need to wait until we have a spare slot
#endif
			num--;
			continue;  // Nothing doing, go back to listening
		} else {
			// add the child to an empty child slot
			addchild(getchildslot(), child_threadid);
#ifdef DGDEBUG
			std::cout << "Preforked parent added child to list" << std::endl;
#endif
		}
	}
	return 1;  // parent returning
}

#ifndef WIN32
// cleaning up for brand new child threads - only the parent needs the signal handlers installed, and so forth
void tidyup_forchild()
{
	// Block signals for child threads and let the parent thread handle them all
	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGUSR1);
	pthread_sigmask(SIG_BLOCK, &sigs, NULL);
}
#endif

// handle any connections received by this child (also tell parent we're ready each time we become idle)
void* handle_connections(void *arg)
{
	ConnectionHandler h;  // the class that handles the connections
	String ip;

#ifndef WIN32
	tidyup_forchild();
#endif

	// stay alive both for the maximum allowed age of child processes, and whilst we aren't supposed to be re-reading configuration
	while (!reloadconfig && !ttg) {
		pthread_mutex_lock(&connmutex);
		if (reloadconfig || ttg)
			break;
		while (connqueue.empty())
		{
			pthread_cond_wait(&connevent, &connmutex);
			if (reloadconfig || ttg)
				break;
		}
		if (reloadconfig || ttg)
		{
			pthread_mutex_unlock(&connmutex);
			break;
		}
		std::auto_ptr<Socket> peersock(connqueue.front());
		connqueue.pop();
		pthread_mutex_unlock(&connmutex);

		String peersockip (peersock->getPeerIP());

		// now check the connection is actually good
		if (peersock->getFD() < 0 || peersockip.length() < 7) {
			if (o.logconerror)
				syslog(LOG_INFO, "Error accepting. (Ignorable)");
			continue;
		}

		// deal with the connection
		h.handleConnection(*(peersock.get()), peersockip);
	}
#ifdef DGDEBUG
	if (reloadconfig)
		std::cout << "child been told to exit by hup" << std::endl;
#endif
	return NULL;
}

// *
// *
// * end of child process code
// *
// *


// *
// *
// * start of child process handling (minus prefork)
// *
// *

// look for any dead children, and clean them up
void mopup_afterkids()
{
	for (int i = 0; i < o.max_children; i++) {
		if (childrenstates[i] >= 0)
			pthread_join(childrenids[i], NULL);
	}
}

// get a free slot in our thread ID list, if there is one - return -1 if not
int getchildslot()
{
	int i;
	for (i = 0; i < o.max_children; i++) {
		if (childrenstates[i] < 0) {
			return i;
		}
	}
	return -1;
}

// add the given child, including FD & PID, to the given slot in our lists
void addchild(int pos, pthread_t child_pid)
{
	childrenids[pos] = child_pid;
	childrenstates[pos] = 4;  // busy waiting for init
	numchildren++;
}

// *
// *
// * end of child process handling code
// *
// *


// *
// *
// * logger and IP stats thread main loops
// *
// *

void *logger_loop(void *arg)
{
#ifdef DGDEBUG
	std::cout << "log thread started" << std::endl;
#endif
#ifndef WIN32
	tidyup_forchild();
#endif

#ifdef ENABLE_EMAIL
	// Email notification patch by J. Gauthier
	std::map<std::string, int> violation_map;
	std::map<std::string, int> timestamp_map;   
	std::map<std::string, std::string> vbody_map;

	int curv_tmp, stamp_tmp, byuser;
#endif
	
	std::ofstream* logfile = NULL;
	if (!o.log_syslog) {
		logfile = new std::ofstream(o.log_location.c_str(), std::ios::app);
		if (logfile->fail()) {
			syslog(LOG_ERR, "Error opening/creating log file.");
#ifdef DGDEBUG
			std::cout << "Error opening/creating log file: " << o.log_location << std::endl;
#endif
			delete logfile;
			// Turn off logging so in-memory queue doesn't
			// just become more and more full and never cleared
			o.ll = 0;
			return NULL;
		}
	}

	while (!ttg)
	{
		pthread_mutex_lock(&logmutex);
		if (ttg)
			break;
		while (logqueue.empty())
		{
			pthread_cond_wait(&logevent, &logmutex);
			if (ttg)
				break;
		}
		if (ttg)
		{
			pthread_mutex_unlock(&logmutex);
			break;
		}
		// TODO - clear out the log queue on exit
		logentry* l = logqueue.front();
		logqueue.pop();
		pthread_mutex_unlock(&logmutex);

		// Start building the log line

		if (l->port != 0 && l->port != 80) {
			// put port numbers of non-standard HTTP requests into the logged URL
			String newwhere(l->where);
			if (newwhere.after("://").contains("/")) {
				String proto, host, path;
				proto = newwhere.before("://");
				host = newwhere.after("://");
				path = host.after("/");
				host = host.before("/");
				newwhere = proto;
				newwhere += "://";
				newwhere += host;
				newwhere += ":";
				newwhere += String(l->port);
				newwhere += "/";
				newwhere += path;
				l->where = newwhere;
			} else {
				l->where += ":";
				l->where += String(l->port);
			}
		}

		// stamp log entries so they stand out/can be searched
		if (l->isnaughty) {
			l->what = "*DENIED* " + l->what;
		}
		else if (l->isexception && (o.log_exception_hits == 2)) {
			l->what = "*EXCEPTION* " + l->what;
		}
	   
		if (l->wasscanned) {
			if (l->wasinfected) {
				l->what = "*INFECTED* " + l->what;
			} else {
				l->what = "*SCANNED* " + l->what;
			}
		}
		if (l->contentmodified) {
			l->what = "*CONTENTMOD* " + l->what;
		}
		if (l->urlmodified) {
			l->what = "*URLMOD* " + l->what;
		}
		if (l->headermodified) {
			l->what = "*HEADERMOD* " + l->what;
		}

		std::string builtline, year, month, day, hour, min, sec, when, vbody, utime;
		struct timeval theend;

		// create a string representation of UNIX timestamp if desired
		if (o.log_timestamp || (o.log_file_format == 3)) {
			gettimeofday(&theend, NULL);
			String temp((int) (theend.tv_usec / 1000));
			while (temp.length() < 3) {
				temp = "0" + temp;
			}
			if (temp.length() > 3) {
				temp = "999";
			}
			utime = temp;
			utime = "." + utime;
			utime = String((int) theend.tv_sec) + utime;
		}

		if (o.log_file_format != 3) {
			// "when" not used in format 3, and not if logging timestamps instead
			String temp;
			time_t tnow;  // to hold the result from time()
			struct tm tmnow;  // to hold the result from localtime()
			time(&tnow);  // get the time after the lock so all entries in order
			localtime_r(&tnow, &tmnow);  // convert to local time (BST, etc)
			year = String(tmnow.tm_year + 1900);
			month = String(tmnow.tm_mon + 1);
			day = String(tmnow.tm_mday);
			hour = String(tmnow.tm_hour);
			temp = String(tmnow.tm_min);
			if (temp.length() == 1) {
				temp = "0" + temp;
			}
			min = temp;
			temp = String(tmnow.tm_sec);
			if (temp.length() == 1) {
				temp = "0" + temp;
			}
			sec = temp;
			when = year + "." + month + "." + day + " " + hour + ":" + min + ":" + sec;
			if (o.log_timestamp)
				when += " " + utime;
				
		}

		// truncate long log items
		if (o.max_logitem_length > 0) {
			if (l->cat.length() > o.max_logitem_length)
				l->cat.resize(o.max_logitem_length);
			if (l->what.length() > o.max_logitem_length)
				l->what.resize(o.max_logitem_length);
			if (l->where.length() > o.max_logitem_length)
				l->where.resize(o.max_logitem_length);
		}

		// blank out IP, hostname and username if desired
		if (o.anonymise_logs) {
			l->who = "";
			l->from = "0.0.0.0";
			l->clienthost.clear();
		}

		String stringcode(l->code);
		String stringgroup(l->filtergroup+1);

		switch (o.log_file_format) {
		case 4:
			builtline = when +"\t"+ l->who + "\t" + l->from + "\t" + l->where + "\t" + l->what + "\t" + l->how
				+ "\t" + l->ssize + "\t" + l->sweight + "\t" + l->cat +  "\t" + stringgroup + "\t"
				+ stringcode + "\t" + l->mimetype + "\t" + l->clienthost + "\t" + o.fg[l->filtergroup]->name
				+ "\t" + (o.log_user_agent ? l->useragent : "-");
			break;
		case 3:
			{
				// as certain bits of info are logged in format 3, their creation is best done here, not in all cases.
				std::string duration, hier, hitmiss;
				long durationsecs, durationusecs;
				durationsecs = (theend.tv_sec - l->t.tv_sec);
				durationusecs = theend.tv_usec - l->t.tv_usec;
				durationusecs = (durationusecs / 1000) + durationsecs * 1000;
				String temp((int) durationusecs);
				while (temp.length() < 6) {
					temp = " " + temp;
				}
				duration = temp;

				if (l->code == 403) {
					hitmiss = "TCP_DENIED/403";
				} else {
					if (l->cachehit) {
						hitmiss = "TCP_HIT/";
						hitmiss.append(stringcode);
					} else {
						hitmiss = "TCP_MISS/";
						hitmiss.append(stringcode);
					}
				}
				hier = "DEFAULT_PARENT/";
				hier += o.proxy_ip;

				builtline = utime + " " + duration + " " + ( (l->clienthost.length() > 0) ? l->clienthost : l->from) + " " + hitmiss + " " + l->ssize + " "
					+ l->how + " " + l->where + " " + l->who + " " + hier + " " + l->mimetype ;
				break;
			}
		case 2:
			builtline = "\"" + when  +"\",\""+ l->who + "\",\"" + l->from + "\",\"" + l->where + "\",\"" + l->what + "\",\""
				+ l->how + "\",\"" + l->ssize + "\",\"" + l->sweight + "\",\"" + l->cat +  "\",\"" + stringgroup + "\",\""
				+ stringcode + "\",\"" + l->mimetype + "\",\"" + l->clienthost + "\",\"" + o.fg[l->filtergroup]->name + "\",\""
				+ (o.log_user_agent ? l->useragent : "-") + "\"";
			break;
		default:
			builtline = when +" "+ l->who + " " + l->from + " " + l->where + " " + l->what + " "
				+ l->how + " " + l->ssize + " " + l->sweight + " " + l->cat +  " " + stringgroup + " "
				+ stringcode + " " + l->mimetype + " " + l->clienthost + " " + o.fg[l->filtergroup]->name + " "
				+ (o.log_user_agent ? l->useragent : "-");
		}

		if (!o.log_syslog)
			*logfile << builtline << std::endl;  // append the line
		else
			syslog(LOG_INFO, "%s", builtline.c_str());
#ifdef DGDEBUG
		std::cout << builtline << std::endl;
#endif

#ifdef ENABLE_EMAIL
		// do the notification work here, but fork for speed
		if (o.fg[filtergroup]->use_smtp==true) {

			// run through the gambit to find out of we're sending notification
			// because if we're not.. then fork()ing is a waste of time.

			// virus
			if ((wasscanned && wasinfected) && (o.fg[filtergroup]->notifyav))  {
				// Use a double fork to ensure child processes are reaped adequately.
				pid_t smtppid;
				if ((smtppid = fork()) != 0) {
					// Parent immediately waits for first child
					waitpid(smtppid, NULL, 0);
				} else {
					// First child forks off the *real* process, but immediately exits itself
					if (fork() == 0)  {
						// Second child - do stuff
						setsid();
						FILE* mail = popen (o.mailer.c_str(), "w");
						if (mail==NULL) {
							syslog(LOG_ERR, "Unable to contact defined mailer.");
						}
						else {
							fprintf(mail, "To: %s\n", o.fg[filtergroup]->avadmin.c_str());
							fprintf(mail, "From: %s\n", o.fg[filtergroup]->mailfrom.c_str());
							fprintf(mail, "Subject: %s\n", o.fg[filtergroup]->avsubject.c_str());
							fprintf(mail, "A virus was detected by DansGuardian.\n\n");
							fprintf(mail, "%-10s%s\n", "Data/Time:", when.c_str());
							if (who != "-")
								fprintf(mail, "%-10s%s\n", "User:", who.c_str());
							fprintf(mail, "%-10s%s (%s)\n", "From:", from.c_str(),  ((clienthost.length() > 0) ? clienthost.c_str() : "-"));
							fprintf(mail, "%-10s%s\n", "Where:", where.c_str());
							// specifically, the virus name comes after message 1100 ("Virus or bad content detected.")
							String swhat(what);
							fprintf(mail, "%-10s%s\n", "Why:", swhat.after(o.language_list.getTranslation(1100)).toCharArray() + 1);
							fprintf(mail, "%-10s%s\n", "Method:", how.c_str());
							fprintf(mail, "%-10s%s\n", "Size:", ssize.c_str());
							fprintf(mail, "%-10s%s\n", "Weight:", sweight.c_str());
							if (cat.c_str()!=NULL)
								fprintf(mail, "%-10s%s\n", "Category:", cat.c_str());
							fprintf(mail, "%-10s%s\n", "Mime type:", mimetype.c_str());
							fprintf(mail, "%-10s%s\n", "Group:", o.fg[filtergroup]->name.c_str());
							fprintf(mail, "%-10s%s\n", "HTTP resp:", stringcode.c_str());

							pclose(mail);
						}
						// Second child exits
						_exit(0);
					}
					// First child exits
					_exit(0);
				}
			}

			// naughty OR virus 
			else if ((isnaughty || (wasscanned && wasinfected)) && (o.fg[filtergroup]->notifycontent)) {
				byuser = o.fg[filtergroup]->byuser;

				// if no violations so far by this user/group,
				// reset threshold counters 
				if (byuser) {
					if (!violation_map[who]) {
						// set the time of the first violation
						timestamp_map[who] = time(0);
						vbody_map[who] = "";
					}
				}
				else if (!o.fg[filtergroup]->current_violations) {
					// set the time of the first violation 
					o.fg[filtergroup]->threshold_stamp = time(0);
					o.fg[filtergroup]->violationbody="";
				}

				// increase per-user or per-group violation count
				if (byuser)
					violation_map[who]++;
				else
					o.fg[filtergroup]->current_violations++;

				// construct email report
				char *vbody_temp = new char[8192];   
				sprintf(vbody_temp, "%-10s%s\n", "Data/Time:", when.c_str());
				vbody+=vbody_temp;

				if ((!byuser) && (who != "-")) {
					sprintf(vbody_temp, "%-10s%s\n", "User:", who.c_str());
					vbody+=vbody_temp;
				}
				sprintf(vbody_temp, "%-10s%s (%s)\n", "From:", from.c_str(),  ((clienthost.length() > 0) ? clienthost.c_str() : "-"));
				vbody+=vbody_temp;
				sprintf(vbody_temp, "%-10s%s\n", "Where:", where.c_str());
				vbody+=vbody_temp;
				sprintf(vbody_temp, "%-10s%s\n", "Why:", what.c_str());
				vbody+=vbody_temp;
				sprintf(vbody_temp, "%-10s%s\n", "Method:", how.c_str());
				vbody+=vbody_temp;
				sprintf(vbody_temp, "%-10s%s\n", "Size:", ssize.c_str());
				vbody+=vbody_temp;
				sprintf(vbody_temp, "%-10s%s\n", "Weight:", sweight.c_str());
				vbody+=vbody_temp;
				if (cat.c_str()!=NULL) {
					sprintf(vbody_temp, "%-10s%s\n", "Category:", cat.c_str());
					vbody+=vbody_temp;
				}
				sprintf(vbody_temp, "%-10s%s\n", "Mime type:", mimetype.c_str());
				vbody+=vbody_temp;
				sprintf(vbody_temp, "%-10s%s\n", "Group:", o.fg[filtergroup]->name.c_str());
				vbody+=vbody_temp;
				sprintf(vbody_temp, "%-10s%s\n\n", "HTTP resp:", stringcode.c_str());
				vbody+=vbody_temp;
				delete[] vbody_temp;
				
				// store the report with the group/user
				if (byuser) {
					vbody_map[who]+=vbody;
					curv_tmp = violation_map[who];
					stamp_tmp = timestamp_map[who];
				}
				else {
					o.fg[filtergroup]->violationbody+=vbody;
					curv_tmp = o.fg[filtergroup]->current_violations;
					stamp_tmp = o.fg[filtergroup]->threshold_stamp;
				}

				// if threshold exceeded, send mail
				if (curv_tmp >= o.fg[filtergroup]->violations) {
					if ((o.fg[filtergroup]->threshold == 0) || ( (time(0) - stamp_tmp) <= o.fg[filtergroup]->threshold)) {
						// Use a double fork to ensure child processes are reaped adequately.
						pid_t smtppid;
						if ((smtppid = fork()) != 0) {
							// Parent immediately waits for first child
							waitpid(smtppid, NULL, 0);
						} else {
							// First child forks off the *real* process, but immediately exits itself
							if (fork() == 0)  {
								// Second child - do stuff
								setsid();
								FILE* mail = popen (o.mailer.c_str(), "w");
								if (mail==NULL) {
									syslog(LOG_ERR, "Unable to contact defined mailer.");
								}
								else {
									fprintf(mail, "To: %s\n", o.fg[filtergroup]->contentadmin.c_str());
									fprintf(mail, "From: %s\n", o.fg[filtergroup]->mailfrom.c_str());

									if (byuser)
										fprintf(mail, "Subject: %s (%s)\n", o.fg[filtergroup]->contentsubject.c_str(), who.c_str());
									else
										fprintf(mail, "Subject: %s\n", o.fg[filtergroup]->contentsubject.c_str());

									fprintf(mail, "%i violation%s ha%s occured within %i seconds.\n",
										curv_tmp,
										(curv_tmp==1)?"":"s",
										(curv_tmp==1)?"s":"ve",									 
										o.fg[filtergroup]->threshold);

									fprintf(mail, "%s\n\n", "This exceeds the notification threshold.");
									if (byuser)
										fprintf(mail, "%s", vbody_map[who].c_str());
									else
										fprintf(mail, "%s", o.fg[filtergroup]->violationbody.c_str());
									pclose(mail);
								}
								// Second child exits
								_exit(0);
							}
							// First child exits
							_exit(0);
						}
					}
					if (byuser)
						violation_map[who]=0;
					else
						o.fg[filtergroup]->current_violations=0;
				}
			} // end naughty OR virus
		} // end usesmtp
#endif
		delete l;
	}

	if (logfile) {
		logfile->close();  // close the file
		delete logfile;
	}
	return NULL;
}

void *ipstats_loop(void *arg)
{
#ifndef WIN32
	tidyup_forchild();
#endif
	int maxusage = 0;
	while (!ttg)
	{
		// Wait for 3 minutes before writing stats - but don't just use sleep(),
		// because the main thread may want us to wake up and quit in the mean time.
		time_t now = time(NULL);
		timespec abstime;
		abstime.tv_nsec = 0;
		abstime.tv_sec = now + 180;
		pthread_mutex_lock(&ipcachemutex);
		if (pthread_cond_timedwait(&ipcacheevent, &ipcachemutex, &abstime) == ETIMEDOUT)
		{
#ifdef DGDEBUG
			std::cout << "ips in list: " << ipcache->getNumberOfItems() << std::endl;
			std::cout << "purging old ip entries" << std::endl;
#endif
			ipcache->purgeOldEntries();
#ifdef DGDEBUG
			std::cout << "ips in list: " << ipcache->getNumberOfItems() << std::endl;
#endif
			// write usage statistics
			int currusage = ipcache->getNumberOfItems();
			pthread_mutex_unlock(&ipcachemutex);
			if (currusage > maxusage)
				maxusage = currusage;
			String usagestats;
			usagestats += String(currusage) + "\n" + String(maxusage) + "\n";
#ifdef DGDEBUG
			std::cout << "writing usage stats: " << currusage << " " << maxusage << std::endl;
#endif
#ifdef WIN32
			int statfd = open(o.stat_location.c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
#else
			int statfd = open(o.stat_location.c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#endif
			if (statfd > 0) {
				write(statfd, usagestats.toCharArray(), usagestats.length());
			}
			close(statfd);
		}
		else
			pthread_mutex_unlock(&ipcachemutex);
	}
	return NULL;
}


// *
// *
// * end logger, IP list and URL cache code
// *
// *


// Does lots and lots of things - forks off url cache & logger processes, preforks child processes for connection handling, does tidying up on exit
// also handles the various signalling options DG supports (reload config, flush cache, kill all processes etc.)
int fc_controlit()
{
	int rc;

	o.lm.garbageCollect();
	if (o.max_ips > 0)
		// Cache seen IPs for a week
		ipcache = new DynamicIPList(o.max_ips, 604799);
	if (o.url_cache_number > 0)
		urlcache.setListSize(o.url_cache_number, o.url_cache_age);

	// allocate & create our server sockets
	serversocketcount = o.filter_ip.size();

	serversockets.reset(serversocketcount);
	SOCKET *serversockfds = serversockets.getFDAll();

	for (int i = 0; i < serversocketcount; i++) {
		// if the socket fd is not +ve then the socket creation failed
#ifdef WIN32
		if (serversockfds[i] == INVALID_SOCKET) {
#else
		if (serversockfds[i] < 0) {
#endif
			if (!is_daemonised) {
				std::cerr << "Error creating server socket " << i << std::endl;
			}
			syslog(LOG_ERR, "Error creating server socket %d", i);
			return 1;
		}
	}

#ifndef WIN32
	// Made unconditional such that we have root privs when creating pidfile & deleting old IPC sockets
	// PRA 10-10-2005
	/*bool needdrop = false;

	if (o.filter_port < 1024) {*/
#ifdef DGDEBUG
		std::cout << "seteuiding for low port binding/pidfile creation" << std::endl;
#endif
		//needdrop = true;
		rc = seteuid(o.root_user);
		if (rc == -1) {
			syslog(LOG_ERR, "%s", "Unable to seteuid() to bind filter port.");
#ifdef DGDEBUG
			std::cerr << "Unable to seteuid() to bind filter port." << std::endl;
#endif
			return 1;
		}
	//}

	// we have to open/create as root before drop privs
	int pidfilefd = sysv_openpidfile(o.pid_filename);
	if (pidfilefd < 0) {
		syslog(LOG_ERR, "%s", "Error creating/opening pid file.");
		std::cerr << "Error creating/opening pid file:" << o.pid_filename << std::endl;
		return 1;
	}
#endif

	// we expect to find a valid filter ip 0 specified in conf if multiple IPs are in use.
	// if we don't find one, bind to any, as per old behaviour.
	if (o.filter_ip[0].length() > 6) {
		if (serversockets.bindAll(o.filter_ip, o.filter_port)) {
			if (!is_daemonised) {
				std::cerr << "Error binding server socket (is something else running on the filter port and ip?" << std::endl;
			}
			syslog(LOG_ERR, "Error binding server socket (is something else running on the filter port and ip?");
		return 1;
		}
	} else {
		// listen/bind to a port on any interface
		if (serversockets.bindSingle(o.filter_port)) {
			char errstr[1024];
			if (!is_daemonised) {
				std::cerr << "Error binding server socket: [" << o.filter_port << "] (" << strerror_r(errno, errstr, 1024) << ")" << std::endl;
			}
			syslog(LOG_ERR, "Error binding server socket: [%d] (%s)", o.filter_port, strerror_r(errno, errstr, 1024));
			return 1;
		}
	}

#ifndef WIN32
	// Made unconditional for same reasons as above
	//if (needdrop) {
		rc = seteuid(o.proxy_user);  // become low priv again
		if (rc == -1) {
			syslog(LOG_ERR, "Unable to re-seteuid()");
#ifdef DGDEBUG
			std::cerr << "Unable to re-seteuid()" << std::endl;
#endif
			return 1;  // seteuid failed for some reason so exit with error
		}
	//}
#endif

	if (serversockets.listenAll(256)) {	// set it to listen mode with a kernel
		// queue of 256 backlog connections
		if (!is_daemonised) {
			std::cerr << "Error listening to server socket" << std::endl;
		}
		syslog(LOG_ERR, "Error listening to server socket");
		return 1;
	}

#ifndef WIN32
	if (!daemonise()) {	// become a detached daemon
		if (!is_daemonised) {
			std::cerr << "Error daemonising" << std::endl;
		}
		syslog(LOG_ERR, "Error daemonising");
		return 1;
	}

	// this has to be done after daemonise to ensure we get the correct PID.
	rc = sysv_writepidfile(pidfilefd);  // also closes the fd
	if (rc != 0) {
		char errstr[1024];
		syslog(LOG_ERR, "Error writing to the dansguardian.pid file: %s", strerror_r(errno, errstr, 1024));
		return false;
	}
	// We are now a daemon so all errors need to go in the syslog, rather
	// than being reported on screen as we've detached from the console and
	// trying to write to stdout will not be nice.

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL)) {	// ignore SIGPIPE so we can handle
		// premature disconections better
		syslog(LOG_ERR, "%s", "Error ignoring SIGPIPE");
		return (1);
	}
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGHUP, &sa, NULL)) {	// ignore HUP
		syslog(LOG_ERR, "%s", "Error ignoring HUP");
		return (1);
	}
#endif
	
	// XXX Create logging thread and IP stats thread; kill them after main loop
	pthread_t logthread;
	if (o.ll > 0)
	{
		rc = pthread_create(&logthread, NULL, &logger_loop, NULL);
		if (rc != 0) {
			char errstr[1024];
			syslog(LOG_ERR, "Unable to pthread_create() the logging thread: %s", strerror_r(rc, errstr, 1024));
			return 1;
		}
	}
	pthread_t ipstatsthread;
	if (o.max_ips > 0)
	{
		rc = pthread_create(&ipstatsthread, NULL, &ipstats_loop, NULL);
		if (rc != 0) {
			char errstr[1024];
			syslog(LOG_ERR, "Unable to pthread_create() the IP stats thread: %s", strerror_r(rc, errstr, 1024));
			return 1;
		}
	}

	// I am the parent thread here onwards.

#ifdef DGDEBUG
	std::cout << "Parent thread created children" << std::endl;
#endif

#ifndef WIN32
	// register sig_term as our SIGTERM handler
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &sig_term;
	if (sigaction(SIGTERM, &sa, NULL)) {
		// when the parent thread gets a
		// sigterm we need to kill our
		// children which this will do,
		// then we need to exit
		syslog(LOG_ERR, "Error registering SIGTERM handler");
		return (1);
	}

	// register sig_hup as our SIGHUP handler
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &sig_hup;
	if (sigaction(SIGHUP, &sa, NULL)) {
		// when the parent thread gets a
		// sighup we need to kill our
		// children which this will do,
		// then we need to read config
		syslog(LOG_ERR, "Error registering SIGHUP handler");
		return (1);
	}

	// register sig_usr1 as our handler
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &sig_usr1;
	if (sigaction(SIGUSR1, &sa, NULL)) {
		// when the parent thread gets a
		// sigusr1 we need to hup our
		// children to make them exit
		// then we need to read fg config
		syslog(LOG_ERR, "Error registering SIGUSR handler");
		return (1);
	}

#ifdef ENABLE_SEGV_BACKTRACE
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &sig_segv;
	if (sigaction(SIGSEGV, &sa, NULL)) {
		syslog(LOG_ERR, "Error registering SIGSEGV handler");
		return 1;
	}
#endif

#ifdef DGDEBUG
	std::cout << "Parent thread sig handlers done" << std::endl;
#endif
#endif

	childrenids = new pthread_t[o.max_children];  // so when one exits we know who
	childrenstates = new int[o.max_children];  // so we know what they're up to

#ifdef HAVE_POLL_H
	pollfd pollfds[serversocketcount];
#else
	fd_set selectfds;
	fd_set selecterrfds;
	unsigned int nfds = 0;
#endif

	int i;

	//time_t tnow;
	time_t tmaxspare;

	time(&tmaxspare);

#ifdef DGDEBUG
	std::cout << "Parent process pid structs allocated" << std::endl;
#endif

	// store child ids...
	for (i = 0; i < o.max_children; i++) {
		childrenstates[i] = -1;
	}
	// ...and server fds
#ifdef HAVE_POLL_H
	for (i = 0; i < serversocketcount; i++) {
		pollfds[i].fd = serversockfds[i];
		pollfds[i].events = POLLIN;
	}
#endif

#ifdef DGDEBUG
	std::cout << "Parent process pid structs zeroed" << std::endl;
#endif

	failurecount = 0;  // as we don't exit on an error with select()
	// due to the fact that these errors do happen
	// every so often on a fully working, but busy
	// system, we just watch for too many errors
	// consecutivly.

	numchildren = 0;
	rc = prefork(o.max_children);

#ifdef WIN32
	Sleep(1000);
#else
	sleep(1);  // need to allow some of the forks to complete
#endif

#ifdef DGDEBUG
	std::cout << "Parent process preforked rc:" << rc << std::endl;
	std::cout << "Parent process pid:" << getpid() << std::endl;
#endif

	if (rc < 0) {
		ttg = true;
		syslog(LOG_ERR, "%s", "Error creating initial fork pool - exiting...");
	}

	reloadconfig = false;

	syslog(LOG_INFO, "Started sucessfully.");

	while (failurecount < 30 && !ttg && !reloadconfig) {
#ifdef HAVE_POLL_H
		for (i = 0; i < serversocketcount; i++) {
			pollfds[i].revents = 0;
		}
		rc = poll(pollfds, serversocketcount, 60 * 1000);
#else
		FD_ZERO(&selectfds);
		FD_ZERO(&selecterrfds);
		for (i = 0; i < serversocketcount; i++) {
			FD_SET(serversockfds[i], &selectfds);
			FD_SET(serversockfds[i], &selecterrfds);
			if (serversockfds[i] > nfds)
				nfds = serversockfds[i];
		}
		timeval stv;
		stv.tv_sec = 60;
		stv.tv_usec = 0;
		rc = select(nfds + 1, &selectfds, NULL, &selecterrfds, &stv);
#endif

#ifdef WIN32
		if (rc == SOCKET_ERROR) {
#else
		if (rc < 0) {
#endif
#ifdef DGDEBUG
			char errstr[1024];
			std::cout << "errno: " << socket_errno << " " << strerror_r(socket_errno, errstr, 1024) << std::endl;
#endif
			if (socket_errno == SOCKET_EINTR) {
				continue;  // was interupted by a signal so restart
			}
			if (o.logconerror)
			{
				char errstr[1024];
				syslog(LOG_ERR, "Error polling server sockets: %d, %s", socket_errno, strerror_r(socket_errno, errstr, 1024));
			}
			failurecount++;  // log the error/failure
			continue;  // then continue with the looping
		}

		if (rc > 0) {
			for (i = 0; i < serversocketcount; i++) {
#ifdef HAVE_POLL_H
				if ((pollfds[i].revents & POLLIN) > 0) {
#else
				if (FD_ISSET(serversockfds[i], &selectfds)) {
#endif
					// socket ready to accept() a connection
					failurecount = 0;  // something is clearly working so reset count

					Socket* newsock = serversockets[i]->accept();
					pthread_mutex_lock(&connmutex);
					if (ttg || reloadconfig)
						break;
					// Wait if we have too many active connections
					while (connqueue.size() > 10)
					{
						pthread_mutex_unlock(&connmutex);
#ifdef WIN32
						Sleep(1000);
#else
						sleep(1);
#endif
						pthread_mutex_lock(&connmutex);
					}

					connqueue.push(newsock);
					pthread_cond_signal(&connevent);
					pthread_mutex_unlock(&connmutex);
				}
#ifdef HAVE_POLL_H
				else if (pollfds[i].revents) {
#else
				if (FD_ISSET(serversockfds[i], &selecterrfds)) {
#endif
					ttg = true;
					syslog(LOG_ERR, "Error with main listening socket.  Exiting.");
					break;
				}
			}
		}
	}
	
	ttg = true;
	reloadconfig = true;
	pthread_cond_broadcast(&connevent);
	pthread_cond_broadcast(&logevent);
	pthread_cond_broadcast(&ipcacheevent);
	// we might not giving enough time for defuncts to be created and then
	// mopped but on exit or reload config they'll get mopped up
#ifdef WIN32
	Sleep(1000);
#else
	sleep(1);
#endif
	mopup_afterkids();
	
	urlcache.flush();

	while (!connqueue.empty())
	{
		delete connqueue.front();
		connqueue.pop();
	}

	while (!logqueue.empty())
	{
		delete logqueue.front();
		logqueue.pop();
	}
	
	if (o.ll > 0)
		pthread_join(logthread, NULL);
	if (o.max_ips > 0)
		pthread_join(ipstatsthread, NULL);

	delete[]childrenids;
	delete[]childrenstates;

	if (failurecount >= 30) {
		syslog(LOG_ERR, "%s", "Exiting due to high failure count.");
#ifdef DGDEBUG
		std::cout << "Exiting due to high failure count." << std::endl;
#endif
	}
#ifdef DGDEBUG
	std::cout << "Main parent process exiting." << std::endl;
#endif

	// be nice and neat
	serversockets.deleteAll();
	delete[] serversockfds;
	delete ipcache;
	ipcache = NULL;

#ifndef WIN32
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	if (sigaction(SIGTERM, &sa, NULL)) {	// restore sig handler
		// in child process
#ifdef DGDEBUG
		std::cerr << "Error resetting signal for SIGTERM" << std::endl;
#endif
		syslog(LOG_ERR, "%s", "Error resetting signal for SIGTERM");
	}
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGHUP, &sa, NULL)) {	// restore sig handler
		// in child process
#ifdef DGDEBUG
		std::cerr << "Error resetting signal for SIGHUP" << std::endl;
#endif
		syslog(LOG_ERR, "%s", "Error resetting signal for SIGHUP");
	}
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGUSR1, &sa, NULL)) {	// restore sig handler
		// in child process
#ifdef DGDEBUG
		std::cerr << "Error resetting signal for SIGUSR1" << std::endl;
#endif
		syslog(LOG_ERR, "%s", "Error resetting signal for SIGUSR1");
	}
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	if (sigaction(SIGPIPE, &sa, NULL)) {	// restore sig handler
		// in child process
#ifdef DGDEBUG
		std::cerr << "Error resetting signal for SIGPIPE" << std::endl;
#endif
		syslog(LOG_ERR, "%s", "Error resetting signal for SIGPIPE");
	}
#endif

	if (o.logconerror) {
		syslog(LOG_ERR, "%s", "Main parent process exiting.");
	}
	return 1;  // It is only possible to reach here with an error
}
