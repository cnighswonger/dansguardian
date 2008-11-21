//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.
//Written by Daniel Barron (daniel@//jadeb/.com).
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
#include "FatController.hpp"
#include "SysV.hpp"

#include <iostream>
#include <cstdio>
#include <ctime>
#include <unistd.h>
#include <cerrno>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include <fstream>
#include <fcntl.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef __BENCHMARK
#include <sys/times.h>
#include "NaughtyFilter.hpp"
#endif


// GLOBALS

#ifndef FD_SETSIZE
#define FD_SETSIZE 256
#endif

OptionContainer o;

bool is_daemonised;

// regexp used during URL decoding by HTTPHeader
// we want it compiled once, not every time it's used, so do so on startup
RegExp urldecode_re;

#ifdef HAVE_PCRE
// regexes used for embedded URL extraction by NaughtyFilter
RegExp absurl_re, relurl_re;
#endif

// DECLARATIONS

// get the OptionContainer to read in the given configuration file
void read_config(const char *configfile, int type);


// IMPLEMENTATION

// get the OptionContainer to read in the given configuration file
void read_config(const char *configfile, int type)
{
	int rc = open(configfile, 0, O_RDONLY);
	if (rc < 0) {
		syslog(LOG_ERR, "Error opening %s", configfile);
		std::cerr << "Error opening " << configfile << std::endl;
		exit(1);  // could not open conf file for reading, exit with error
	}
	close(rc);

	if (!o.read(configfile, type)) {
		syslog(LOG_ERR, "%s", "Error parsing the dansguardian.conf file or other DansGuardian configuration files");
		std::cerr << "Error parsing the dansguardian.conf file or other DansGuardian configuration files" << std::endl;
		exit(1);  // OptionContainer class had an error reading the conf or other files so exit with error
	}
}

// program entry point
int main(int argc, char *argv[])
{
	is_daemonised = false;
	bool nodaemon = false;
	bool needreset = false;
	std::string configfile(__CONFFILE);
	srand(time(NULL));
	int rc;

	openlog("dansguardian", LOG_PID | LOG_CONS, LOG_USER);

#ifdef DGDEBUG
	std::cout << "Running in debug mode..." << std::endl;
#endif

#ifdef __BENCHMARK
	char benchmark = '\0';
#endif

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			for (unsigned int j = 1; j < strlen(argv[i]); j++) {
				char option = argv[i][j];
				bool dobreak = false;
				switch (option) {
				case 'q':
					read_config(configfile.c_str(), 0);
					return sysv_kill(o.pid_filename);
				case 'Q':
					read_config(configfile.c_str(), 0);
					sysv_kill(o.pid_filename, false);
					// give the old process time to die
					while(sysv_amirunning(o.pid_filename))
						sleep(1);
					unlink(o.pid_filename.c_str());
					unlink(o.ipc_filename.c_str());
					unlink(o.urlipc_filename.c_str());
					// remember to reset config before continuing
					needreset = true;
					break;
				case 's':
					read_config(configfile.c_str(), 0);
					return sysv_showpid(o.pid_filename);
				case 'r':
					read_config(configfile.c_str(), 0);
					return sysv_hup(o.pid_filename);
				case 'g':
					read_config(configfile.c_str(), 0);
					return sysv_usr1(o.pid_filename);
				case 'v':
					std::cout << "DansGuardian " << PACKAGE_VERSION << std::endl << std::endl
						<< "Built with: " << DG_CONFIGURE_OPTIONS << std::endl;
					return 0;
				case 'N':
					nodaemon = true;
					break;
				case 'c':
					if ((i+1) < argc) {
						configfile = argv[i+1];
						dobreak = true;  // broken-ness of this option reported by Jason Gauthier 2006-03-09
					} else {
						std::cerr << "No config file specified!" << std::endl;
						return 1;
					}
					break;
				case 'h':
					std::cout << "Usage: " << argv[0] << " [{-c ConfigFileName|-v|-P|-h|-N|-q|-s|-r|-g}]" << std::endl;
					std::cout << "  -v gives the version number and build options." << std::endl;
					std::cout << "  -h gives this message." << std::endl;
					std::cout << "  -c allows you to specify a different configuration file location." << std::endl;
					std::cout << "  -N Do not go into the background." << std::endl;
					std::cout << "  -q causes DansGuardian to kill any running copy." << std::endl;
					std::cout << "  -Q kill any running copy AND start a new one with current options." << std::endl;
					std::cout << "  -s shows the parent process PID and exits." << std::endl;
					std::cout << "  -r closes all connections and reloads config files by issuing a HUP," << std::endl;
					std::cout << "     but this does not reset the maxchildren option (amongst others)." << std::endl;
					std::cout << "  -g gently restarts by not closing all current connections; only reloads" << std::endl
						<< "     filter group config files. (Issues a USR1)" << std::endl;
#ifdef __BENCHMARK
					std::cout << "  --bs benchmark searching filter group 1's bannedsitelist" << std::endl;
					std::cout << "  --bu benchmark searching filter group 1's bannedurllist" << std::endl;
					std::cout << "  --bp benchmark searching filter group 1's phrase lists" << std::endl;
					std::cout << "  --bn benchmark filter group 1's NaughtyFilter in its entirety" << std::endl;
#endif
					return 0;
#ifdef __BENCHMARK
				case '-':
					if (strlen(argv[i]) != 4) {
						std::cerr << "Invalid benchmark option" << std::endl;
						return 1;
					}
					benchmark = argv[i][3];
					dobreak = true;
					break;
#endif
				}
				if (dobreak) break; // skip to the next argument
			}
		}
	}

	// Set current locale for proper character conversion
	setlocale(LC_ALL, "");

	if (needreset) {
		o.reset();
	}
	
	read_config(configfile.c_str(), 2);

#ifdef __BENCHMARK
	// run benchmarks instead of starting the daemon
	if (benchmark) {
		std::string results;
		char* found;
		struct tms then, now;
		std::string line;
		std::deque<String*> lines;
		while (!std::cin.eof()) {
			std::getline(std::cin, line);
			String* strline = new String(line);
			lines.push_back(strline);
		}
		String* strline = NULL;
		times(&then);
		switch (benchmark) {
		case 's':
			// bannedsitelist
			while (!lines.empty()) {
				strline = lines.back();
				lines.pop_back();
				if ((found = o.fg[0]->inBannedSiteList(*strline))) {
					results += found;
					results += '\n';
				}
				delete strline;
			}
			break;
		case 'u':
			// bannedurllist
			while (!lines.empty()) {
				strline = lines.back();
				lines.pop_back();
				if ((found = o.fg[0]->inBannedURLList(*strline))) {
					results += found;
					results += '\n';
				}
				delete strline;
			}
			break;
		case 'p': {
				// phraselists
				std::deque<unsigned int> found;
				std::string file;
				while (!lines.empty()) {
					strline = lines.back();
					lines.pop_back();
					file += strline->toCharArray();
					delete strline;
				}
				char cfile[file.length() + 129];
				memcpy(cfile, file.c_str(), sizeof(char)*file.length());
				o.lm.l[o.fg[0]->banned_phrase_list]->graphSearch(found, cfile, file.length());
				for (std::deque<unsigned int>::iterator i = found.begin(); i != found.end(); i++) {
					results += o.lm.l[o.fg[0]->banned_phrase_list]->getItemAtInt(*i);
					results += '\n';
				}
			}
			break;
		case 'n': {
				// NaughtyFilter
				std::string file;
				NaughtyFilter n;
				while (!lines.empty()) {
					strline = lines.back();
					lines.pop_back();
					file += strline->toCharArray();
					delete strline;
				}
				DataBuffer d(file.c_str(), file.length());
				String f;
				n.checkme(&d, f, f);
				std::cout << n.isItNaughty << std::endl << n.whatIsNaughty << std::endl << n.whatIsNaughtyLog << std::endl << n.whatIsNaughtyCategories << std::endl;
			}
			break;
		default:
			std::cerr << "Invalid benchmark option" << std::endl;
			return 1;
		}
		times(&now);
		std::cout << results << std::endl << "time: " << now.tms_utime - then.tms_utime << std::endl;
		return 0;
	}
#endif

	if (sysv_amirunning(o.pid_filename)) {
		syslog(LOG_ERR, "%s", "I seem to be running already!");
		std::cerr << "I seem to be running already!" << std::endl;
		return 1;  // can't have two copies running!!
	}

	if (nodaemon) {
		o.no_daemon = 1;
	}

	if ((o.max_children + 6) > FD_SETSIZE) {
		syslog(LOG_ERR, "%s", "maxchildren option in dansguardian.conf has a value too high.");
		std::cerr << "maxchildren option in dansguardian.conf has a value too high." << std::endl;
		std::cerr << "Dammit Jim, I'm a filtering proxy, not a rabbit." << std::endl;
		return 1;  // we can't have rampant proccesses can we?
	}

	unsigned int rootuid;  // prepare a struct for use later
	rootuid = geteuid();
	o.root_user = rootuid;

	struct passwd *st;  // prepare a struct
	struct group *sg;

	// "daemongroup" option exists, but never used to be honoured. this is now
	// an important feature, however, because we need to be able to create temp
	// files with suitable permissions for scanning by AV daemons - we do this
	// by becoming a member of a specified AV group and setting group read perms
	if ((sg = getgrnam(o.daemon_group_name.c_str())) != 0) {
		o.proxy_group = sg->gr_gid;
	} else {
		syslog(LOG_ERR, "Unable to getgrnam(): %s", strerror(errno));
		std::cerr << "Unable to getgrnam(): " << strerror(errno) << std::endl;
		return 1;
	}

	if ((st = getpwnam(o.daemon_user_name.c_str())) != 0) {	// find uid for proxy user
		o.proxy_user = st->pw_uid;

		rc = setgid(o.proxy_group);  // change to rights of proxy user group
		// i.e. low - for security
		if (rc == -1) {
			syslog(LOG_ERR, "%s", "Unable to setgid()");
			std::cerr << "Unable to setgid()" << std::endl;
			return 1;  // setgid failed for some reason so exit with error
		}
#ifdef HAVE_SETREUID
		rc = setreuid((uid_t) - 1, st->pw_uid);
#else
		rc = seteuid(o.proxy_user);  // need to be euid so can su back
		// (yes it negates but no choice)
#endif
		if (rc == -1) {
			syslog(LOG_ERR, "Unable to seteuid()");
			std::cerr << "Unable to seteuid()" << std::endl;
			return 1;  // seteuid failed for some reason so exit with error
		}
	} else {
		syslog(LOG_ERR, "Unable to getpwnam() - does the proxy user exist?");
		std::cerr << "Unable to getpwnam() - does the proxy user exist?" << std::endl;
		std::cerr << "Proxy user looking for is '" << o.daemon_user_name << "'" << std::endl;
		return 1;  // was unable to lockup the user id from passwd
		// for some reason, so exit with error
	}

	if (!o.no_logger && !o.log_syslog) {
		std::ofstream logfiletest(o.log_location.c_str(), std::ios::app);
		if (logfiletest.fail()) {
			syslog(LOG_ERR, "Error opening/creating log file. (check ownership and access rights).");
			std::cout << "Error opening/creating log file. (check ownership and access rights)." << std::endl;
			std::cout << "I am running as " << o.daemon_user_name << " and I am trying to open " << o.log_location << std::endl;
			return 1;  // opening the log file for writing failed
		}
		logfiletest.close();
	}

	urldecode_re.comp("%[0-9a-fA-F][0-9a-fA-F]");  // regexp for url decoding

#ifdef HAVE_PCRE
	// todo: these only work with PCRE enabled (non-greedy matching).
	// change them, or make them a feature for which you need PCRE?
	absurl_re.comp("[\"'](http|ftp)://.*?[\"']");  // find absolute URLs in quotes
	relurl_re.comp("(href|src)\\s*=\\s*[\"'].*?[\"']");  // find relative URLs in quotes
#endif

	// this is no longer a class, but the comment has been retained for historical reasons. PRA 03-10-2005
	//FatController f;  // Thomas The Tank Engine

	while (true) {
		rc = fc_controlit();
		// its a little messy, but I wanted to split
		// all the ground work and non-daemon stuff
		// away from the daemon class
		// However the line is not so fine.
		if (rc == 2) {

			// In order to re-read the conf files and create cache files
			// we need to become root user again

#ifdef HAVE_SETREUID
			rc = setreuid((uid_t) - 1, rootuid);
#else
			rc = seteuid(rootuid);
#endif
			if (rc == -1) {
				syslog(LOG_ERR, "%s", "Unable to seteuid() to read conf files.");
#ifdef DGDEBUG
				std::cerr << "Unable to seteuid() to read conf files." << std::endl;
#endif
				return 1;
			}
#ifdef DGDEBUG
			std::cout << "About to re-read conf file." << std::endl;
#endif
			o.reset();
			if (!o.read(configfile.c_str(), 2)) {
				syslog(LOG_ERR, "%s", "Error re-parsing the dansguardian.conf file or other DansGuardian configuration files");
#ifdef DGDEBUG
				std::cerr << "Error re-parsing the dansguardian.conf file or other DansGuardian configuration files" << std::endl;
#endif
				return 1;
				// OptionContainer class had an error reading the conf or
				// other files so exit with error
			}
#ifdef DGDEBUG
			std::cout << "conf file read." << std::endl;
#endif

			if (nodaemon) {
				o.no_daemon = 1;
			}

			while (waitpid(-1, NULL, WNOHANG) > 0) {
			}	// mop up defunts

#ifdef HAVE_SETREUID
			rc = setreuid((uid_t) - 1, st->pw_uid);
#else
			rc = seteuid(st->pw_uid);  // become low priv again
#endif

			if (rc == -1) {
				syslog(LOG_ERR, "%s", "Unable to re-seteuid()");
#ifdef DGDEBUG
				std::cerr << "Unable to re-seteuid()" << std::endl;
#endif
				return 1;  // seteuid failed for some reason so exit with error
			}
			continue;
		}

		if (rc > 0) {
			if (!is_daemonised) {
				std::cerr << "Exiting with error" << std::endl;
			}
			syslog(LOG_ERR, "%s", "Exiting with error");
			return rc;  // exit returning the error number
		}
		return 0;  // exit without error
	}
}
