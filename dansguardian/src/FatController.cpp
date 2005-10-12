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

#include "platform.h"

#include "FatController.hpp"
#include "ConnectionHandler.hpp"
#include "DynamicURLList.hpp"
#include "String.hpp"
#include "Socket.hpp"
#include "UDSocket.hpp"
#include "SysV.hpp"

#include <syslog.h>
#include <csignal>
#include <sys/stat.h>
#include <pwd.h>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <sys/time.h>
#include <sys/poll.h>

#ifdef __GCCVER3
#include <istream>
#else
#include <istream.h>
#endif


// GLOBALS

// these are used in signal handlers - "volatile" indicates they can change at
// any time, and therefore value reading on them does not get optimised. since
// the values can get altered by outside influences, this is useful.
static volatile bool ttg = false;
/*static*/ volatile bool reloadconfig = false;
static volatile bool gentlereload = false;
static volatile bool sig_term_killall = false;

extern OptionContainer o;
extern bool is_daemonised;

int numchildren;  // to keep count of our children
int busychildren;  // to keep count of our children
int freechildren;  // to keep count of our children
int waitingfor;  // num procs waiting for to be preforked
int *childrenpids;  // so when one exits we know who
int *childrenstates;  // so we know what they're up to
struct pollfd *pids;
UDSocket **childsockets;
int failurecount;
Socket serversock;  // the socket we will listen on for connections
UDSocket ipcsock;  // the unix domain socket to be used for ipc with the forked children
UDSocket urllistsock;
Socket* peersock = NULL;  // the socket which will contain the connection

String peersockip;  // which will contain the connection ip
int peersockport;  // port connection originates


// DECLARATIONS

// Signal handlers
extern "C"
{
	void sig_chld(int signo);
	void sig_term(int signo);  // This is so we can kill our children
	void sig_termsafe(int signo);  // This is so we can kill our children safer
	void sig_hup(int signo);  // This is so we know if we should re-read our config.
	void sig_usr1(int signo);  // This is so we know if we should re-read our config but not kill current connections
}

// logging & URL cache processes
int log_listener(std::string log_location, int logconerror);
int url_list_listener(int logconerror);
// send flush message over URL cache IPC socket
void flush_urlcache();

// fork off into background
bool daemonise();
// create specified amount of child processes
int prefork(int num);

// check child process is ready to start work
bool check_kid_readystatus(int tofind);
// child process informs parent process that it is ready
int send_readystatus(UDSocket &pipe);

// child process main loop - sits waiting for incoming connections & processes them
int handle_connections(UDSocket &pipe);
// tell a non-busy child process to accept the incoming connection
void tellchild_accept(int num);
// child process accept()s connection from server socket
bool getsock_fromparent(UDSocket &fd);

// add known info about a child to our info lists
void addchild(int pos, int fd, pid_t child_pid);
// find ID of first non-busy child
int getfreechild();
// find an empty slot in our child info lists
int getchildslot();
// cull up to this number of non-busy children
void cullchildren(int num);
// delete this child from our info lists (pass in child's recorded exit value - currently unused)
void deletechild(int child_pid, int stat);
// clean up any dead child processes (calls deletechild with exit values)
void mopup_afterkids();

// tidy up resources for a brand new child process (uninstall signal handlers, delete copies of unnecessary data, etc.)
void tidyup_forchild();

// send SIGTERM or SIGHUP to call children
void kill_allchildren();
void hup_allchildren();

// setuid() to proxy user (not just seteuid()) - used by child processes & logger/URL cache for security & resource usage reasons
bool drop_priv_completely();



// IMPLEMENTATION

// signal handlers
extern "C"
{	// The kernel knows nothing of objects so
	// we have to have a lump of c
	void sig_term(int signo)
	{
		sig_term_killall = true;
		ttg = true;  // its time to go
	}
	void sig_termsafe(int signo)
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
}

// this is used by dansguardian.cpp, to, yep, test connection to the proxy
// If report is true we log the problem.  report as false allows the caller
// to test multiple times with no error
bool fc_testproxy(std::string proxyip, int proxyport, bool report)
{
	int sck_inet, conn;
	Socket sock;
	sck_inet = sock.getFD();
	if (sck_inet == -1) {
		if (report) {
			if (!is_daemonised) {
				std::cerr << "Error creating socket to test proxy connection" << std::endl;
			}
			syslog(LOG_ERR, "%s", "Error creating socket to test proxy connection");
		}
		return false;
	}
	conn = sock.connect(proxyip, proxyport);  // hmmm, I wonder what this do
	if (conn) {
		if (report) {
			if (!is_daemonised) {
				std::cerr << "Error connecting to parent proxy" << std::endl;
			}
			syslog(LOG_ERR, "%s", "Error connecting to parent proxy");
		}
		return false;
	}
	sock.close();
	return true;  // it worked!
}

// completely drop our privs - i.e. setuid, not just seteuid
bool drop_priv_completely()
{
	// This is done to solve the problem where the total processes for the
	// uid rather than euid is taken for RLIMIT_NPROC and so can't fork()
	// as many as expected.
	// It is also more secure.
	//
	// Suggested fix by Lawrence Manning Tue 25th February 2003
	//

	int rc = seteuid(o.root_user);  // need to be root again to drop properly
	if (rc == -1) {
		syslog(LOG_ERR, "%s", "Unable to seteuid(suid)");
#ifdef DGDEBUG
		std::cout << strerror(errno) << std::endl;
#endif
		return false;  // setuid failed for some reason so exit with error
	}
	rc = setuid(o.proxy_user);
	if (rc == -1) {
		syslog(LOG_ERR, "%s", "Unable to setuid()");
		return false;  // setuid failed for some reason so exit with error
	}
	return true;
}

// signal the URL cache to flush via IPC
void flush_urlcache()
{
	if (o.url_cache_number < 1) {
		return;  // no cache running to flush
	}
	UDSocket fipcsock;
	if (fipcsock.getFD() < 0) {
		syslog(LOG_ERR, "%s", "Error creating ipc socket to url cache for flush");
		return;
	}
	if (fipcsock.connect((char *) o.urlipc_filename.c_str()) < 0) {	// conn to dedicated url cach proc
		syslog(LOG_ERR, "%s", "Error connecting via ipc to url cache for flush");
#ifdef DGDEBUG
		std::cout << "Error connecting via ipc to url cache for flush" << std::endl;
#endif
		return;
	}
	String request = "F \n";
	try {
		fipcsock.writeString(request.toCharArray());  // throws on err
	}
	catch(exception & e) {
#ifdef DGDEBUG
		std::cerr << "Exception flushing url cache" << std::endl;
		std::cerr << e.what() << std::endl;
#endif
		syslog(LOG_ERR, "%s", "Exception flushing url cache");
		syslog(LOG_ERR, "%s", e.what());
	}
}

// Fork ourselves off into the background
bool daemonise()
{

	if (o.no_daemon == 1) {
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


// *
// *
// *  child process code
// *
// *

// prefork specified num of children and set them handling connections
int prefork(int num)
{
	if (num < waitingfor) {
		return 3;  // waiting for forks already
	}
#ifdef DGDEBUG
	std::cout << "attempting to prefork:" << num << std::endl;
#endif
	int sv[2];
	pid_t child_pid;
	while (num--) {
		if (numchildren >= o.max_children) {
			return 2;  // too many - geddit?
		}
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
			return -1;  // error
		}

		child_pid = fork();

		if (child_pid == -1) {	// fork failed, for example, if the
			// process is not allowed to create
			// any more
			syslog(LOG_ERR, "%s", "Unable to fork() any more.");
#ifdef DGDEBUG
			std::cout << "Unable to fork() any more." << std::endl;
			std::cout << strerror(errno) << std::endl;
			std::cout << "numchildren:" << numchildren << std::endl;
#endif
			failurecount++;  // log the error/failure
			// A DoS attack on a server allocated
			// too many children in the conf will
			// kill the server.  But this is user
			// error.
			sleep(1);  // need to wait until we have a spare slot
			num--;
			continue;  // Nothing doing, go back to listening
		}
		else if (child_pid == 0) {
			// I am the child - I am alive!
			close(sv[0]);  // we only need our copy of this
			tidyup_forchild();
			if (!drop_priv_completely()) {
				return -1;  //error
			}
			// no need to deallocate memory etc as already done when fork()ed

			// right - let's do our job!
			UDSocket sock(sv[1]);
			int rc = handle_connections(sock);
			
			// ok - job done, time to tidy up.
			serversock.close();  // listening connection
			_exit(rc);  // baby go bye bye
		} else {
			// I am the parent
			// close the end of the socketpair we don't need
			close(sv[1]);
			// add the child and its FD/PID to an empty child slot
			addchild(getchildslot(), sv[0], child_pid);
#ifdef DGDEBUG
			std::cout << "Preforked parent added child to list" << std::endl;
#endif
		}
	}
	return 1;  // parent returning
}

// cleaning up for brand new child processes - only the parent needs the signal handlers installed, and so forth
void tidyup_forchild()
{
	struct sigaction sa;
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
	if (sigaction(SIGUSR1, &sa, NULL)) {	// restore sig handler
		// in child process
#ifdef DGDEBUG
		std::cerr << "Error resetting signal for SIGUSR1" << std::endl;
#endif
		syslog(LOG_ERR, "%s", "Error resetting signal for SIGUSR1");
	}
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &sig_hup;
	if (sigaction(SIGHUP, &sa, NULL)) {	// restore sig handler
		// in child process
#ifdef DGDEBUG
		std::cerr << "Error resetting signal for SIGHUP" << std::endl;
#endif
		syslog(LOG_ERR, "%s", "Error resetting signal for SIGHUP");
	}
	// now close open socket pairs don't need

	for (int i = 0; i < o.max_children; i++) {
		if (pids[i + 1].fd != -1) {
			delete childsockets[i];
		}
	}
	delete[]childrenpids;
	delete[]childrenstates;
	delete[]childsockets;
	delete[]pids;  // 4 deletes good, memory leaks bad
}

// send Ready signal to parent process over the socketpair (used in handle_connections)
int send_readystatus(UDSocket &pipe)
{				// blocks until timeout
	String message = "2\n";
	try {
		if (!pipe.writeToSocket(message.toCharArray(), message.length(), 0, 15, true, true)) {
			return -1;
		}
	}
	catch(exception & e) {
		return -1;
	}
	return 0;
}

// handle any connections received by this child (also tell parent we're ready each time we become idle)
int handle_connections(UDSocket &pipe)
{
	ConnectionHandler h;  // the class that handles the connections
	String ip;
	bool toldparentready = false;
	int cycle = o.maxage_children;
	int stat = 0;
	reloadconfig = false;

	// stay alive both for the maximum allowed age of child processes, and whilst we aren't supposed to be re-reading configuration
	while (cycle-- && !reloadconfig) {
		if (!toldparentready) {
			if (send_readystatus(pipe) == -1) {	// non-blocking (timed)
#ifdef DGDEBUG
				std::cout << "parent timed out telling it we're ready" << std::endl;
#endif
				break;  // parent timed out telling it we're ready
				// so either parent gone or problem so lets exit this joint
			}
			toldparentready = true;
		}

		if (!getsock_fromparent(pipe)) {	// blocks waiting for a few mins
			continue;
		}
		toldparentready = false;

		if (peersock->getFD() < 1 || peersockip.length() < 7) {
			continue;
		}

		h.handleConnection(*peersock, peersockip, peersockport);  // deal with the connection
		delete peersock;
	}
#ifdef DGDEBUG
	if (reloadconfig) {
		std::cout << "child been told to exit by hup" << std::endl;
	}
#endif
	if (!toldparentready) {
		stat = 2;
	}
	return stat;
}

// the parent process recieves connections - children receive notifications of this over their socketpair, and accept() them for handling
bool getsock_fromparent(UDSocket &fd)
{
	String message;
	char *buf = new char[5];
	int rc;
	try {
		rc = fd.readFromSocket(buf, 4, 0, 360, true, true);  // blocks for a few mins
	}
	catch(exception & e) {
		delete[]buf;

		// whoop! we received a SIGHUP. we should reload our configuration - and no, we didn't get an FD.

		reloadconfig = true;
		return false;
	}
	// that way if child does nothing for a long time it will eventually
	// exit reducing the forkpool depending on o.maxage_children which is
	// usually 500 so max time a child hangs around is lonngggg
	// it needs to be a long block to stop the machine needing to page in
	// the process
	
	// check the message from the parent
	if (rc < 1) {
		delete[]buf;
		return false;
	}
	if (buf[0] != 'G') {
		delete[]buf;
		return false;
	}
	delete[]buf;

	// woo! we have a connection. accept it.
	
	peersock = serversock.accept();
	peersockip = peersock->getPeerIP();
	peersockport = peersock->getPeerSourcePort();

	try {
		fd.writeToSockete("K\n", 2, 0, 10, true);  // need to make parent wait for OK
		// so effectively providing a lock
	}
	catch(exception & e) {
		peersock->close();
	}

	if (peersock->getFD() < 1) {
		if (o.logconerror == 1) {
			syslog(LOG_INFO, "%s", "Error accepting. (Ignorable)");
		}
		return false;
	}
	return true;
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
	pid_t pid;
	int stat_val;
	while (true) {
		pid = waitpid(-1, &stat_val, WNOHANG);
		if (pid < 1) {
			break;
		}
		if (WIFEXITED(stat_val)) {	// exited normally
			deletechild((int) pid, WEXITSTATUS(stat_val));
		} else {
			deletechild((int) pid, -1);
		}
	}
}

// get a free slot in out PID list, if there is one - return -1 if not
int getchildslot()
{
	int i;
	for (i = 0; i < o.max_children; i++) {
		if (childrenpids[i] == -1) {
			return i;
		}
	}
	return -1;
}

// add the given child, including FD & PID, to the given slot in our lists
void addchild(int pos, int fd, pid_t child_pid)
{
	childrenpids[pos] = (int) child_pid;
	childrenstates[pos] = 4;  // busy waiting for init
	numchildren++;
	busychildren++;
	waitingfor++;
	pids[pos + 1].fd = fd;
	UDSocket* sock = new UDSocket(fd);
	childsockets[pos] = sock;
}

// kill give number of non-busy children
void cullchildren(int num)
{
#ifdef DGDEBUG
	cout << "culling childs:" << num << endl;
#endif
	int i;
	int count = 0;
	for (i = o.max_children - 1; i >= 0; i--) {
		if (childrenstates[i] == 0) {
			kill(childrenpids[i], SIGTERM);
			count++;
			childrenstates[i] = -2;  // dieing
			numchildren--;
			delete childsockets[i];
			pids[i + 1].fd = -1;
			if (count >= num) {
				break;
			}
		}
	}
}

// send SIGTERM to all child processes
void kill_allchildren()
{
#ifdef DGDEBUG
	cout << "killing all childs:" << endl;
#endif
	for (int i = o.max_children - 1; i >= 0; i--) {
		if (childrenstates[i] >= 0) {
			kill(childrenpids[i], SIGTERM);
			childrenstates[i] = -2;  // dieing
			numchildren--;
		}
	}
}

// send SIGHUP to all child processes
void hup_allchildren()
{
#ifdef DGDEBUG
	cout << "huping all childs:" << endl;
#endif
	for (int i = o.max_children - 1; i >= 0; i--) {
		if (childrenstates[i] >= 0) {
			kill(childrenpids[i], SIGHUP);
		}
	}
}

// attempt to receive the message from the child's send_readystatus call
bool check_kid_readystatus(int tofind)
{
	bool found = false;
	char *buf = new char[5];
	int rc = -1;  // for compiler warnings
	for (int f = 1; f <= o.max_children; f++) {

		if (tofind < 1) {
			break;  // no point looping through all if all found
		}
		if (pids[f].fd == -1) {
			continue;
		}
		if ((pids[f].revents & POLLIN) > 0) {
			if (childrenstates[f - 1] < 0) {
				tofind--;
				continue;
			}
			try {
				rc = childsockets[f-1]->getLine(buf, 4, 100, true);
			}
			catch(exception & e) {
				kill(childrenpids[f - 1], SIGTERM);
				deletechild(childrenpids[f - 1], -1);
				tofind--;
				continue;
			}
			if (rc > 0) {
				if (buf[0] == '2') {
					if (childrenstates[f - 1] == 4) {
						waitingfor--;
					}
					childrenstates[f - 1] = 0;
					busychildren--;
					tofind--;
				}
			} else {	// child -> parent communications failure so kill it
				kill(childrenpids[f - 1], SIGTERM);
				deletechild(childrenpids[f - 1], -1);
				tofind--;
			}
		}
		if (childrenstates[f - 1] == 0) {
			found = true;
		}
	}
	// if unbusy found then true otherwise false
	delete[]buf;
	return found;
}

// remove child from our PID/FD and slot lists
void deletechild(int child_pid, int stat)
{
	int i;
	for (i = 0; i < o.max_children; i++) {
		if (childrenpids[i] == child_pid) {
			childrenpids[i] = -1;
			if (childrenstates[i] == 1) {
				//if (stat == 2) {
					busychildren--;
				/*} else {
					busychildren--;  // should only happen if kid goes screwy
					// child calls _exit with return value of handle_connections,
					// so if it's nonzero, it means there was an error in there somewhere
				}*/
			}
			if (childrenstates[i] != -2) {	// -2 is when its been culled
				numchildren--;  // so no need to duplicater
				delete childsockets[i];
				pids[i + 1].fd = -1;
			}
			childrenstates[i] = -1;  // unused
			break;
		}
	}
	// never should happen that passed pid is not known,
	// unless its the logger or url cache process, in which case we
	// don't want to do anything anyway. and this can only happen
	// when shutting down or restarting.
}

// get the index of the first non-busy child
int getfreechild()
{				// check that there is 1 free done
	// before calling
	int i;
	for (i = 0; i < o.max_children; i++) {
		if (childrenstates[i] == 0) {	// not busy (free)
			return i;
		}
	}
	return -1;
}

// tell given child process to accept an incoming connection
void tellchild_accept(int num)
{
	int fd = pids[num + 1].fd;
	String message = "G\n";
	try {
		childsockets[num]->writeToSockete(message.toCharArray(), message.length(), 0, 5, true);
	} catch(exception & e) {
		kill(childrenpids[num], SIGTERM);
		deletechild(childrenpids[num], -1);
		return;
	}
	char *buf = new char[5];
	try {
		childsockets[num]->getLine(buf, 4, 5, true);
	} catch(exception & e) {
		kill(childrenpids[num], SIGTERM);
		deletechild(childrenpids[num], -1);
		delete[]buf;
		return;
	}

	delete[]buf;  // no need to check as the very fact the child sent
	// something back is a good sign
	busychildren++;
	childrenstates[num] = 1;  // busy
}


// *
// *
// * end of child process handling code
// *
// *


// *
// *
// * logger and URL cache main loops
// *
// *


int log_listener(std::string log_location, int logconerror)
{
#ifdef DGDEBUG
	std::cout << "log listener started" << std::endl;
#endif
	if (!drop_priv_completely()) {
		return 1;  //error
	}
	UDSocket* ipcpeersock;  // the socket which will contain the ipc connection
	int rc, ipcsockfd;
	char *logline = new char[8192];

	ofstream logfile(log_location.c_str(), ios::app);
	if (logfile.fail()) {
		syslog(LOG_ERR, "%s", "Error opening/creating log file.");
#ifdef DGDEBUG
		std::cout << "Error opening/creating log file: " << log_location << std::endl;
#endif
		return 1;  // return with error
	}

	ipcsockfd = ipcsock.getFD();

	fd_set fdSet;  // our set of fds (only 1) that select monitors for us
	fd_set fdcpy;  // select modifes the set so we need to use a copy
	FD_ZERO(&fdSet);  // clear the set
	FD_SET(ipcsockfd, &fdSet);  // add ipcsock to the set

	while (true) {		// loop, essentially, for ever

		fdcpy = fdSet;  // take a copy
		rc = select(ipcsockfd + 1, &fdcpy, NULL, NULL, NULL);  // block
		// until something happens
		if (rc < 0) {	// was an error
			if (errno == EINTR) {
				continue;  // was interupted by a signal so restart
			}
			if (logconerror == 1) {
				syslog(LOG_ERR, "%s", "ipc rc<0. (Ignorable)");
			}
			continue;
		}
		if (rc < 1) {
			if (logconerror == 1) {
				syslog(LOG_ERR, "%s", "ipc rc<0. (Ignorable)");
			}
			continue;
		}
		if (FD_ISSET(ipcsockfd, &fdcpy)) {
#ifdef DGDEBUG
			std::cout << "received a log request" << std::endl;
#endif
			ipcpeersock = ipcsock.accept();
			if (ipcpeersock->getFD() < 0) {
				ipcpeersock->close();
				if (logconerror == 1) {
					syslog(LOG_ERR, "%s", "Error accepting ipc. (Ignorable)");
				}
				continue;  // if the fd of the new socket < 0 there was error
				// but we ignore it as its not a problem
			}
			try {
				rc = ipcpeersock->getLine(logline, 8192, 3, true);  // throws on err
			}
			catch(exception & e) {
				ipcpeersock->close();
				if (logconerror == 1) {
					syslog(LOG_ERR, "%s", "Error reading ipc. (Ignorable)");
				}
				continue;
			}
			logfile << logline << std::endl;  // append the line
#ifdef DGDEBUG
			std::cout << logline << std::endl;
#endif
			ipcpeersock->close();  // close the connection
#ifdef DGDEBUG
			std::cout << "logged" << std::endl;
#endif
			continue;  // go back to listening
		}
		// should never get here
		syslog(LOG_ERR, "%s", "Something wicked has ipc happened");

	}
	delete[]logline;
	logfile.close();  // close the file and
	delete ipcpeersock;  // be nice and neat
	return 1;  // It is only possible to reach here with an error

}

int url_list_listener(int logconerror)
{
#ifdef DGDEBUG
	std::cout << "url listener started" << std::endl;
#endif
	if (!drop_priv_completely()) {
		return 1;  //error
	}
	UDSocket* ipcpeersock;  // the socket which will contain the ipc connection
	int rc, ipcsockfd;
	char *logline = new char[32000];
	String reply;
	DynamicURLList urllist;
#ifdef DGDEBUG
	std::cout << "setting url list size-age:" << o.url_cache_number << "-" << o.url_cache_age << std::endl;
#endif
	urllist.setListSize(o.url_cache_number, o.url_cache_age);
	ipcsockfd = urllistsock.getFD();
#ifdef DGDEBUG
	std::cout << "url ipcsockfd:" << ipcsockfd << std::endl;
#endif

	fd_set fdSet;  // our set of fds (only 1) that select monitors for us
	fd_set fdcpy;  // select modifes the set so we need to use a copy
	FD_ZERO(&fdSet);  // clear the set
	FD_SET(ipcsockfd, &fdSet);  // add ipcsock to the set

#ifdef DGDEBUG
	std::cout << "url listener entering select()" << std::endl;
#endif
	while (true) {		// loop, essentially, for ever

		fdcpy = fdSet;  // take a copy

		rc = select(ipcsockfd + 1, &fdcpy, NULL, NULL, NULL);  // block
		// until something happens
#ifdef DGDEBUG
		std::cout << "url listener select returned" << std::endl;
#endif
		if (rc < 0) {	// was an error
			if (errno == EINTR) {
				continue;  // was interupted by a signal so restart
			}
			if (logconerror == 1) {
				syslog(LOG_ERR, "%s", "url ipc rc<0. (Ignorable)");
			}
			continue;
		}
		if (FD_ISSET(ipcsockfd, &fdcpy)) {
#ifdef DGDEBUG
			std::cout << "received an url request" << std::endl;
#endif
			ipcpeersock = urllistsock.accept();
			if (ipcpeersock->getFD() < 0) {
				ipcpeersock->close();
				if (logconerror == 1) {
#ifdef DGDEBUG
					std::cout << "Error accepting url ipc. (Ignorable)" << std::endl;
#endif
					syslog(LOG_ERR, "%s", "Error accepting url ipc. (Ignorable)");
				}
				continue;  // if the fd of the new socket < 0 there was error
				// but we ignore it as its not a problem
			}
			try {
				rc = ipcpeersock->getLine(logline, 32000, 3, true);  // throws on err
			}
			catch(exception & e) {
				ipcpeersock->close();  // close the connection
				if (logconerror == 1) {
#ifdef DGDEBUG
					std::cout << "Error reading ip ipc. (Ignorable)" << std::endl;
					std::cerr << e.what() << std::endl;
#endif
					syslog(LOG_ERR, "%s", "Error reading ip ipc. (Ignorable)");
					syslog(LOG_ERR, "%s", e.what());
				}
				continue;
			}
			if (logline[0] == 'F' && logline[1] == ' ') {
				ipcpeersock->close();  // close the connection
				urllist.flush();
#ifdef DGDEBUG
				std::cout << "url FLUSH request" << std::endl;
#endif
				continue;
			}
			if (logline[0] == 'A' && logline[1] == ' ') {
				ipcpeersock->close();  // close the connection
				urllist.addEntry(logline + 2);
#ifdef DGDEBUG
				std::cout << "url add request:" << logline << std::endl;
#endif
				continue;
			}
#ifdef DGDEBUG
			std::cout << "url search request:" << logline << std::endl;
#endif
			if (urllist.inURLList(logline)) {
				reply = "Y\n";
			} else {
				reply = "N\n";
			}
			try {
				ipcpeersock->writeString(reply.toCharArray());
			}
			catch(exception & e) {
				ipcpeersock->close();  // close the connection
				if (logconerror == 1) {
					syslog(LOG_ERR, "%s", "Error writing url ipc. (Ignorable)");
					syslog(LOG_ERR, "%s", e.what());
				}
				continue;
			}
			ipcpeersock->close();  // close the connection
#ifdef DGDEBUG
			std::cout << "url list reply:" << reply << std::endl;
#endif
			continue;  // go back to listening
		}
	}
	delete[]logline;
	delete ipcpeersock;
	urllistsock.close();  // be nice and neat
	return 1;  // It is only possible to reach here with an error
}


// *
// *
// * end logger and URL cache code
// *
// *


// Does lots and lots of things - forks off url cache & logger processes, preforks child processes for connection handling, does tidying up on exit
// also handles the various signalling options DG supports (reload config, flush cache, kill all processes etc.)
int fc_controlit()
{
	o.lm.garbageCollect();

	serversock.reset();
	if (o.no_logger == 0) {
		ipcsock.reset();
	} else {
		ipcsock.close();
	}
	urllistsock.reset();

	pid_t loggerpid = 0;  // to hold the logging process pid
	pid_t urllistpid = 0;  // to hold the logging process pid (zero to stop warning)
	int rc, serversockfd, fds;

	serversockfd = serversock.getFD();

	if (serversockfd < 0) {
		if (!is_daemonised) {
			std::cerr << "Error creating server socket" << std::endl;
		}
		syslog(LOG_ERR, "%s", "Error creating server socket");
		return 1;  // if the socket fd is not +ve then the socket
		// creation failed
	}

	if (o.no_logger == 0) {
		if (ipcsock.getFD() < 0) {
			if (!is_daemonised) {
				std::cerr << "Error creating ipc socket" << std::endl;
			}
			syslog(LOG_ERR, "%s", "Error creating ipc socket");
			return 1; 
		}
	}

	// Made unconditional such that we have root privs when creating pidfile & deleting old IPC sockets
	// PRA 10-10-2005
	/*bool needdrop = false;

	if (o.filter_port < 1024) {*/
#ifdef DGDEBUG
		std::cout << "seteuiding for low port binding/pidfile creation" << std::endl;
#endif
		//needdrop = true;
#ifdef HAVE_SETREUID
		rc = setreuid((uid_t) - 1, o.root_user);
#else
		rc = seteuid(o.root_user);
#endif
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

	if (o.filter_ip.length() > 6) {	// filter ip specified in conf
		// listen/bind to a port and ip
		if (serversock.bind(o.filter_ip, o.filter_port)) {
			if (!is_daemonised) {
				std::cerr << "Error binding server socket (is something else running on the filter port and ip? [" << o.filter_port << " " << o.filter_ip << "])" << std::endl;
			}
			syslog(LOG_ERR, "%s", "Error binding server socket (is something else running on the filter port and ip?");
			return 1;
		}
	} else {		// listen/bind to a port
		if (serversock.bind(o.filter_port)) {
			if (!is_daemonised) {
				std::cerr << "Error binding server socket (is something else running on the filter port? [" << o.filter_port << "])" << std::endl;
			}
			syslog(LOG_ERR, "%s", "Error binding server socket (is something else running on the filter port?");
			return 1;
		}
	}

	// Made unconditional for same reasons as above
	//if (needdrop) {
#ifdef HAVE_SETREUID
		rc = setreuid((uid_t) - 1, o.proxy_user);
#else
		rc = seteuid(o.proxy_user);  // become low priv again
#endif
		if (rc == -1) {
			syslog(LOG_ERR, "%s", "Unable to re-seteuid()");
#ifdef DGDEBUG
			std::cerr << "Unable to re-seteuid()" << std::endl;
#endif
			return 1;  // seteuid failed for some reason so exit with error
		}
	//}

	// Needs deleting if its there
	rc = unlink(o.ipc_filename.c_str());  // this would normally be in a -r situation.
// disabled as requested by Christopher Weimann <csw@k12hq.com>
// Fri, 11 Feb 2005 15:42:28 -0500
// re-enabled temporarily

	// Needs deleting if its there
	rc = unlink(o.urlipc_filename.c_str());  // this would normally be in a -r situation.

	if (o.no_logger == 0) {
		if (ipcsock.bind((char *) o.ipc_filename.c_str())) {	// bind to file
			if (!is_daemonised) {
				std::cerr << "Error binding ipc server file (try using the SysV to stop DansGuardian then try starting it again or doing an 'rm " << o.ipc_filename << "')." << std::endl;
			}
			syslog(LOG_ERR, "%s", "Error binding ipc server file (try using the SysV to stop DansGuardian then try starting it again or doing an 'rm /tmp/.dguardianipc' or whatever you have it configured to).");
			return 1;
		}
	}

	if (o.url_cache_number > 0) {
		if (urllistsock.bind((char *) o.urlipc_filename.c_str())) {	// bind to file
			if (!is_daemonised) {
				std::cerr << "Error binding urllistsock server file (try using the SysV to stop DansGuardian then try starting it again or doing an 'rm " << o.urlipc_filename << "')." << std::endl;
			}
			syslog(LOG_ERR, "%s", "Error binding urllistsock server file (try using the SysV to stop DansGuardian then try starting it again or doing an 'rm /tmp/.dguardianurlipc' or whatever you have it configured to).");
			return 1;
		}
	}


	if (serversock.listen(256)) {	// set it to listen mode with a kernel
		// queue of 256 backlog connections
		if (!is_daemonised) {
			std::cerr << "Error listening to server socket" << std::endl;
		}
		syslog(LOG_ERR, "%s", "Error listening to server socket");
		return 1;
	}
	if (o.no_logger == 0) {
		if (ipcsock.listen(256)) {	// set it to listen mode with a kernel
			// queue of 256 backlog connections
			if (!is_daemonised) {
				std::cerr << "Error listening to ipc server file" << std::endl;
			}
			syslog(LOG_ERR, "%s", "Error listening to ipc server file");
			return 1;
		}
	}

	if (o.url_cache_number > 0) {
		if (urllistsock.listen(256)) {	// set it to listen mode with a kernel
			// queue of 256 backlog connections
			if (!is_daemonised) {
				std::cerr << "Error listening to url ipc server file" << std::endl;
			}
			syslog(LOG_ERR, "%s", "Error listening to url ipc server file");
			return 1;
		}
	}

	if (!daemonise()) {	// become a detached daemon
		if (!is_daemonised) {
			std::cerr << "Error daemonising" << std::endl;
		}
		syslog(LOG_ERR, "%s", "Error daemonising");
		return 1;
	}

	// this has to be done after daemonise to ensure we get the correct PID.
	rc = sysv_writepidfile(pidfilefd);  // also closes the fd
	if (rc != 0) {
		syslog(LOG_ERR, "Error writing to the dansguardian.pid file: %s", strerror(errno));
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

	// Next thing we need to do is to split into two processes - one to
	// handle incoming TCP connections from the clients and one to handle
	// incoming UDS ipc from our forked children.  This helps reduce
	// bottlenecks by not having only one select() loop.

	if (o.no_logger == 0) {

		loggerpid = fork();  // make a child processes copy of self to be logger

		if (loggerpid == 0) {	// ma ma!  i am the child
			serversock.close();  // we don't need our copy of this so close it
			urllistsock.close();  // we don't need our copy of this so close it
			log_listener(o.log_location, o.logconerror);
#ifdef DGDEBUG
			std::cout << "Log listener exiting" << std::endl;
#endif
			_exit(0);  // is reccomended for child and daemons to use this instead
		}
	}

	if (o.url_cache_number > 0) {
		urllistpid = fork();  // make a child processes copy of self to be logger

		if (urllistpid == 0) {	// ma ma!  i am the child
			serversock.close();  // we don't need our copy of this so close it
			if (o.no_logger == 0) {
				ipcsock.close();  // we don't need our copy of this so close it
			}

			url_list_listener(o.logconerror);
#ifdef DGDEBUG
			std::cout << "URL List listener exiting" << std::endl;
#endif
			_exit(0);  // is reccomended for child and daemons to use this instead
		}
	}
	// I am the parent process here onwards.

#ifdef DGDEBUG
	std::cout << "Parent process created children" << std::endl;
#endif


	if (o.url_cache_number > 0) {
		urllistsock.close();  // we don't need our copy of this so close it
	}
	if (o.no_logger == 0) {
		ipcsock.close();  // we don't need our copy of this so close it
	}

	memset(&sa, 0, sizeof(sa));
	if (o.soft_restart == 0) {
		sa.sa_handler = &sig_term;  // register sig_term as our handler
	} else {
		sa.sa_handler = &sig_termsafe;
	}
	if (sigaction(SIGTERM, &sa, NULL)) {	// when the parent process gets a
		// sigterm we need to kill our
		// children which this will do,
		// then we need to exit
		syslog(LOG_ERR, "%s", "Error registering SIGTERM handler");
		return (1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &sig_hup;  // register sig_hup as our handler
	if (sigaction(SIGHUP, &sa, NULL)) {	// when the parent process gets a
		// sighup we need to kill our
		// children which this will do,
		// then we need to read config
		syslog(LOG_ERR, "%s", "Error registering SIGHUP handler");
		return (1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &sig_usr1;  // register sig_usr1 as our handler
	if (sigaction(SIGUSR1, &sa, NULL)) {	// when the parent process gets a
		// sigusr1 we need to hup our
		// children to make them exit
		// then we need to read fg config
		syslog(LOG_ERR, "%s", "Error registering SIGUSR handler");
		return (1);
	}
#ifdef DGDEBUG
	std::cout << "Parent process sig handlers done" << std::endl;
#endif

	struct timeval quicksleep;  // used later on for a short sleep
	quicksleep.tv_sec = 0;
	quicksleep.tv_usec = 10000;  // = 10ms = 0.01sec
	struct timeval qscopy;  // copy to use as select() can modify

	numchildren = 0;  // to keep count of our children
	busychildren = 0;  // to keep count of our children
	freechildren = 0;  // to keep count of our children

	childrenpids = new int[o.max_children];  // so when one exits we know who
	childrenstates = new int[o.max_children];  // so we know what they're up to
	childsockets = new UDSocket* [o.max_children];
	fds = o.max_children + 1;

	pids = new struct pollfd[fds];

	int i;

	time_t tnow;
	time_t tmaxspare;

	time(&tmaxspare);

#ifdef DGDEBUG
	std::cout << "Parent process pid structs allocated" << std::endl;
#endif

	for (i = 0; i < o.max_children; i++) {
		childrenpids[i] = -1;
		childrenstates[i] = -1;
		pids[i + 1].fd = -1;
		pids[i + 1].events = POLLIN;

	}
	pids[0].fd = serversockfd;
	pids[0].events = POLLIN;

#ifdef DGDEBUG
	std::cout << "Parent process pid structs zeroed" << std::endl;
#endif

	failurecount = 0;  // as we don't exit on an error with select()
	// due to the fact that these errors do happen
	// every so often on a fully working, but busy
	// system, we just watch for too many errors
	// consecutivly.

	waitingfor = 0;
	rc = prefork(o.min_children);

	sleep(1);  // need to allow some of the forks to complete

#ifdef DGDEBUG
	std::cout << "Parent process preforked rc:" << rc << std::endl;
	std::cout << "Parent process pid:" << getpid() << std::endl;
#endif

	if (rc < 0) {
		ttg = true;
		syslog(LOG_ERR, "%s", "Error creating initial fork pool - exiting...");
	}

	bool preforked = true;
	int tofind;
	reloadconfig = false;

	while (failurecount < 30 && !ttg && !reloadconfig) {

		// loop, essentially, for ever until 30
		// consecutive errors in which case something
		// is badly wrong.
		// OR, its timetogo - got a sigterm
		// OR, we need to exit to reread config
		if (gentlereload) {
#ifdef DGDEBUG
			cout << "gentle reload activated" << endl;
#endif
			o.deleteFilterGroups();
			if (!o.readFilterGroupConf()) {
				reloadconfig = true;  // filter groups problem so lets
				// try and reload entire config instead
				// if that fails it will bomb out
			} else {
				o.filter_groups_list.reset();
				if (!o.doReadItemList(o.filter_groups_list_location.c_str(),&(o.filter_groups_list),"filtergroupslist",true)) {
					reloadconfig = true;  // filter groups problem...
				} else {
					o.deleteCSPlugins();
					if (!o.loadCSPlugins()) {
						reloadconfig = true;  // content scan plugs problem
					} else {
						o.lm.garbageCollect();
						hup_allchildren();
						prefork(o.min_children);
						gentlereload = false;
					}
				}
			}
			flush_urlcache();
			continue;
		}

		// Lets take the opportunity to clean up our dead children if any
		for (i = 0; i <= o.max_children; i++) {
			pids[i].revents = 0;
		}
		mopup_afterkids();
		rc = poll(pids, fds, 60 * 1000);
		mopup_afterkids();

		if (rc < 0) {	// was an error
#ifdef DGDEBUG
			std::cout << "errno:" << errno << " " << strerror(errno) << std::endl;
#endif

			if (errno == EINTR) {
				continue;  // was interupted by a signal so restart
			}
			failurecount++;  // log the error/failure
			continue;  // then continue with the looping
		}

		tofind = rc;
		if (rc > 0) {
			if ((pids[0].revents & POLLIN) > 0) {
				tofind--;
			}
		}

		if (tofind > 0) {
			if (check_kid_readystatus(tofind)) {
				preforked = false;  // we are no longer waiting last prefork
			}
		}

		freechildren = numchildren - busychildren;

#ifdef DGDEBUG
		std::cout << "numchildren:" << numchildren << std::endl;
		std::cout << "busychildren:" << busychildren << std::endl;
		std::cout << "freechildren:" << freechildren << std::endl;
		std::cout << "waitingfor:" << waitingfor << std::endl << std::endl;
#endif

		if (rc > 0) {
			if ((pids[0].revents & (POLLERR | POLLHUP | POLLNVAL)) > 0) {
				ttg = true;
				syslog(LOG_ERR, "%s", "Error with main listening socket.  Exiting.");
				continue;
			}
			if ((pids[0].revents & POLLIN) > 0) {
				// socket ready to accept() a connection
				failurecount = 0;  // something is clearly working so reset count
				if (freechildren < 1 && numchildren < o.max_children) {
					if (!preforked) {
						rc = prefork(1);
						if (rc < 0) {
							syslog(LOG_ERR, "%s", "Error forking 1 extra process.");
							failurecount++;
						}
						preforked = true;
					}
					qscopy = quicksleep;  // use copy as select() can modify it
					select(0, NULL, NULL, NULL, &qscopy);  // is a very quick sleep()
					continue;
				}
				if (freechildren > 0) {
					tellchild_accept(getfreechild());
				} else {
					qscopy = quicksleep;  // use copy as select() can modify it
					select(0, NULL, NULL, NULL, &qscopy);  // is a very quick sleep()
				}
			}
		}

		if (freechildren < o.minspare_children && !preforked && numchildren < o.max_children) {
			rc = prefork(o.prefork_children);
			preforked = true;
			if (rc < 0) {
				syslog(LOG_ERR, "%s", "Error forking preforkchildren extra processes.");
				failurecount++;
			}
		}

		if (freechildren <= o.maxspare_children) {
			time(&tmaxspare);
		}
		if (freechildren > o.maxspare_children) {
			time(&tnow);
			if ((tnow - tmaxspare) > (2 * 60)) {	// 2 * 60
				cullchildren(freechildren - o.maxspare_children);
			}
		}

	}
	cullchildren(numchildren);  // remove the fork pool of spare children
	for (int i = 0; i < o.max_children; i++) {
		if (pids[i + 1].fd != -1) {
			delete childsockets[i];
		}
	}
	if (numchildren > 0) {
		hup_allchildren();
		sleep(2);  // give them a small chance to exit nicely before we force
		// hmmmm I wonder if sleep() will get interupted by sigchlds?
	}
	if (numchildren > 0) {
		kill_allchildren();
	}
	// we might not giving enough time for defuncts to be created and then
	// mopped but on exit or reload config they'll get mopped up
	sleep(1);
	mopup_afterkids();

	delete[]childrenpids;
	delete[]childrenstates;
	delete[]childsockets;
	delete[]pids;  // 4 deletes good, memory leaks bad

	if (failurecount >= 30) {
		syslog(LOG_ERR, "%s", "Exiting due to high failure count.");
#ifdef DGDEBUG
		std::cout << "Exiting due to high failure count." << std::endl;
#endif
	}
#ifdef DGDEBUG
	std::cout << "Main parent process exiting." << std::endl;
#endif
	serversock.close();  // be nice and neat
	if (o.url_cache_number > 0) {
		urllistsock.close();
	}

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

	if (sig_term_killall) {
		struct sigaction sa, oldsa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = SIG_IGN;
		sigaction(SIGTERM, &sa, &oldsa);  // ignore sigterm for us
		kill(0, SIGTERM);  // send everyone in this process group a TERM
		// which causes them to exit as the default action
		// but it also seems to send itself a TERM
		// so we ignore it
		sigaction(SIGTERM, &oldsa, NULL);  // restore prev state
	}

	if (reloadconfig) {
		if (o.no_logger == 0) {
			::kill(loggerpid, SIGTERM);  // get rid of logger
		}
		if (o.url_cache_number > 0) {
			::kill(urllistpid, SIGTERM);  // get rid of url cache
		}
		return 2;
	}
	if (ttg) {
		if (o.no_logger == 0) {
			::kill(loggerpid, SIGTERM);  // get rid of logger
		}
		if (o.url_cache_number > 0) {
			::kill(urllistpid, SIGTERM);  // get rid of url cache
		}
		return 0;
	}
	if (o.logconerror == 1) {
		syslog(LOG_ERR, "%s", "Main parent process exiting.");
	}
	return 1;  // It is only possible to reach here with an error
}
