// Base socket class - inherit this to implement UNIX/INET domain sockets

//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.

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
#include <fcntl.h>
#include <sys/time.h>
#include <cerrno>
#include <unistd.h>
#include <stdexcept>
#include <iostream>

#ifdef WIN32
#include "../lib/syslog.h"
#else
#include <syslog.h>
#endif

#ifndef WIN32
#include <sys/select.h>
#else
#include <winsock2.h>
#endif

#ifndef HAVE_STRERROR_R
#include "../lib/strerror_r.h"
#endif

#ifdef DGDEBUG
#include <iostream>
#endif

#include "BaseSocket.hpp"

// GLOBALS
extern bool reloadconfig;


// DEFINITIONS

#define dgtimercmp(a, b, cmp) \
	(((a)->tv_sec == (b)->tv_sec) ? ((a)->tv_usec cmp (b)->tv_usec) : ((a)->tv_sec cmp (b)->tv_sec))

#define dgtimersub(a, b, result) \
	(result)->tv_sec = (a)->tv_sec - (b)->tv_sec; \
	(result)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
	if ((result)->tv_usec < 0) { \
		(result)->tv_sec--; \
		(result)->tv_usec += 1000000; \
	}


// IMPLEMENTATION

// a wrapper for select so that it auto-restarts after an SOCKET_EINTR.
// can be instructed to watch out for signal triggered config reloads.
int selectEINTR(std::set<SOCKET> *readfds, std::set<SOCKET> *writefds, std::set<SOCKET> *exceptfds, struct timeval *timeout, bool honour_reloadconfig)
{
	int rc;
	// Fix for OSes that do not explicitly modify select()'s timeout value
	// from Soner Tari <list@kulustur.org> (namely OpenBSD)
	// Modified to use custom code in preference to timersub/timercmp etc.
	// to avoid that particular portability nightmare.
	timeval entrytime;
	timeval exittime;
	timeval elapsedtime;
	timeval timeoutcopy;
	std::set<SOCKET> orig_readfds, orig_writefds, orig_exceptfds;
	
	// find highest FD for passing into select
	SOCKET numfds = 0;
	if (readfds) {
		for (std::set<SOCKET>::const_iterator i = readfds->begin(); i != readfds->end(); ++i)
			if ((*i) > numfds)
				numfds = *i;
		orig_readfds = *readfds;
		readfds->clear();
	}
	if (writefds) {
		for (std::set<SOCKET>::const_iterator i = writefds->begin(); i != writefds->end(); ++i)
			if ((*i) > numfds)
				numfds = *i;
		orig_writefds = *writefds;
		writefds->clear();
	}
	if (exceptfds) {
		for (std::set<SOCKET>::const_iterator i = exceptfds->begin(); i != exceptfds->end(); ++i)
			if ((*i) > numfds)
				numfds = *i;
		orig_exceptfds = *exceptfds;
		exceptfds->clear();
	}
	++numfds;

	while (true) {
		// Build up actual fdsets from the integer sets we've been given
		// All because an fd_set is an opaque structure on Windows....
		fd_set readset, writeset, exceptset;
		if (readfds) {
			FD_ZERO(&readset);
			for (std::set<SOCKET>::const_iterator i = orig_readfds.begin(); i != orig_readfds.end(); ++i)
				FD_SET(*i, &readset);
		}
		if (writefds) {
			FD_ZERO(&writeset);
			for (std::set<SOCKET>::const_iterator i = orig_writefds.begin(); i != orig_writefds.end(); ++i)
				FD_SET(*i, &writeset);
		}
		if (exceptfds) {
			FD_ZERO(&exceptset);
			for (std::set<SOCKET>::const_iterator i = orig_exceptfds.begin(); i != orig_exceptfds.end(); ++i)
				FD_SET(*i, &exceptset);
		}
			
		if (timeout != NULL) {
			gettimeofday(&entrytime, NULL);
			timeoutcopy = *timeout;
			rc = select(numfds, (readfds ? &readset : NULL), (writefds ? &writeset : NULL), (exceptfds ? &exceptset : NULL), &timeoutcopy);
			// explicitly modify the timeout if the OS hasn't done this for us
			if (timeoutcopy.tv_sec == timeout->tv_sec && timeoutcopy.tv_usec == timeout->tv_usec) {
				gettimeofday(&exittime, NULL);
				// calculate time spent sleeping this iteration
				dgtimersub(&exittime, &entrytime, &elapsedtime);
				// did we wait longer than/as long as was left?
				if (!dgtimercmp(timeout, &elapsedtime, <)) {
					// no - reduce the amount that is left
					dgtimersub(timeout, &elapsedtime, timeout);
				} else {
					// yes - we've timed out, so exit
					timeout->tv_sec = timeout->tv_usec = 0;
					break;
				}
			} else {
				// if the OS has modified the timeout for us,
				// propogate the change back to the caller
				*timeout = timeoutcopy;
			}
		} else
			rc = select(numfds, (readfds ? &readset : NULL), (writefds ? &writeset : NULL), (exceptfds ? &exceptset : NULL), NULL);
#ifdef WIN32
		if (rc == SOCKET_ERROR) {
#else
		if (rc < 0) {
#endif
			if (socket_errno == SOCKET_EINTR && (honour_reloadconfig? !reloadconfig : true)) {
				continue;  // was interupted by a signal so restart
			}
		}
		else if (rc > 0) {
			if (readfds) {
				for (std::set<SOCKET>::const_iterator i = orig_readfds.begin(); i != orig_readfds.end(); ++i)
					if (FD_ISSET(*i, &readset))
							readfds->insert(*i);
			}
			if (writefds) {
				for (std::set<SOCKET>::const_iterator i = orig_writefds.begin(); i != orig_writefds.end(); ++i)
					if (FD_ISSET(*i, &writeset))
							writefds->insert(*i);
			}
			if (exceptfds) {
				for (std::set<SOCKET>::const_iterator i = orig_exceptfds.begin(); i != orig_exceptfds.end(); ++i)
					if (FD_ISSET(*i, &exceptset))
							exceptfds->insert(*i);
			}
		}
		break;  // end the while
	}
	return rc;  // return status
}

// This class contains client and server socket init and handling
// code as well as functions for testing and working with the socket FDs.

// constructor - override this if desired to create an actual socket at startup
BaseSocket::BaseSocket():timeout(5), sck(0), sckinuse(false), buffstart(0), bufflen(0)
{}

// create socket from FD - must be overridden to clear the relevant address structs
BaseSocket::BaseSocket(SOCKET fd):timeout(5), sck(fd), sckinuse(true), buffstart(0), bufflen(0)
{
}

// destructor - close socket
BaseSocket::~BaseSocket()
{
	// close fd if socket not used
	if (sckinuse) {
#ifndef WIN32
		::close(sck);
#else
		closesocket(sck);
#endif
	}
}

// reset - close socket & reset timeout.
// call this in derived classes' reset() method, which should also clear address structs
void BaseSocket::baseReset()
{
	if (sckinuse) {
#ifndef WIN32
		::close(sck);
#else
		closesocket(sck);
#endif
		sckinuse = false;
	}
	timeout = 5;
	buffstart = 0;
	bufflen = 0;
}

// mark a socket as a listening server socket
int BaseSocket::listen(int queue)
{
	return ::listen(sck, queue);
}

#ifndef WIN32
// "template adaptor" for accept - basically, let G++ do the hard work of
// figuring out the type of the third parameter ;)
template <typename T>
inline int local_accept_adaptor (int (*accept_func)(int, struct sockaddr*, T),
	int sck, struct sockaddr *acc_adr, socklen_t *acc_adr_length)
{
  return accept_func (sck, acc_adr, (T) acc_adr_length);
}
#endif

// receive an incoming connection & return FD
// call this in accept methods of derived classes, which should pass in empty sockaddr & socklen_t to be filled out
SOCKET BaseSocket::baseAccept(struct sockaddr *acc_adr, socklen_t *acc_adr_length)
{	

#ifndef WIN32
	// OS X defines accept as:
	// int accept(int s, struct sockaddr *addr, int *addrlen);
	// but everyone else as:
	// int accept(int s, struct sockaddr *addr, socklen_t *addrlen);
	// NB: except 10.4, which seems to use the more standard definition. grrr.
	return local_accept_adaptor(::accept, sck, acc_adr, acc_adr_length);
#else
	// However the above doesn't work for Windows - possibly some interaction
	// with templates and SOCKET being a macro, but regardless, it doesn't like
	// the type of accept() on Windows.
	return ::accept(sck, acc_adr, acc_adr_length);
#endif
}

// return socket's FD - please use sparingly and DO NOT do manual data transfer using it
SOCKET BaseSocket::getFD()
{
	return sck;
}

// close the socket
void BaseSocket::close()
{
	if (sckinuse) {
#ifndef WIN32
		::close(sck);
#else
		closesocket(sck);
#endif
		sckinuse = false;
	}
	buffstart = 0;
	bufflen = 0;
}

// set the socket-wide timeout
void BaseSocket::setTimeout(int t)
{
	timeout = t;
}

// return timeout
int BaseSocket::getTimeout()
{
	return timeout;
}

// non-blocking check to see if there is data waiting on socket
bool BaseSocket::checkForInput()
{
	if ((bufflen - buffstart) > 0)
		return true;
	timeval t;  // timeval struct
	t.tv_sec = 0;
	t.tv_usec = 0;
	std::set<SOCKET> fdSet;
	fdSet.insert(sck);
	if (selectEINTR(&fdSet, NULL, NULL, &t) < 1) {
		return false;
	}
	return true;
}

// blocking check for waiting data - blocks for up to given timeout, can be told to break on signal-triggered config reloads
void BaseSocket::checkForInput(int timeout, bool honour_reloadconfig) throw(std::exception)
{
	if ((bufflen - buffstart) > 0)
		return;
	// blocks if socket blocking
	// until timeout
	timeval t;  // timeval struct
	t.tv_sec = timeout;
	t.tv_usec = 0;
	int rc;
	std::set<SOCKET> fdSet;
	fdSet.insert(sck);
	if ((rc = selectEINTR(&fdSet, NULL, NULL, &t, honour_reloadconfig)) < 1) {
		int sockopterr;
		socklen_t sl = sizeof(int);
		getsockopt(sck, SOL_SOCKET, SO_ERROR, (SOCKOPT) &sockopterr, &sl);
		char errstr[1024];
		syslog(LOG_ERR, "select() on input: getsockopt %d, select rc %d, socket errno %d, %s", sockopterr, rc, socket_errno, strerror_r(socket_errno, errstr, 1024));
		std::string err("select() on input: ");
		throw std::runtime_error(err + (socket_errno ? errstr : "unknown/timeout"));
	}
}

// non-blocking check to see if a socket is ready to be written
bool BaseSocket::readyForOutput()
{
	timeval t;  // timeval struct
	t.tv_sec = 0;
	t.tv_usec = 0;
	std::set<SOCKET> fdSet;
	fdSet.insert(sck);
	if (selectEINTR(NULL, &fdSet, NULL, &t) < 1) {
		return false;
	}
	return true;
}

// blocking equivalent of above, can be told to break on signal-triggered reloads
void BaseSocket::readyForOutput(int timeout, bool honour_reloadconfig) throw(std::exception)
{
	// blocks if socket blocking
	// until timeout
	timeval t;  // timeval struct
	t.tv_sec = timeout;
	t.tv_usec = 0;
	std::set<SOCKET> fdSet;
	fdSet.insert(sck);
	if (selectEINTR(NULL, &fdSet, NULL, &t, honour_reloadconfig) < 1) {
		std::string err("select() on output: ");
		char errstr[1024];
		throw std::runtime_error(err + (socket_errno ? strerror_r(socket_errno, errstr, 1024) : "timeout"));
	}
}

// read a line from the socket, can be told to break on config reloads
int BaseSocket::getLine(char *buff, int size, int timeout, bool honour_reloadconfig, bool *chopped) throw(std::exception)
{
	// first, return what's left from the previous buffer read, if anything
	int i = 0;
	if ((bufflen - buffstart) > 0) {
/*#ifdef DGDEBUG
		std::cout << "data already in buffer; bufflen: " << bufflen << " buffstart: " << buffstart << std::endl;
#endif*/
		int tocopy = size;
		if ((bufflen - buffstart) < size)
			tocopy = bufflen - buffstart;
		char* result = (char*)memccpy(buff, buffer + buffstart, '\n', tocopy);
		if (result != NULL) {
			// indicate that a newline was chopped off, if desired
			if (chopped)
				*chopped = true;
			*(--result) = '\0';
			buffstart += (result - buff) + 1;
			return result - buff;
		} else {
			i += tocopy;
		}
	}
	while (i < (size - 1)) {
		buffstart = 0;
		bufflen = 0;
		try {
			checkForInput(timeout, honour_reloadconfig);
		} catch(std::exception & e) {
			char errstr[1024];
			throw std::runtime_error(std::string("Can't read from socket: ") + strerror_r(socket_errno, errstr, 1024));  // on error
		}
		bufflen = recv(sck, buffer, 1024, 0);
#ifdef DGDEBUG
		std::cout << "read into buffer; bufflen: " << bufflen << std::endl;
#endif
		if (bufflen < 0) {
			if (socket_errno == SOCKET_EINTR && (honour_reloadconfig ? !reloadconfig : true)) {
				continue;
			}
			char errstr[1024];
			throw std::runtime_error(std::string("Can't read from socket: ") + strerror_r(socket_errno, errstr, 1024));  // on error
		}
		//if socket closed or newline received...
		if (bufflen == 0) {
			buff[i] = '\0';  // ...terminate string & return what read
			return i;
		}
		int tocopy = bufflen;
		if ((i + bufflen) > (size-1))
			tocopy = (size-1) - i;
		char* result = (char*)memccpy(buff+i, buffer, '\n', tocopy);
		if (result != NULL) {
			// indicate that a newline was chopped off, if desired
			if (chopped)
				*chopped = true;
			*(--result) = '\0';
			buffstart += (result - (buff+i)) + 1;
			return i + (result - (buff+i));
		}
		i += tocopy;
	}
	// oh dear - buffer end reached before we found a newline
	buff[i] = '\0';
	return i;
}

// write line to socket
void BaseSocket::writeString(const char *line) throw(std::exception)
{
	int l = strlen(line);
	if (!writeToSocket(line, l, 0, timeout)) {
		char errstr[1024];
		throw std::runtime_error(std::string("Can't write to socket: ") + strerror_r(socket_errno, errstr, 1024));
	}
}

// write data to socket - throws exception on failure, can be told to break on config reloads
void BaseSocket::writeToSockete(const char *buff, int len, unsigned int flags, int timeout, bool honour_reloadconfig) throw(std::exception)
{
	if (!writeToSocket(buff, len, flags, timeout, honour_reloadconfig)) {
		char errstr[1024];
		throw std::runtime_error(std::string("Can't write to socket: ") + strerror_r(socket_errno, errstr, 1024));
	}
}

// write data to socket - can be told not to do an initial readyForOutput, and to break on config reloads
bool BaseSocket::writeToSocket(const char *buff, int len, unsigned int flags, int timeout, bool check_first, bool honour_reloadconfig)
{
	int actuallysent = 0;
	int sent;
	while (actuallysent < len) {
		if (check_first) {
			try {
				readyForOutput(timeout, honour_reloadconfig);  // throws exception on error or timeout
			}
			catch(std::exception & e) {
				return false;
			}
		}
		sent = send(sck, buff + actuallysent, len - actuallysent, 0);
		if (sent < 0) {
			if (socket_errno == SOCKET_EINTR && (honour_reloadconfig ? !reloadconfig : true)) {
				continue;  // was interupted by signal so restart
			}
			return false;
		}
		if (sent == 0) {
			return false;  // other end is closed
		}
		actuallysent += sent;
	}
	return true;
}

// read a specified expected amount and return what actually read
int BaseSocket::readFromSocketn(char *buff, int len, unsigned int flags, int timeout)
{
	int cnt, rc;
	cnt = len;
	
	// first, return what's left from the previous buffer read, if anything
	if ((bufflen - buffstart) > 0) {
/*#ifdef DGDEBUG
		std::cout << "readFromSocketn: data already in buffer; bufflen: " << bufflen << " buffstart: " << buffstart << std::endl;
#endif*/
		int tocopy = len;
		if ((bufflen - buffstart) < len)
			tocopy = bufflen - buffstart;
		memcpy(buff, buffer + buffstart, tocopy);
		cnt -= tocopy;
		buffstart += tocopy;
		buff += tocopy;
		if (cnt == 0)
			return len;
	}
	
	while (cnt > 0) {
		try {
			checkForInput(timeout);  // throws exception on error or timeout
		}
		catch(std::exception & e) {
			return -1;
		}
		rc = recv(sck, buff, cnt, flags);
		if (rc < 0) {
			if (socket_errno == SOCKET_EINTR) {
				continue;
			}
			return -1;
		}
		if (rc == 0) {	// eof
			return len - cnt;
		}
		buff += rc;
		cnt -= rc;
	}
	return len;
}

// read what's available and return error status - can be told not to do an initial checkForInput, and to break on reloads
int BaseSocket::readFromSocket(char *buff, int len, unsigned int flags, int timeout, bool check_first, bool honour_reloadconfig)
{
	// first, return what's left from the previous buffer read, if anything
	int cnt = len;
	int tocopy = 0;
	if ((bufflen - buffstart) > 0) {
/*#ifdef DGDEBUG
		std::cout << "readFromSocket: data already in buffer; bufflen: " << bufflen << " buffstart: " << buffstart << std::endl;
#endif*/
		tocopy = len;
		if ((bufflen - buffstart) < len)
			tocopy = bufflen - buffstart;
		memcpy(buff, buffer + buffstart, tocopy);
		cnt -= tocopy;
		buffstart += tocopy;
		buff += tocopy;
		if (cnt == 0)
			return len;
	}
	
	int rc;
	if (check_first) {
		try {
			checkForInput(timeout, honour_reloadconfig);
		} catch(std::exception & e) {
			return -1;
		}
	}
	while (true) {
		rc = recv(sck, buff, cnt, flags);
		if (rc < 0) {
			if (socket_errno == SOCKET_EINTR && (honour_reloadconfig ? !reloadconfig : true)) {
				continue;
			}
		}
		break;
	}
	return rc + tocopy;
}
