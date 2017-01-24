// Windows user identification auth plugin 

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


// There is a distinct lack of "#ifdef WIN32" in the below for one reason:
// this plugin is only compiled if the platform is detected as Windows to
// begin with, so portability isn't our biggest concern.


// INCLUDES
#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif

#include "../Auth.hpp"

#include "../../lib/syslog.h"

#include "windows.h"
#include "iphlpapi.h"
#include "winsock2.h"
#include "ws2tcpip.h"


// DECLARATIONS

// class name is relevant!
class winuserinstance:public AuthPlugin
{
public:
	winuserinstance(ConfigVar &definition):AuthPlugin(definition) {};
	int identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, std::string &string);
};


// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

AuthPlugin *winusercreate(ConfigVar & definition)
{
	return new winuserinstance(definition);
}

// end of Class factory

// Use arcane black magic to identify Windows username from connection details
int winuserinstance::identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, std::string &string)
{
	// Look up the client's connection in the extended TCP table.
	// We can't predict how much memory we will need for this,
	// so call it with none and allocate however much it says
	// it's going to require (repeat until success).
	MIB_TCPTABLE_OWNER_PID *tcptable = NULL;
	DWORD tcptablesize = 0;
	DWORD err;
	while ((err = GetExtendedTcpTable(tcptable, &tcptablesize, false, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0)) == ERROR_INSUFFICIENT_BUFFER)
	{
		free(tcptable);
		tcptable = (MIB_TCPTABLE_OWNER_PID *) malloc(tcptablesize);
	}
	if (err != NO_ERROR)
	{
		syslog(LOG_ERR, "GetExtendedTcpTable fail: %d", err);
		return -1;
	}
	
	// Go looking for our client connection, so we can get its PID.
	for (DWORD i = 0; i < tcptable->dwNumEntries; ++i)
	{
		MIB_TCPROW_OWNER_PID *j = &(tcptable->table[i]);
		if ((j->dwState == MIB_TCP_STATE_ESTAB)
			&& (ntohs(j->dwRemotePort) == peercon.getLocalPort())
			&& (ntohs(j->dwLocalPort) == peercon.getPeerSourcePort())
			&& (j->dwRemoteAddr == inet_addr("127.0.0.1")))
		{
			// Now look up the owner of this connection's owning PID
			HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, false, j->dwOwningPid);
			if (process == NULL)
			{
				free(tcptable);
				syslog(LOG_ERR, "OpenProcess fail");
				return -2;
			}
			HANDLE token;
			if (OpenProcessToken(process, TOKEN_READ, &token) == 0)
			{
				free(tcptable);
				CloseHandle(process);
				syslog(LOG_ERR, "OpenProcessToken fail");
				return -3;
			}
			TOKEN_USER *tokenuser = NULL;
			DWORD tokenusersize = 0;
			while (GetTokenInformation(token, TokenUser, (LPVOID) tokenuser, tokenusersize, &tokenusersize) == 0)
			{
				if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
				{
					free(tcptable);
					CloseHandle(token);
					CloseHandle(process);
					syslog(LOG_ERR, "GetTokenInformation fail");
					return -4;
				}
				free(tokenuser);
				tokenuser = (TOKEN_USER *) malloc(tokenusersize);
			}
			char username[1024];
			char domain[1024];
			DWORD usernamesize = 1024;
			DWORD domainsize = 1024;
			SID_NAME_USE dummy;
			if (LookupAccountSid(NULL, tokenuser->User.Sid, username, &usernamesize, domain, &domainsize, &dummy) == 0)
			{
				free(tokenuser);
				free(tcptable);
				CloseHandle(token);
				CloseHandle(process);
				syslog(LOG_ERR, "LookupAccountSid fail");
				return -5;
			}

			free(tokenuser);
			free(tcptable);
			CloseHandle(token);
			CloseHandle(process);

			string.assign(username);
			return DGAUTH_OK;
		}
	}

	syslog(LOG_ERR, "No matching connection was found.");
	free(tcptable);
	return -6;
}
