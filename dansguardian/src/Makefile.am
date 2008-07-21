AUTOMAKE_OPTIONS = subdir-objects

clean_SUBDIRS= . downloadmanagers contentscanners authplugins

# A MASSIVE thank you to Lawrence Manning for pointing out the
# -export-dynamic option was needed to solve a long problem
# which stopped DG2.9 from actually running ever.
# Daniel Barron Fri 18th March 2005

# Unfortunately, since it was never made to work on anything
# other than Linux, libtool support has been removed in favour
# of configure-time options (at DB's request).

if HAVE_CLAMAV
CLAMAV_SOURCE = contentscanners/clamav.cpp
else
CLAMAV_SOURCE =
endif

#if HAVE_KAVCLIENT
#KAVAV_SOURCES = contentscanners/kavav.cpp
#else
#KAVAV_SOURCES =
#endif

if ENABLE_CLAMD
CLAMDSCAN_SOURCE = contentscanners/clamdscan.cpp
else
CLAMDSCAN_SOURCE =
endif

if ENABLE_ICAP
ICAPSCAN_SOURCE = contentscanners/icapscan.cpp
else
ICAPSCAN_SOURCE =
endif

if ENABLE_KAVD
KAVDSCAN_SOURCE = contentscanners/kavdscan.cpp
else
KAVDSCAN_SOURCE =
endif

if ENABLE_COMMANDLINE
COMMANDLINE_SOURCE = contentscanners/commandlinescan.cpp
else
COMMANDLINE_SOURCE =
endif

DEFAULTDM_SOURCE = downloadmanagers/default.cpp

if ENABLE_FANCYDM
FANCYDM_SOURCE = downloadmanagers/fancy.cpp
else
FANCYDM_SOURCE =
endif

if ENABLE_TRICKLEDM
TRICKLEDM_SOURCE = downloadmanagers/trickle.cpp
else
TRICKLEDM_SOURCE =
endif

PROXYAUTH_SOURCE = authplugins/proxy.cpp
IDENTAUTH_SOURCE = authplugins/ident.cpp
IPAUTH_SOURCE = authplugins/ip.cpp
DIGESTAUTH_SOURCE = authplugins/digest.cpp

if ENABLE_NTLM
NTLMAUTH_SOURCE = authplugins/ntlm.cpp
else
NTLMAUTH_SOURCE =
endif

if WIN32
UDSOCKET_SOURCE =
SYSV_SOURCE =
REPLACEMENT_SOURCE = ../lib/ctime_r.cpp ../lib/inet_aton.cpp ../lib/strerror_r.cpp ../lib/mkstemp.cpp ../lib/localtime_r.cpp ../lib/syslog.cpp
else
UDSOCKET_SOURCE = UDSocket.cpp
SYSV_SOURCE = SysV.cpp
REPLACEMENT_SOURCE =
endif

sbin_PROGRAMS = dansguardian 

dansguardian_CXXFLAGS = $(PCRE_CFLAGS) $(PTHREAD_CFLAGS) $(AM_CXXFLAGS)
dansguardian_LDFLAGS = $(PTHREAD_LIBS) $(AM_LDFLAGS)
dansguardian_LDADD = $(LIBOBJS) $(PCRE_LIBS) $(PTHREAD_LIBS) $(AM_LIBS)
dansguardian_CPPFLAGS = -D__CONFFILE='"$(DGCONFFILE)"' \
			-D__LOGLOCATION='"$(DGLOGLOCATION)/"' \
			-D__PIDDIR='"$(DGPIDDIR)"' \
			-D__PROXYUSER='"$(DGPROXYUSER)"' \
			-D__PROXYGROUP='"$(DGPROXYGROUP)"' \
			-D__CONFDIR='"$(DGCONFDIR)"' \
			$(AM_CPPFLAGS)
dansguardian_SOURCES = String.cpp \
                       FDTunnel.cpp \
                       ConnectionHandler.cpp \
                       DataBuffer.cpp \
                       HTTPHeader.cpp \
                       NaughtyFilter.cpp \
                       RegExp.cpp \
		       FDFuncs.cpp \
		       BaseSocket.cpp \
                       Socket.cpp \
                       FatController.cpp \
                       $(UDSOCKET_SOURCE) \
                       $(SYSV_SOURCE) \
                       ListContainer.cpp \
                       Auth.cpp \
                       HTMLTemplate.cpp \
                       LanguageContainer.cpp \
                       DynamicURLList.cpp \
		       DynamicIPList.cpp \
                       ImageContainer.cpp \
		       IPList.cpp \
                       OptionContainer.cpp \
                       FOptionContainer.cpp \
                       ListManager.cpp \
                       md5.cpp \
                       DownloadManager.cpp \
                       ConfigVar.cpp \
                       ContentScanner.cpp \
		       SocketArray.cpp \
                       dansguardian.cpp \
		       $(CLAMAV_SOURCE) $(ICAPSCAN_SOURCE) \
		       $(KAVDSCAN_SOURCE) $(CLAMDSCAN_SOURCE) \
		       $(COMMANDLINE_SOURCE) \
		       $(DEFAULTDM_SOURCE) $(FANCYDM_SOURCE) \
		       $(TRICKLEDM_SOURCE) $(PROXYAUTH_SOURCE) \
		       $(IDENTAUTH_SOURCE) $(IPAUTH_SOURCE) \
		       $(NTLMAUTH_SOURCE) $(DIGESTAUTH_SOURCE) \
		       $(REPLACEMENT_SOURCE)
