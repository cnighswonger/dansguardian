//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.
//Written by Daniel Barron (daniel@//jadeb.com).
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

//This file contains modifications suggested and mostly provided by
//Daniel Robbins 13/4/01 drobbins@gento.org
//Modifications include, but not limited to, getcontenttype(), << , >>


// INCLUDES

#include "HTTPHeader.hpp"
#include "DataBuffer.hpp"
#include "Socket.hpp"

#include <unistd.h>
#include <sys/socket.h>
#include <exception>
#include <time.h>
#include <syslog.h>
#include <cerrno>
#include <zlib.h>


// GLOBALS
extern RegExp urldecode_re;


// IMPLEMENTATION

// set timeout for socket operations
void HTTPHeader::setTimeout(int t)
{
	timeout = t;
}

// *
// *
// * header value and type checks
// *
// *

// grab request type (GET, HEAD etc.)
String HTTPHeader::requestType()
{
	return header[0].before(" ");
}

// grab content length
int HTTPHeader::contentLength()
{
	String temp;
	for (int i = 0; i < (signed) header.size(); i++) {	// check each line in
		// the header
		if (header[i].startsWith("Content-Length:")) {
			temp = header[i].after(" ");
			return temp.toInteger();
		}
	}
	return 0;  // it finds the length of the POST data
}

// check the request's return code to see if it's an auth required message
bool HTTPHeader::authRequired()
{
	String temp = header[0].after(" ");
	if (temp.contains(" ")) {
		temp = temp.before(" ");
	}
	if (temp.startsWith("407")) {
		return true;
	}
	return false;
}

// grab content disposition
String HTTPHeader::disposition()
{
	String filename;
	for (int i = 0; i < (signed) header.size(); i++) {	// check each line in
		// the header
		if (header[i].startsWith("Content-Disposition:")) {
			filename = header[i].after(";").after("=");
			filename.removeWhiteSpace();  // incase of trailing space
			if (filename.contains("\"")) {
				return header[i].after(";").after("\"").before("\"");
			}
			return filename;
			// example format:
			// Content-Disposition: attachment; filename="filename.ext"
			// Content-Disposition: attachment; filename=filename.ext
		}
	}
	return "";  // it finds the header proposed filename
}

// grab the user agent
String HTTPHeader::userAgent()
{
	String agent;
	for (int i = 0; i < (signed) header.size(); i++) {
		if (header[i].startsWith("User-Agent:")) {
			agent = header[i].after(" ");
			return agent;
		}
	}
	return agent;
}

// grab the content type header
String HTTPHeader::getContentType()
{
	String mimetype;
	int j;
	unsigned char c;
	for (int i = 0; i < (signed) header.size(); i++) {
		if (header[i].startsWith("Content-Type:")) {
			mimetype = header[i].after(" ");
			j = 0;
			while (j < (signed) mimetype.length()) {
				c = mimetype[j];
				if (c == ' ' || c == ';' || c < 32) {	// remove the
					mimetype = mimetype.subString(0, j);
					// extra info not needed
					j = 0;
				}
				j++;
			}
			break;
		}
	}
	mimetype.toLower();
	if (mimetype.length() < 1) {
		mimetype = "-";
	}
	return mimetype;
}

// does the given content type string match our headers?
bool HTTPHeader::isContentType(String t)
{
	return getContentType().startsWith(t);
}

// grab contents of X-Forwarded-For header
// Modification based on a submitted patch by
// Jimmy Myrick (jmyrick@tiger1.tiger.org)
std::string HTTPHeader::getXForwardedForIP()
{
	String line;
	for (int i = 0; i < (signed) header.size(); i++) {
		if (header[i].startsWith("X-Forwarded-For:")) {
			line = header[i].after("or: ");
			break;
		}
	}
	line.chop();
	return std::string(line.toCharArray());
}

// check the return code to see if it's a redirection request
bool HTTPHeader::isRedirection()
{
	// The 1st line of the header for a redirection is thus:
	// HTTP/1.(0|1) 3xx
	if (header.size() < 1) {
		return false;
	}			// sometimes get called b 4 read
	String answer = header[0].after(" ").before(" ");
	if (answer[0] == '3' && answer.length() == 3) {
		return true;
	}
	return false;
}

// If basic authentication is enabled DG is able to decode the username
// and password from the header - however we are only interested in the
// username

// grab the username from a decoded basic auth header
std::string HTTPHeader::getAuthUser()
{
	String t = getAuth();
	t = t.before(":");
	t.toLower();
	return std::string(t.toCharArray());
}

// grab the contents of the Proxy-Authorization header, and if using
// basic auth, base64 decode the username & password.
String HTTPHeader::getAuth()
{
	String line;
	for (int i = 0; i < (signed) header.size(); i++) {
		if (header[i].startsWith("Proxy-Authorization: Basic ")
		    || header[i].startsWith("Proxy-Authorization: basic ")) {
			line = header[i].after("asic ");
			line = decodeb64(line).c_str();  // its base64 MIME encoded
			break;
		}
	}
	return line;
}

// do we have a non-identity content encoding? this means body is compressed
bool HTTPHeader::isCompressed()
{
	for (int i = 0; i < (signed) header.size(); i++) {
		if (header[i].startsWith("Content-Encoding:")) {
			if (header[i].indexOf("identity") != -1) {
				// http1.1 says this
				// should not be here, but not must not
				return false;
			}
#ifdef DGDEBUG
			std::cout << "is compressed" << std::endl;
#endif
			return true;  // i.e. encoded with something other than clear
		}
	}
	return false;
}

// grab content encoding header
String HTTPHeader::contentEncoding()
{
	String ce;
	for (int i = 0; i < (signed) header.size(); i++) {
		if (header[i].startsWith("Content-Encoding:")) {
			ce = header[i].after("Content-Encoding: ");
			ce.toLower();
			return ce;
		}
	}
	return "";  // we need a default don't we?
}

// *
// *
// * header modifications
// *
// *

// squid adds this so if more support it it may be useful one day
void HTTPHeader::addXForwardedFor(std::string clientip)
{
	std::string line = "X-Forwarded-For: " + clientip + "\r";
	header.push_back(String(line.c_str()));
}

// return a modified accept-encoding header, based on the one supplied,
// but with "identity" added and only supported encodings allowed.
String HTTPHeader::modifyEncodings(String e)
{

	// There are 4 types of encoding: gzip, deflate, compress and identity
	// deflate is in zlib format
	// compress is in unix compress format
	// identity is uncompressed and supported by all browsers (obviously)
	// we do not support compress

	e.toLower();
	String o = "Accept-Encoding: identity";
#if ZLIB_VERNUM < 0x1210
#warning 'Accept-Encoding: gzip' is disabled
#else
	if (e.contains("gzip")) {
		o += ",gzip";
	}
#endif
	if (e.contains("deflate")) {
		o += ",deflate";
	}

	return o;
}

// set content length to report the given length, and strip content encoding
void HTTPHeader::removeEncoding(int newlen)
{
	for (int i = 0; i < (signed) header.size(); i++) {
		if (header[i].startsWith("Content-Length:")) {
			header[i] = "Content-Length: " + String(newlen);
		}
		if (header[i].startsWith("Content-Encoding:")) {
			header[i] = "X-DansGuardian-Removed: Content-Encoding";
		}
	}
}

// set content length header to report given lenth
void HTTPHeader::setContentLength(int newlen)
{
	for (int i = 0; i < (signed) header.size(); i++) {
		if (header[i].startsWith("Content-Length:")) {
			header[i] = "Content-Length: " + String(newlen);
		}
	}
}

// *
// *
// * detailed header checks & fixes
// *
// *

// is a URL malformed?
bool HTTPHeader::malformedURL(String url)
{
	String host = url.after("://");
	if (host.contains("/")) {
		host = host.before("/");
	}
	if (host.length() < 2) {
#ifdef DGDEBUG
		std::cout << "host len to small" << std::endl;
#endif
		return true;
	}
	if (host.contains("..") || host.endsWith(".")) {
#ifdef DGDEBUG
		std::cout << "double dots or ending dots" << std::endl;
#endif
		return true;
	}
	int i, len;
	unsigned char c;
	len = host.length();
	for (i = 0; i < len; i++) {
		c = (unsigned char) host[i];
		if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z')
		    && !(c >= '0' && c <= '9') && c != '.' && c != '-' && c != '_') {
#ifdef DGDEBUG
			std::cout << "bad char in hostname" << std::endl;
#endif
			return true;
			// only allowed letters, digits, hiphen, dots
		}

	}
	return false;
}

// is this a POST request encapsulating a file upload?
bool HTTPHeader::isPostUpload()
{
	if (header[0].before(" ") != "POST") {
		return false;
	}
	bool answer = false;
	int postlen = postdata.buffer_length;
	int i;
	if (postlen < 14) {	// min length for there to be a match
		return false;
	}
	char *postdatablock = new char[postlen + 64];  // extra 64 for search
	try {
		postdata.copyToMemory(postdatablock);
		for (i = 0; i < postlen; i++) {	// make lowercase char by char
			if (isupper(postdatablock[i])) {
				postdatablock[i] = tolower(postdatablock[i]);
			}
		}
		RegExp mysearch;
		std::string dis = "content-type: ";  // signifies file upload
		char *p = new char[32];
		try {
			for (i = 0; i < (signed) dis.length(); i++) {
				p[i] = dis[i];  // copy it to the block of memory
			}
			char *pend = p + dis.length();  // pointer for search
			char *postdatablockend = postdatablock + postlen;
			// search the post data for the content type header
			char *res = mysearch.search(postdatablock, postdatablockend, p, pend);
			// if we searched all the way to the end without finding it,
			// there is no post upload going on; otherwise, there is
			if (res != postdatablockend) {
				answer = true;
			}
		}
		catch(exception & e) {
		};
		delete[]p;
	}
	catch(exception & e) {
	};
	delete[]postdatablock;
	return answer;
}

// fix bugs in certain web servers that don't obey standards
void HTTPHeader::checkheader()
{
	for (int i = 0; i < (signed) header.size(); i++) {	// check each line in
		// the header
		if (header[i].startsWith("Content-length:")) {
			header[i] = "Content-Length:" + header[i].after("Content-length:");
		}
		else if (header[i].startsWith("x-forwarded-for:")) {
			header[i] = "X-Forwarded-For:" + header[i].after("x-forwarded-for:");
		}
		else if (header[i].startsWith("Content-type:")) {
			header[i] = "Content-Type:" + header[i].after("Content-type:");
		}
		else if (header[i].startsWith("Content-disposition:")) {
			header[i] = "Content-Disposition:" + header[i].after("Content-disposition:");
		}
		else if (header[i].startsWith("Content-encoding:")) {
			header[i] = "Content-Encoding:" + header[i].after("Content-encoding:");
		}
		else if (header[i].startsWith("Accept-encoding:")) {
			header[i] = "Accept-Encoding:" + header[i].after("Accept-encoding:");
			header[i] = modifyEncodings(header[i]) + "\r";
		}
		else if (header[i].startsWith("Accept-Encoding:")) {
			header[i] = modifyEncodings(header[i]) + "\r";
		}
		// Need to force HTTP/1.1 clients and servers to use non persistant connections
		else if (header[i].startsWith("Connection: keep-alive")) {
			//header[i] = "Connection: Keep-Alive" + header[i].after("Connection: keep-alive");
			header[i] = "Connection: Close\r";
		}
		else if (header[i].startsWith("Connection: Keep-Alive")) {
			header[i] = "Connection: Close\r";// ditto
		}
		else if (header[i].startsWith("Proxy-Connection: Keep-Alive")) {
			header[i] = "Proxy-Connection: Close\r";
		}
		else if (header[i].startsWith("Proxy-Connection: keep-alive")) {
			//header[i] = "Proxy-Connection: Keep-Alive" + header[i].after("Proxy-Connection: keep-alive");
			header[i] = "Proxy-Connection: Close\r";
		}
		else if (header[i].startsWith("Proxy-authorization:")) {
			header[i] = "Proxy-Authorization:" + header[i].after("Proxy-authorization:");
		}
#ifdef DGDEBUG
		std::cout << header[i] << std::endl;
#endif
	}
}

// A request may be in the form:
//  GET http://foo.bar:80/ HTML/1.0 (if :80 is omitted 80 is assumed)
// or:
//  GET / HTML/1.0
//  Host: foo.bar (optional header in HTTP/1.0, but like HTTP/1.1, we require it!)
//  Port: 80 (not a standard header; do any clients send it?)
// or:
//  CONNECT foo.bar:443  HTTP/1.1
// So we need to handle all 3

String HTTPHeader::url()
{
	port = 0;
	String hostname;
	String answer = header[0].after(" ");
	answer.removeMultiChar(' ');
	if (answer.after(" ").startsWith("HTTP/")) {
		answer = answer.before(" HTTP/");
	} else {
		answer = answer.before(" http/");  // just in case!
	}
//cout << answer << endl;
	if (requestType() == "CONNECT") {
		if (!answer.startsWith("https://")) {
			answer = "https://" + answer;
		}
	}
//cout << answer << endl;
	if (answer.length()) {
		int i;
		if (answer[0] == '/') {	// must be the latter above
			for (i = 1; i < (signed) header.size(); i++) {
				if (header[i].startsWith("Host:")) {
					hostname = header[i].after(":");
					hostname.removeMultiChar(' ');
					if (hostname.contains(":")) {
						hostname = hostname.before(":");  // chop off the port bit but it should never be there
					}
					hostname.removeWhiteSpace();  // remove rubbish like
					// ^M and blanks
					hostname = "http://" + hostname;
					answer = hostname + answer;
					if (port > 0) {
						break;  // need to keep parsing to get port
					}
				}
				else if (header[i].startsWith("Port:")) {
					port = header[i].after(" ").toInteger();
					if (port == 0 || port > 65535) {
						port = 80;
					}
				}
			}
		} else {	// must be in the form GET http://foo.bar:80/ HTML/1.0
			if (!answer.after("://").contains("/")) {
				answer += "/";  // needed later on so correct host is extracted
			}
			String protocol = answer.before("://");
			hostname = answer.after("://");
			String url = hostname.after("/");
			url.removeWhiteSpace();  // remove rubbish like ^M and blanks
			if (url.length() > 0) {
				url = "/" + url;
			}
			hostname = hostname.before("/");  // extra / was added 4 here
			if (hostname.contains("@")) {	// Contains a username:password combo
				hostname = hostname.after("@");
			}
			if (hostname.contains(":")) {
				port = hostname.after(":").toInteger();
				if (port == 0 || port > 65535) {
					port = 80;
				}
				hostname = hostname.before(":");  // chop off the port bit
			}
			answer = protocol + "://" + hostname + url;
		}
	}
	if (answer.endsWith("//")) {
		answer.chop();
	}
#ifdef DGDEBUG
	std::cout << "from header url:" << answer << std::endl;
#endif
	return answer;
}

// *
// *
// * Bypass URL/Cookie funcs
// *
// *

// chop the GBYPASS variable out of a bypass URL
// This function ASSUMES that you really know what you are doing
// Do NOT run this function unless you know that the URL contains a valid bypass code
// Ernest W Lessenger
void HTTPHeader::chopBypass(String url)
{
	if (url.contains("GBYPASS=")) {
		if (url.contains("?GBYPASS=")) {
			String bypass = url.after("?GBYPASS=");
			header[0] = header[0].before("?GBYPASS=") + header[0].after(bypass.toCharArray());
		} else {
			String bypass = url.after("&GBYPASS=");
			header[0] = header[0].before("&GBYPASS=") + header[0].after(bypass.toCharArray());
		}
	}
}

// same for scan bypass
void HTTPHeader::chopScanBypass(String url)
{
	if (url.contains("GSBYPASS=")) {
		if (url.contains("?GSBYPASS=")) {
			String bypass = url.after("?GSBYPASS=");
			header[0] = header[0].before("?GSBYPASS=") + header[0].after(bypass.toCharArray());
		} else {
			String bypass = url.after("&GSBYPASS=");
			header[0] = header[0].before("&GSBYPASS=") + header[0].after(bypass.toCharArray());
		}
	}
}

// I'm not proud of this... --Ernest
String HTTPHeader::getCookie(const char *cookie)
{
	String line;
	for (int i = 0; i < (signed) header.size(); i++) {
		if (header[i].startsWith("Cookie:")) {
			line = header[i].after("ie: ");
			if (line.contains(cookie)) {	// We know we have the cookie
				line = line.after(cookie);
				line.lop();  // Get rid of the '='
				if (line.contains(";")) {
					line = line.before(";");
				}
			}
			// break;  // Technically there should be only one Cookie: header, but...
		}
	}
	line.removeWhiteSpace();
#ifdef DGDEBUG
	std::cout << "Found GBYPASS cookie:" << line << std::endl;
#endif
	return line;
}

// add cookie with given name & value to outgoing headers
void HTTPHeader::setCookie(const char *cookie, const char *value)
{
	String line = "Set-Cookie: ";
	line += cookie;
	line += "=";
	line += value;
	line += "; path=/\r";
	header.push_back(line);
#ifdef DGDEBUG
	std::cout << "Setting cookie:" << line << std::endl;
#endif
	// no expiry specified so ends with the browser session
}

// is this a temporary filter bypass cookie?
bool HTTPHeader::isBypassCookie(String * url, const char *magic, const char *clientip)
{
	String cookie = getCookie("GBYPASS");
	String cookiehash = cookie.subString(0, 32);
	String cookietime = cookie.after(cookiehash.toCharArray());
	String mymagic = magic;
	mymagic += clientip;
	mymagic += cookietime;
	String hashed = (*url).md5(mymagic.toCharArray());
	if (hashed != cookiehash) {
#ifdef DGDEBUG
		std::cout << "Cookie GBYPASS not match" << std::endl;
#endif
		return false;
	}
	time_t timen = time(NULL);
	time_t timeu = cookietime.toLong();
	if (timeu < timen) {
#ifdef DGDEBUG
		std::cout << "Cookie GBYPASS expired" << std::endl;
#endif
		return false;
	}
	return true;
}

// is this a temporary filter bypass URL?
int HTTPHeader::isBypassURL(String * url, const char *magic, const char *clientip)
{
	if ((*url).length() <= 45)
		return false;  // Too short, can't be a bypass

	if (!(*url).contains("GBYPASS=")) {	// If this is not a bypass url
		return 0;
	}
#ifdef DGDEBUG
	std::cout << "URL GBYPASS found checking..." << std::endl;
#endif

	String url_left = (*url).before("GBYPASS=");
	url_left.chop();  // remove the ? or &
	String url_right = (*url).after("GBYPASS=");

	String url_hash = url_right.subString(0, 32);
	String url_time = url_right.after(url_hash.toCharArray());
#ifdef DGDEBUG
	std::cout << "URL: " << url_left << ", HASH: " << url_hash << "TIME: " << url_time << std::endl;
#endif

	String mymagic = magic;
	mymagic += clientip;
	mymagic += url_time;
	String hashed = url_left.md5(mymagic.toCharArray());

	if (hashed != url_hash) {
		return 0;
	}

	time_t timen = time(NULL);
	time_t timeu = url_time.toLong();

	if (timeu < 1) {
#ifdef DGDEBUG
		std::cout << "URL GBYPASS bad time value" << std::endl;
#endif
		return 1;  // bad time value
	}
	if (timeu < timen) {	// expired key
#ifdef DGDEBUG
		std::cout << "URL GBYPASS expired" << std::endl;
#endif
		return 1;  // denotes expired but there
	}
#ifdef DGDEBUG
	std::cout << "URL GBYPASS not expired" << std::endl;
#endif

	return (int) timeu;
}

// is this a scan bypass URL? i.e. a "magic" URL for retrieving a previously scanned file
bool HTTPHeader::isScanBypassURL(String * url, const char *magic, const char *clientip)
{
	if ((*url).length() <= 45)
		return false;  // Too short, can't be a bypass

	if (!(*url).contains("GSBYPASS=")) {	// If this is not a bypass url
		return false;
	}
#ifdef DGDEBUG
	std::cout << "URL GSBYPASS found checking..." << std::endl;
#endif

	String url_left = (*url).before("GSBYPASS=");
	url_left.chop();  // remove the ? or &
	String url_right = (*url).after("GSBYPASS=");

	String url_hash = url_right.subString(0, 32);
#ifdef DGDEBUG
	std::cout << "URL: " << url_left << ", HASH: " << url_hash << std::endl;
#endif

	// format is:
	// GSBYPASS=hash(ip+url+tempfilename+mime+disposition+secret)
	// &N=tempfilename&M=mimetype&D=dispos

	String tempfilename = url_right.after("&N=");
	String tempfilemime = tempfilename.after("&M=");
	String tempfiledis = tempfilemime.after("&D=");
	tempfilemime = tempfilemime.before("&D=");
	tempfilename = tempfilename.before("&M=");

	String tohash = clientip + url_left + tempfilename + tempfilemime + tempfiledis + magic;
	String hashed = tohash.md5();

	if (hashed == url_hash) {
		return true;
	}
#ifdef DGDEBUG
	std::cout << "URL GSBYPASS HASH mismatch" << std::endl;
#endif

	return false;
}

// *
// *
// * URL and Base64 decoding funcs
// *
// *

// URL decoding (%xx)
// uses regex pre-compiled on startup
String HTTPHeader::decode(String s)
{
	if (s.length() < 3) {
		return s;
	}
#ifdef DGDEBUG
	std::cout << "decoding url" << std::endl;
#endif
	if (!urldecode_re.match(s.toCharArray())) {
		return s;
	}			// exit if not found
#ifdef DGDEBUG
	std::cout << "matches:" << urldecode_re.numberOfMatches() << std::endl;
	std::cout << "removing %XX" << std::endl;
#endif
	int match;
	int offset;
	int pos = 0;
	int size = s.length();
	String result;
	String n;
	for (match = 0; match < urldecode_re.numberOfMatches(); match++) {
		offset = urldecode_re.offset(match);
		if (offset > pos) {
			result += s.subString(pos, offset - pos);
		}
		n = urldecode_re.result(match).c_str();
		n.lop();  // remove %
		result += hexToChar(n);
		pos = offset + 3;
	}
	if (size > pos) {
		result += s.subString(pos, size - pos);
	} else {
		n = "%" + n;
	}
	return result;
}

// turn %xx back into original character
String HTTPHeader::hexToChar(String n)
{
	if (n.length() < 2) {
		return n;
	}
	char *buf = new char[2];
	unsigned int a, b;
	unsigned char c;
	a = n[0];
	b = n[1];
	if (a >= 'a' && a <= 'f') {
		a -= 87;
	}
	else if (a >= 'A' && a <= 'F') {
		a -= 55;
	}
	else if (a >= '0' && a <= '9') {
		a -= 48;
	}
	if (b >= 'a' && b <= 'f') {
		b -= 87;
	}
	else if (b >= 'A' && b <= 'F') {
		b -= 55;
	}
	else if (b >= '0' && b <= '9') {
		b -= 48;
	}
	c = a * 16 + b;
	if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	    || (c >= '0' && c <= '9') || (c == '-')) {
		buf[0] = c;
		buf[1] = '\0';
		n = buf;
	} else {
		n = "%" + n;
	}
	return n;
}

// decode a line of base64
std::string HTTPHeader::decodeb64(String line)
{				// decode a block of b64 MIME
	long four = 0;
	int d;
	std::string result = "";
	int len = line.length() - 4;
	for (int i = 0; i < len; i += 4) {
		four = 0;
		d = decode1b64(line[i + 0]);
		four = four | d;
		d = decode1b64(line[i + 1]);
		four = (four << 6) | d;
		d = decode1b64(line[i + 2]);
		four = (four << 6) | d;
		d = decode1b64(line[i + 3]);
		four = (four << 6) | d;
		d = (four & 0xFF0000) >> 16;
		result += (char) d;
		d = (four & 0xFF00) >> 8;
		result += (char) d;
		d = four & 0xFF;
		result += (char) d;
	}
	return result;
}

// decode an individual base64 character
int HTTPHeader::decode1b64(char c)
{
	unsigned char i = '\0';
	switch (c) {
	case '+':
		i = 62;
		break;
	case '/':
		i = 63;
		break;
	case '=':
		i = 0;
		break;
	default:		// must be A-Z, a-z or 0-9
		i = '9' - c;
		if (i > 0x3F) {	// under 9
			i = 'Z' - c;
			if (i > 0x3F) {	// over Z
				i = 'z' - c;
				if (i > 0x3F) {	// over z so invalid
					i = 0x80;  // so set the high bit
				} else {
					// a-z
					i = c - 71;
				}
			} else {
				// A-Z
				i = c - 65;
			}
		} else {
			// 0-9
			i = c + 4;
		}
		break;
	}
	return (int) i;
}

// *
// *
// * network send/receive funcs
// *
// *

void HTTPHeader::out(Socket * sock, int sendflag) throw(exception)
{
	String l;  // for amalgamating to avoid conflict with the Nagel algorithm

	if (sendflag == __DGHEADER_SENDALL || sendflag == __DGHEADER_SENDFIRSTLINE) {
		if (header.size() > 0) {
			l = header[0] + "\n";
#ifdef DGDEBUG
			std::cout << "headertoclient:" << l << std::endl;
#endif
			if (!(*sock).writeToSocket(l.toCharArray(), l.length(), 0, timeout)) {
				throw exception();
			}
		}
		if (sendflag == __DGHEADER_SENDFIRSTLINE) {
			return;
		}
	}

	l = "";

	for (int i = 1; i < (signed) header.size(); i++) {
		l += header[i] + "\n";
	}
	l += "\r\n";

#ifdef DGDEBUG
	std::cout << "headertoclient:" << l << std::endl;
#endif

	// send header to the output stream
	// need exception for bad write

	if (!(*sock).writeToSocket(l.toCharArray(), l.length(), 0, timeout)) {
		throw exception();
	}

	if (postdata.buffer_length > 0) {
		postdata.out(sock);
	}
}

void HTTPHeader::in(Socket * sock)
{
	// the RFCs don't specify a max header line length so this should be
	// dynamic really.  Pointed out (well reminded actually) by Daniel Robbins
	char buff[8192];  // setup a buffer to hold the incomming HTTP line
	String line;  // temp store to hold the line after processing
	line = "----";  // so we get past the first while
	while (line.length() > 3) {	// loop until the stream is
		// failed or we get to the end of the header (a line by itself)

		(*sock).getLine(buff, 8192, timeout);  // get a line of header from the stream

		// getline will throw an exception if there is an error which will
		// only be caught by HandleConnection()


		line = buff;  // convert the line to a String

		header.push_back(line);  // stick the line in the deque that
		// holds the header
	}
	header.pop_back();  // remove the final blank line of a header

	checkheader();  // sort out a few bits in the header

	int length;
	String requestMethod = header[0].before(" ");
	if (!requestMethod.contains("/") && (length = contentLength()) > 0) {
		// if it's a request (not reply) with content, grab the data and store it
		postdata.read(sock, length);  // get the DataBuffer to read the data
	}
}
