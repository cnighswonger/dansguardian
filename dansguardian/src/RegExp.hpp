// RegExp class - search text using regular expressions

//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.
//Written by Daniel Barron (daniel@// jadeb.com).
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

#ifndef __HPP_REGEXP
#define __HPP_REGEXP


// INCLUDES

#include <sys/types.h>		// needed for size_t used in regex.h

#ifdef HAVE_PCRE
#include <pcreposix.h>
#else
#include <regex.h>
#endif

#include <string>
#include <vector>


// DECLARATIONS

class RegExp
{
public:
	// constructor - set sensible defaults
	RegExp();
	// destructor - delete regexp if compiled
	~RegExp();
	// copy constructor
	RegExp(const RegExp & r);
	
	// compile the given regular expression
	bool comp(const char *exp);
	// match the given text against the pre-compiled expression
	bool match(const char *text, std::vector<std::string> *results = NULL, std::vector<unsigned int> *offsets = NULL, std::vector<unsigned int> *lengths = NULL);
	

private:
	// the expression itself
	regex_t reg;
	// whether it's been pre-compiled
	bool wascompiled;
	
	// the uncompiled form of the expression (checkme: is this only used
	// for debugging purposes?)
	std::string searchstring;
};
	
// faster equivalent of STL::Search
char *fsearch(char *file, char *fileend, char *phrase, char *phraseend);

#endif
