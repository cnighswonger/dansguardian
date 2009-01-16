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

#ifndef __HPP_NAUGHTYFILTER
#define __HPP_NAUGHTYFILTER


// INCLUDES

#include "String.hpp"
#include "OptionContainer.hpp"


// DECLARATIONS

class NaughtyFilter
{
public:
	// should the content be blocked?
	bool isItNaughty;
	// should the content bypass any further filtering?
	bool isException;
	// should the browser use the categories string or the displaycategories string?
	// (related to category list thresholding)
	bool usedisplaycats;

	// the reason for banning, what to say about it in the logs, and the
	// categories under which banning has taken place
	std::string whatIsNaughty;
	std::string whatIsNaughtyLog;
	std::string whatIsNaughtyCategories;
	std::string whatIsNaughtyDisplayCategories;

	NaughtyFilter();
	void reset();
	void checkme(const char *rawbody, off_t rawbodylen, const String *url, const String *domain,
		unsigned int filtergroup, unsigned int phraselist, bool searchterms = false);
	
	// highest positive (or lowest negative) weighting out of
	// both phrase filtering passes (smart/raw)
	int naughtiness;

private:
	// check the banned, weighted & exception lists
	// pass in both URL & domain to activate embedded URL checking
	// (this is made optional in this manner because it's pointless
	// trying to look for links etc. in "smart" filtering mode, i.e.
	// after HTML has been removed, and in search terms.)
	void checkphrase(char *file, off_t filelen, const String *url, const String *domain,
		unsigned int filtergroup, unsigned int phraselist);
	
	// check PICS ratings
	void checkPICS(const char *file, unsigned int filtergroup);
	void checkPICSrating(std::string label, unsigned int filtergroup);
	void checkPICSratingSafeSurf(String r, unsigned int filtergroup);
	void checkPICSratingevaluWEB(String r, unsigned int filtergroup);
	void checkPICSratingCyberNOT(String r, unsigned int filtergroup);
	void checkPICSratingRSAC(String r, unsigned int filtergroup);
	void checkPICSratingICRA(String r, unsigned int filtergroup);
	void checkPICSratingWeburbia(String r, unsigned int filtergroup);
	void checkPICSratingVancouver(String r, unsigned int filtergroup);

	// new Korean stuff
	void checkPICSratingICEC(String r, unsigned int filtergroup);
	void checkPICSratingSafeNet(String r, unsigned int filtergroup);

	void checkPICSagainstoption(String s, const char *l, int opt, std::string m);
};

#endif
