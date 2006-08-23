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

#include "NaughtyFilter.hpp"
#include "RegExp.hpp"
#include "ListContainer.hpp"

#include <syslog.h>
#include <algorithm>
#include <deque>


// GLOBALS 

extern OptionContainer o;

#ifdef __PCRE
extern RegExp absurl_re, relurl_re;
#endif


// DECLARATIONS

// category list entry class - stores category index & weight of all phrases
// found so far that fall under this category. also includes a less-than
// operator so that the STL sort algorithm can be applied to lists of these.
class listent {
public:
	listent(const int& c, const int& w, String& s) {
		weight = w;
		cat = c;
		string = s;
	};
	int cat;
	int weight;
	String string;
	int operator < (const listent &a) const {
		// sort in descending order of score
		return weight > a.weight ? 1 : 0;
	};
};


// IMPLEMENTATION

// constructor - set up defaults
NaughtyFilter::NaughtyFilter()
:	isItNaughty(false), isException(false), usedisplaycats(false), filtergroup(0), whatIsNaughty(""),
	whatIsNaughtyLog(""), whatIsNaughtyCategories(""), naughtiness(0)
{
}

void NaughtyFilter::reset()
{
	isItNaughty = false;
	isException = false;
	/*filtergroup = 0;
	whatIsNaughty = "";
	whatIsNaughtyLog = "";
	whatIsNaughtyCategories = "";*/
	usedisplaycats = false;
	naughtiness = 0;
}

// check the given document body for banned, weighted, and exception phrases (and PICS, and regexes, &c.)
void NaughtyFilter::checkme(DataBuffer *body, String &url, String &domain)
{
	// original data
	int rawbodylen = (*body).buffer_length;
	char *rawbody = (*body).data;
	
	// check PICS now - not dependent on case, hex decoding, etc.
	// as only sites which play by the rules will self-rate
	if ((*o.fg[filtergroup]).enable_PICS == 1) {
#ifdef DGDEBUG
		std::cout << "PICS is enabled" << std::endl;
#endif
		checkPICS(rawbody, rawbodylen);
		if (isItNaughty)
			return;  // Well there is no point in continuing is there?
	}
	
	// hex-decoded data (not case converted)
	int hexdecodedlen = rawbodylen;
	char *hexdecoded = rawbody;

	unsigned char c;

	// Hex decode content if desired
	// Do this now, as it's not especially case-sensitive,
	// and the case alteration should modify case post-decoding
	if (o.hex_decode_content == 1) {  // Mod suggested by AFN Tue 8th April 2003
#ifdef DGDEBUG
		std::cout << "Hex decoding is enabled" << std::endl;
#endif
		hexdecoded = new char[rawbodylen + 128 + 1];
		unsigned char c1;
		unsigned char c2;
		unsigned char c3;
		char hexval[5] = "0x";  // Initializes a "hexadecimal string"
		hexval[4] = '\0';
		char *ptr;  // pointer required by strtol

		// make a copy of the escaped document char by char
		int i = 0;
		int j = 0;
		while (i < rawbodylen - 3) {  // we lose 3 bytes but what the hell..
			c1 = rawbody[i];
			c2 = rawbody[i + 1];
			c3 = rawbody[i + 2];
			if (c1 == '%' && (((c2 >= '0') && (c2 <= '9')) || ((c2 >= 'a') && (c2 <= 'f')) || ((c2 >= 'A') && (c2 <= 'F')))
				&& (((c3 >= '0') && (c3 <= '9')) || ((c3 >= 'a') && (c3 <= 'f')) || ((c3 >= 'A') && (c3 <= 'F'))))
			{
				hexval[2] = c2;
				hexval[3] = c3;
				c = (unsigned char) strtol(hexval, &ptr, 0);
				i += 3;
				c = c1;
				i++;
			}
			hexdecoded[j] = c;
			j++;
		}
		// copy any remaining bytes
		while (i < rawbodylen) {
			hexdecoded[j++] = rawbody[i++];
		} 
		hexdecoded[j] = '\0';
		hexdecodedlen = j;
	}

	// scan twice, with & without case conversion (if desired) - aids support for exotic char encodings
	// TODO: move META/title sentinel location outside this loop, as they are not case sensitive operations
	bool preserve_case = o.preserve_case;
	if (o.preserve_case == 2) {
		// scanning twice *is* desired
		// first time round the loop, don't preserve case (non-exotic encodings)
#ifdef DGDEBUG
		std::cout << "Filtering with/without case preservation is enabled" << std::endl;
#endif
		preserve_case = 0;
	}
	
	// Store for the lowercase (maybe) data
	// The extra 128 is used for various speed tricks to
	// squeeze as much speed as possible.
	char* bodylc = new char[hexdecodedlen + 128];
	
	// Store for the tag-stripped data
	char* bodynohtml = NULL;
	if (o.phrase_filter_mode == 1 || o.phrase_filter_mode == 2)
		bodynohtml = new char[hexdecodedlen + 128 + 1];
	
	for (int loop = 0; loop < (o.preserve_case == 2 ? 2 : 1); loop++) {
#ifdef DGDEBUG
		std::cout << "Preserve case: " << preserve_case << std::endl;
#endif


		try {  // the last thing we need is an exception causing a memory leak

			int i, j;
#ifdef DGDEBUG
			if (o.phrase_filter_mode == 0 || o.phrase_filter_mode == 2 || o.phrase_filter_mode == 3)
				std::cout << "Raw content needed" << std::endl;
#endif
			// use the one that's been hex decoded, but not stripped
			// make a copy of the document lowercase char by char
			if (preserve_case == 1) {
				for (i = 0; i < hexdecodedlen; i++) {
					c = hexdecoded[i];
					if (c == 13 || c == 9 || c == 10) {
						c = 32;  // convert all whitespace to a space
					}
					bodylc[i] = c;
				}
			} else {
#ifdef DGDEBUG
				std::cout << "Not preserving case of raw content" << std::endl;
#endif
				for (i = 0; i < hexdecodedlen; i++) {
					c = hexdecoded[i];
					if (c >= 'A' && c <= 'Z') {
						c = 'a' + c - 'A';
					}
					else if (c >= 192 && c <= 221) {  // for accented chars
						c += 32;  // 224 + c - 192
					} else {
						if (c == 13 || c == 9 || c == 10) {
							c = 32;  // convert all whitespace to a space
						}
					}
					bodylc[i] = c;
				}
			}

			// filter meta tags & title only
			// based on idea from Nicolas Peyrussie
			if(o.phrase_filter_mode == 3) {
#ifdef DGDEBUG
				std::cout << "Filtering META/title" << std::endl;
#endif
				bool addit = false;  // flag if we should copy this char to filtered version
				bool needcheck = false;  // flag if we actually find anything worth filtering
				int bodymetalen;
			
				// find </head> or <body> as end of search range
				char* endhead = strstr(bodylc, "</head");
#ifdef DGDEBUG
				if (endhead != NULL)
					std::cout<<"Found '</head', limiting search range"<<std::endl;
#endif
				if (endhead == NULL) {
					endhead = strstr(bodylc, "<body");
#ifdef DGDEBUG
					if (endhead != NULL)
						std::cout<<"Found '<body', limiting search range"<<std::endl;
#endif
				}

				// if case preserved, also look for uppercase versions
				if ((preserve_case == 1) and (endhead == NULL)) {
					endhead = strstr(bodylc, "</HEAD");
#ifdef DGDEBUG
					if (endhead != NULL)
						std::cout<<"Found '</HEAD', limiting search range"<<std::endl;
#endif
					if (endhead == NULL) {
						endhead = strstr(bodylc, "<BODY");
#ifdef DGDEBUG
						if (endhead != NULL)
							std::cout<<"Found '<BODY', limiting search range"<<std::endl;
#endif
					}
				}

				if (endhead == NULL)
					endhead = bodylc+hexdecodedlen;

				char* bodymeta = new char[(endhead - bodylc) + 128 + 1];

				// initialisation for removal of duplicate non-alphanumeric characters
				j = 1;
				bodymeta[0] = 32;

				for (i = 0; i < (endhead - bodylc) - 7; i++) {
					c = bodylc[i];
					// are we at the start of a tag?
					if ((!addit) && (c == '<')) {
						if ((strncmp(bodylc+i+1, "meta", 4) == 0) or ((preserve_case == 1) and (strncmp(bodylc+i+1, "META", 4) == 0))) {
#ifdef DGDEBUG
							std::cout << "Found META" << std::endl;
#endif
							// start adding data to the check buffer
							addit = true;
							needcheck = true;
							// skip 'meta '
							i += 6;
							c = bodylc[i];
						}
						// are we at the start of a title tag?
						else if ((strncmp(bodylc+i+1, "title", 5) == 0) or ((preserve_case == 1) and (strncmp(bodylc+i+1, "TITLE", 5) == 0))) {
#ifdef DGDEBUG
							std::cout << "Found TITLE" << std::endl;
#endif
							// start adding data to the check buffer
							addit = true;
							needcheck = true;
							// skip 'title>'
							i += 7;
							c = bodylc[i];
						}
					}
					// meta tags end at a >
					// title tags end at the next < (opening of </title>)
					if (addit && ((c == '>') || (c == '<'))) {
						// stop ading data
						addit = false;
						// add a space before the next word in the check buffer
						bodymeta[j++] = 32;
					}
				
					if (addit) {
						// if we're in "record" mode (i.e. inside a title/metatag), strip certain characters out
						// of the data (to sanitise metatags & aid filtering of titles)
						if ( c== ',' || c == '=' || c == '"' || c  == '\''
							|| c == '(' || c == ')' || c == '.')
						{
							// replace with a space
							c = 32;
						}
						// don't bother duplicating spaces
						if ((c != 32) || (c == 32 && (bodymeta[j-1] != 32))) {
							bodymeta[j++] = c;  // copy it to the filtered copy
						}
					}
				}
				if (needcheck) {
					bodymeta[j++] = '\0';
#ifdef DGDEBUG
					std::cout << bodymeta << std::endl;
#endif
					bodymetalen = j;
					checkphrase(bodymeta, bodymetalen);
				}
#ifdef DGDEBUG
				else
					std::cout<<"Nothing to filter"<<std::endl;
#endif

				delete[] bodymeta;
				// surely the intention is to search *only* meta/title, so always exit
				delete[] bodylc;
				delete[] bodynohtml;
				if (hexdecoded != rawbody)
					delete[]hexdecoded;
				return;
			}

			if (o.phrase_filter_mode == 0 || o.phrase_filter_mode == 2) {
#ifdef DGDEBUG
				std::cout << "Checking raw content" << std::endl;
#endif
				// check unstripped content
				checkphrase(bodylc, hexdecodedlen, &url, &domain);
				if (isItNaughty || isException) {
					delete[]bodylc;
					delete[] bodynohtml;
					if (hexdecoded != rawbody)
						delete[]hexdecoded;
					return;  // Well there is no point in continuing is there?
				}
			}

			if (o.phrase_filter_mode == 0) {
				delete[]bodylc;
				delete[] bodynohtml;
				if (hexdecoded != rawbody)
					delete[]hexdecoded;
				return;  // only doing raw mode filtering
			}

			// if we fell through to here, use the one that's been hex decoded AND stripped
			// Strip HTML
#ifdef DGDEBUG
			std::cout << "\"Smart\" filtering is enabled" << std::endl;
#endif
			// we need this extra byte *
			bool inhtml = false;  // to flag if our pointer is within a html <>
			bool addit;  // flag if we should copy this char to filtered version
			j = 1;
			bodynohtml[0] = 32;  // * for this
			for (int i = 0; i < hexdecodedlen; i++) {
				addit = true;
				c = bodylc[i];
				if (c == '<') {
					inhtml = true;  // flag we are inside a html <>
				}
				if (c == '>') {	// flag we have just left a html <>
					inhtml = false;
					c = 32;
				}
				if (inhtml) {
					addit = false;
				}
				if (c == 32) {
					if (bodynohtml[j - 1] == 32) {	// * and this
						addit = false;
					}
				}
				if (addit) {	// if it passed the filters
					bodynohtml[j++] = c;  // copy it to the filtered copy
				}
			}
#ifdef DGDEBUG
			std::cout << "Checking smart content" << std::endl;
#endif
			checkphrase(bodynohtml, j);
		}
		catch(exception & e) {
#ifdef DGDEBUG
			std::cerr<<"NaughtyFilter caught an exception: "<<e.what()<<std::endl;
#endif
		}

		// second time round the case loop (if there is a second time),
		// do preserve case (exotic encodings)
		preserve_case = 1;
	}
	delete[]bodylc;
	delete[]bodynohtml;
	if (hexdecoded != rawbody)
		delete[]hexdecoded;
}

// check the phrase lists
void NaughtyFilter::checkphrase(char *file, int l, String *url, String *domain)
{
	int weighting = 0;
	int cat;
	std::string weightedphrase = "";
	bool isfound, wasbefore, catfound;
	
	// checkme: translate this?
	String currcat("Embedded URLs");

	// found categories list & reusable iterators
	std::deque<listent> listcategories;
	std::deque<listent>::iterator cattop = listcategories.begin();
	std::deque<listent>::iterator catcurrent;

	// check for embedded references to banned sites/URLs.
	// have regexes that check for URLs in pages (look for attributes (src, href, javascript location)
	// or look for protocol strings (in which case, incl. ftp)?) and extract them.
	// then check the extracted list against the banned site/URL lists.
	// ADs category lists do not want to add to the possibility of a site being banned.
	// Exception lists are not checked.
	// Do not do full-blown category retrieval/duplicate checking; simply add the
	// "Embedded URLs" category.
	// Put a warning next to the option in the config file that this will take lots of CPU.
	// Support phrase mode 1/2 distinction (duplicate sites/URLs).
	// Have weight configurable per filter group, not globally or with a list directive - 
	//   a weight of 0 will disable the option, effectively making this functionality per-FG itself.

	// todo: if checkphrase is passed the domain & existing URL, it can create full URLs from relative ones.
	// if a src/href URL starts with a /, append it to the domain; otherwise, append it to the existing URL.
	// chop off anything after a ?, run through realPath, then put through the URL lists.

#ifdef __PCRE
	// if weighted phrases are enabled, and we have been passed a URL and domain, and embedded URL checking is enabled...
	// then check for embedded URLs!
	if (o.weighted_phrase_mode != 0 && url != NULL && o.fg[filtergroup]->embedded_url_weight > 0) {
		listent *ourcat = NULL;
		std::deque<String> found;
		std::deque<String>::iterator foundtop = found.begin();
		std::deque<String>::iterator foundcurrent;

		String u;
		char* j;

		// check for absolute URLs
		if (absurl_re.match(file)) {
			// each match generates 2 results (because of the brackets in the regex), we're only interested in the first
#ifdef DGDEBUG
			std::cout << "Found " << absurl_re.numberOfMatches()/2 << " absolute URLs:" << std::endl;
#endif
			for (int i = 0; i < absurl_re.numberOfMatches(); i+=2) {
				// chop off quotes
				u = absurl_re.result(i);
				u = u.subString(1,u.length()-2);
#ifdef DGDEBUG
				std::cout << u << std::endl;
#endif
				if ((((j = o.fg[filtergroup]->inBannedSiteList(u)) != NULL) && !(o.lm.l[o.fg[filtergroup]->banned_site_list]->lastcategory.contains("ADs")))
					|| (((j = o.fg[filtergroup]->inBannedURLList(u)) != NULL) && !(o.lm.l[o.fg[filtergroup]->banned_url_list]->lastcategory.contains("ADs"))))
				{
					// duplicate checking
					// checkme: this should really be being done *before* we search the lists.
					// but because inBanned* methods do some cleaning up of their own, we don't know the form to check against.
					// we actually want these cleanups do be done before passing to inBanned*/inException* - this would
					// speed up ConnectionHandler a bit too.
					isfound = false;
					if (o.weighted_phrase_mode == 2) {
						foundcurrent = foundtop;
						while (foundcurrent != found.end()) {
							if (*foundcurrent == j) {
								isfound = true;
								break;
							}
							foundcurrent++;
						}
					}
					if (!isfound) {
						// add the site to the found phrases list
						if (weightedphrase.length() == 0)
							weightedphrase = "[";
						else
							weightedphrase += " ";
						weightedphrase += j;
						if (ourcat == NULL) {
							listcategories.push_back(listent(-1,o.fg[filtergroup]->embedded_url_weight,currcat));
							ourcat = &(listcategories.back());
						} else
							ourcat->weight += o.fg[filtergroup]->embedded_url_weight;
						if (o.weighted_phrase_mode == 2)
							found.push_back(j);
					}
				}
			}
		}

		found.clear();

		// check for relative URLs
		if (relurl_re.match(file)) {
			// we don't want any parameters on the end of the current URL, since we append to it directly
			// when forming absolute URLs from relative ones. we do want a / on the end, too.
			String currurl(*url);
			if (currurl.contains("?"))
				currurl = currurl.before("?");
			if (currurl[currurl.length()-1] != '/')
				currurl += "/";

			// each match generates 2 results (because of the brackets in the regex), we're only interested in the first
#ifdef DGDEBUG
			std::cout << "Found " << relurl_re.numberOfMatches()/2 << " relative URLs:" << std::endl;
#endif
			for (int i = 0; i < relurl_re.numberOfMatches(); i+=2) {
				u = relurl_re.result(i);
				
				// can't find a way to negate submatches in PCRE, so it is entirely possible
				// that some absolute URLs have made their way into this list. we don't want them.
				if (u.contains("://"))
					continue;

#ifdef DGDEBUG
				std::cout << u << std::endl;
#endif
				// remove src/href & quotes
				u = u.after("=");
				u.removeWhiteSpace();
				u = u.subString(1,u.length()-2);
				
				// create absolute URL
				if (u[0] == '/')
					u = (*domain) + u;
				else
					u = currurl + u;
#ifdef DGDEBUG
				std::cout << "absolute form: " << u << std::endl;
#endif
				if ((((j = o.fg[filtergroup]->inBannedSiteList(u)) != NULL) && !(o.lm.l[o.fg[filtergroup]->banned_site_list]->lastcategory.contains("ADs")))
					|| (((j = o.fg[filtergroup]->inBannedURLList(u)) != NULL) && !(o.lm.l[o.fg[filtergroup]->banned_url_list]->lastcategory.contains("ADs"))))
				{
					// duplicate checking
					// checkme: this should really be being done *before* we search the lists.
					// but because inBanned* methods do some cleaning up of their own, we don't know the form to check against.
					// we actually want these cleanups do be done before passing to inBanned*/inException* - this would
					// speed up ConnectionHandler a bit too.
					isfound = false;
					if (o.weighted_phrase_mode == 2) {
						foundcurrent = foundtop;
						while (foundcurrent != found.end()) {
							if (*foundcurrent == j) {
								isfound = true;
								break;
							}
							foundcurrent++;
						}
					}
					if (!isfound) {
						// add the site to the found phrases list
						if (weightedphrase.length() == 0)
							weightedphrase = "[";
						else
							weightedphrase += " ";
						weightedphrase += j;
						if (ourcat == NULL) {
							listcategories.push_back(listent(-1,o.fg[filtergroup]->embedded_url_weight,currcat));
							ourcat = &(listcategories.back());
						} else
							ourcat->weight += o.fg[filtergroup]->embedded_url_weight;
						if (o.weighted_phrase_mode == 2)
							found.push_back(j);
					}
				}
			}
		}
		if (ourcat != NULL) {
			weighting = ourcat->weight;
			weightedphrase += "]";
#ifdef DGDEBUG
			std::cout << weightedphrase << std::endl;
			std::cout << "score from embedded URLs: " << ourcat->weight << std::endl;
#endif
		}
	}
#endif

	std::string bannedphrase = "";
	std::string exceptionphrase = "";
	String bannedcategory;
	int type, index, weight;
	bool allcmatched = true, bannedcombi = false;
	std::string s1;

	// this line here searches for phrases contained in the list - the rest of the code is all sorting
	// through it to find the categories, weightings, types etc. of what has actually been found.
	std::deque<unsigned int> found;
	(*o.lm.l[(*o.fg[filtergroup]).banned_phrase_list]).graphSearch(found, file, l);

	// cache reusable iterators
	std::deque<unsigned int>::iterator foundtop = found.begin();
	std::deque<unsigned int>::iterator foundend = found.end();
	std::deque<unsigned int>::iterator foundcurrent;
	std::deque<unsigned int>::iterator alreadyfound;

	// look for combinations first
	//if banned must wait for exception later
	std::string combifound = "";
	std::string combisofar = "";

	std::vector<int>::iterator combicurrent = o.lm.l[o.fg[filtergroup]->banned_phrase_list]->combilist.begin();

	while (combicurrent != o.lm.l[o.fg[filtergroup]->banned_phrase_list]->combilist.end()) {
		index = *combicurrent;
		if (index == -2) {
			if (allcmatched) {
				type = *(++combicurrent);
				if (type == -1) {	// combination exception
					isItNaughty = false;
					isException = true;
					whatIsNaughtyLog = o.language_list.getTranslation(605);
					// Combination exception phrase found:
					whatIsNaughtyLog += combisofar;
					whatIsNaughty = "";
					return;
				}
				else if (type == 1) {	// combination weighting
					weight = *(++combicurrent);
					weighting += weight;
					if (weight > 0) {
						cat = *(++combicurrent);
						//category index -1 indicates an uncategorised list
						if (cat >= 0) {
							//don't output duplicate categories
							catcurrent = cattop;
							catfound = false;
							while (catcurrent != listcategories.end()) {
								if (catcurrent->cat == cat) {
									catfound = true;
									catcurrent->weight += weight;
									break;
								}
								catcurrent++;
							}
							if (!catfound) {
								currcat = o.lm.l[o.fg[filtergroup]->banned_phrase_list]->getListCategoryAtD(cat);
								listcategories.push_back(listent(cat,weight,currcat));
							}
						}
					} else {
						// skip past category for negatively weighted phrases
						combicurrent++;
					}
					if (weightedphrase.length() > 0) {
						weightedphrase += "+";
					}
					weightedphrase += "(";
					if (weight < 0) {
						weightedphrase += "-" + combisofar;
					} else {
						weightedphrase += combisofar;
					}

					weightedphrase += ")";
					combisofar = "";
				}
				else if (type == 0) {	// combination banned
					bannedcombi = true;
					combifound = combisofar;
					combicurrent += 2;
					cat = *(combicurrent);
					bannedcategory = o.lm.l[o.fg[filtergroup]->banned_phrase_list]->getListCategoryAtD(cat);
				}
			} else {
				allcmatched = true;
				combicurrent += 3;
			}
		} else {
			if (allcmatched) {
				isfound = false;
				s1 =(*o.lm.l[(*o.fg[filtergroup]).banned_phrase_list]).getItemAtInt(index);
				foundcurrent = foundtop;
				while (foundcurrent != foundend) {
					if (s1 == (*o.lm.l[(*o.fg[filtergroup]).banned_phrase_list]).getItemAtInt(*(foundcurrent++))) {
						isfound = true;
						break;
					}
				}
				if (!isfound) {
					allcmatched = false;
					combisofar = "";
				} else {
					if (combisofar.length() > 0) {
						combisofar += ", ";
					}
					combisofar += s1;
				}
			}
		}
		combicurrent++;
	}

	// even if we already found a combi ban, we must still wait; there may be non-combi exceptions to follow

	// now check non-combi phrases
	foundcurrent = foundtop;
	while (foundcurrent != foundend) {
		type = (*o.lm.l[(*o.fg[filtergroup]).banned_phrase_list]).getTypeAt(*foundcurrent);
		// 0=banned, 1=weighted, -1=exception, 2=combi, 3=weightedcombi
		if (type == 0) {
			// if we already found a combi ban, we don't need to know this stuff
			if (!bannedcombi) {
				isItNaughty = true;
				bannedphrase = (*o.lm.l[(*o.fg[filtergroup]).banned_phrase_list]).getItemAtInt(*foundcurrent);
				bannedcategory = (*o.lm.l[(*o.fg[filtergroup]).banned_phrase_list]).getListCategoryAt(*foundcurrent, &cat);
			}
		}
		else if (type == 1) {
			wasbefore = false;
			if (o.weighted_phrase_mode == 2) {
				// check for duplicates & ignore them
				alreadyfound = foundtop;
				while (alreadyfound != foundcurrent) {
					if (*alreadyfound == *foundcurrent) {
						wasbefore = true;
						break;
					}
					alreadyfound++;
				}
			}
			if ((o.weighted_phrase_mode == 1) || ((o.weighted_phrase_mode == 2) && !wasbefore)) {
				//normal mode - count all instances; i.e., multiple instances of word on one page all get counted.
				weight = (*o.lm.l[(*o.fg[filtergroup]).banned_phrase_list]).getWeightAt(*foundcurrent);
				weighting += weight;
				if (weight > 0) {
					currcat = (*o.lm.l[(*o.fg[filtergroup]).banned_phrase_list]).getListCategoryAt(*foundcurrent, &cat);
					if (cat >= 0) {
						//don't output duplicate categories
						catcurrent = cattop;
						catfound = false;
						while (catcurrent != listcategories.end()) {
							if (catcurrent->cat == cat) {
								catfound = true;
								catcurrent->weight += weight;
								break;
							}
							catcurrent++;
						}
						if (!catfound)
							listcategories.push_back(listent(cat,weight,currcat));
					}
				}

				if (o.show_weighted_found == 1) {
					if (weightedphrase.length() > 0) {
						weightedphrase += "+";
					}
					if (weight < 0) {
						weightedphrase += "-";
					}

					weightedphrase += (*o.lm.l[(*o.fg[filtergroup]).banned_phrase_list]).getItemAtInt(*foundcurrent);
				}
#ifdef DGDEBUG
				std::cout << "found weighted phrase ("<< o.weighted_phrase_mode << "):"
					<< (*o.lm.l[(*o.fg[filtergroup]).banned_phrase_list]).getItemAtInt(*foundcurrent) << std::endl;
#endif
			}
		}
		else if (type == -1) {
			isException = true;
			isItNaughty = false;
			whatIsNaughtyLog = o.language_list.getTranslation(604);
			// Exception phrase found:
			whatIsNaughtyLog += (*o.lm.l[(*o.fg[filtergroup]).banned_phrase_list]).getItemAtInt(*foundcurrent);
			whatIsNaughty = "";
			return;  // no point in going further
		}
		foundcurrent++;
	}
#ifdef DGDEBUG
	std::cout << "WEIGHTING: " << weighting << std::endl;
#endif

	// store the lowest negative weighting or highest positive weighting out of all filtering runs, preferring to store positive weightings.
	if ((weighting < 0 && naughtiness <= 0 && weighting < naughtiness) || (naughtiness >= 0 && weighting > naughtiness) || (naughtiness < 0 && weighting > 0) ) {
		naughtiness = weighting;
	}

#ifdef DGDEBUG
	std::cout << "NAUGHTINESS: " << naughtiness << std::endl;
#endif

	// *now* we can safely get down to the whole banning business!

	if (bannedcombi) {
		isItNaughty = true;
		whatIsNaughtyLog = o.language_list.getTranslation(400);
		// Banned combination phrase found:
		whatIsNaughtyLog += combifound;
		whatIsNaughty = o.language_list.getTranslation(401);
		// Banned combination phrase found.
		whatIsNaughtyCategories = bannedcategory.toCharArray();
		return;
	}

	if (isItNaughty) {
		whatIsNaughtyLog = o.language_list.getTranslation(300);
		// Banned Phrase found:
		whatIsNaughtyLog += bannedphrase;
		whatIsNaughty = o.language_list.getTranslation(301);
		// Banned phrase found.
		whatIsNaughtyCategories = bannedcategory.toCharArray();
		return;
	}

	if (weighting > (*o.fg[filtergroup]).naughtyness_limit) {
		isItNaughty = true;
		whatIsNaughtyLog = o.language_list.getTranslation(402);
		// Weighted phrase limit of
		whatIsNaughtyLog += String((*o.fg[filtergroup]).naughtyness_limit).toCharArray();
		whatIsNaughtyLog += " : ";
		whatIsNaughtyLog += String(weighting).toCharArray();
		if (o.show_weighted_found == 1) {
			whatIsNaughtyLog += " (";
			whatIsNaughtyLog += weightedphrase;
			whatIsNaughtyLog += ")";
		}
		whatIsNaughty = o.language_list.getTranslation(403);
		// Weighted phrase limit exceeded.
		// Generate category list, sorted with highest scoring first.
		bool nonempty = false;
		bool belowthreshold = false;
		String categories;
		std::sort(listcategories.begin(), listcategories.end());
		std::deque<listent>::iterator k = listcategories.begin();
		while (k != listcategories.end()) {
			// if category display threshold is in use, apply it
			if (!belowthreshold && (o.fg[filtergroup]->category_threshold > 0)
				&& (k->weight < o.fg[filtergroup]->category_threshold))
			{
				whatIsNaughtyDisplayCategories = categories.toCharArray();
				belowthreshold = true;
				usedisplaycats = true;
			}
			if (k->string.length() > 0) {
				if (nonempty) categories += ", ";
				// put brackets around the string to indicate cats that are logged but not displayed
				if (belowthreshold)
					categories += "(";
				categories += k->string;
				if (belowthreshold)
					categories += ")";
				nonempty = true;
			}
			k++;
			// if category threshold is set to show only the top category,
			// everything after the first loop is below the threshold
			if (!belowthreshold && o.fg[filtergroup]->category_threshold < 0) {
				whatIsNaughtyDisplayCategories = categories.toCharArray();
				belowthreshold = true;
				usedisplaycats = true;
			}
		}
		whatIsNaughtyCategories = categories.toCharArray();
		return;
	}
	// whatIsNaughty is what is displayed in the browser
	// whatIsNaughtyLog is what is logged in the log file if at all
}



// *
// *
// * PICS code
// *
// *



// check the document's PICS rating
// when checkPICS is called we assume checkphrase has made the document lower case.
void NaughtyFilter::checkPICS(char *file, int l)
{
	file[l] = 0;  // to ensure end of c-string marker is there
	(*o.fg[filtergroup]).pics1.match(file);
	if (!(*o.fg[filtergroup]).pics1.matched()) {
		return;
	}			// exit if not found
	for (int i = 0; i < (*o.fg[filtergroup]).pics1.numberOfMatches(); i++) {
		checkPICSrating((*o.fg[filtergroup]).pics1.result(i));  // pass on result for further
		// tests
	}
}

// the meat of the process 
void NaughtyFilter::checkPICSrating(std::string label)
{
	(*o.fg[filtergroup]).pics2.match(label.c_str());
	if (!(*o.fg[filtergroup]).pics2.matched()) {
		return;
	}			// exit if not found
	String lab = label.c_str();  // convert to a String for easy manip
	String r;
	String service;
	for (int i = 0; i < (*o.fg[filtergroup]).pics2.numberOfMatches(); i++) {
		r = (*o.fg[filtergroup]).pics2.result(i).c_str();  // ditto
		r = r.after("(");
		r = r.before(")");  // remove the brackets

		// Only check the substring of lab that is between
		// the start of lab (or the end of the previous match)
		// and the start of this rating.
		// It is possible to have multiple ratings in one pics-label.
		// This is done on e.g. http://www.jesusfilm.org/
		if (i == 0) {
			service = lab.subString(0, (*o.fg[filtergroup]).pics2.offset(i));
		} else {
			service = lab.subString((*o.fg[filtergroup]).pics2.offset(i - 1) + (*o.fg[filtergroup]).pics2.length(i - 1), (*o.fg[filtergroup]).pics2.offset(i));
		}

		if (service.contains("safesurf")) {
			checkPICSratingSafeSurf(r);
			if (isItNaughty) {
				return;
			}
		}
		if (service.contains("evaluweb")) {
			checkPICSratingevaluWEB(r);
			if (isItNaughty) {
				return;
			}
		}
		if (service.contains("microsys")) {
			checkPICSratingCyberNOT(r);
			if (isItNaughty) {
				return;
			}
		}
		if (service.contains("icra")) {
			checkPICSratingICRA(r);
			if (isItNaughty) {
				return;
			}
		}
		if (service.contains("rsac")) {
			checkPICSratingRSAC(r);
			if (isItNaughty) {
				return;
			}
		}
		if (service.contains("weburbia")) {
			checkPICSratingWeburbia(r);
			if (isItNaughty) {
				return;
			}
		}
		if (service.contains("vancouver")) {
			checkPICSratingVancouver(r);
			if (isItNaughty) {
				return;
			}
		}
		if (service.contains("icec")) {
			checkPICSratingICEC(r);
			if (isItNaughty) {
				return;
			}
		}
		if (service.contains("safenet")) {
			checkPICSratingSafeNet(r);
			if (isItNaughty) {
				return;
			}
		}
		// check label for word denoting rating system then pass on to the
		// appropriate function the rating String.
	}
}

void NaughtyFilter::checkPICSagainstoption(String s, char *l, int opt, std::string m)
{
	if (s.indexOf(l) != -1) {
		// if the rating contains the label then:
		int i = 0;
		// get the rating label value
		s = s.after(l);
		if (s.indexOf(" ") != -1) {
			//remove anything after it
			s = s.before(" ");
		}
		// sanity checking
		if (s.length() > 0) {
			i = s.toInteger();  // convert the value in a String to an integer
			if (opt < i) {	// check its value against the option in config file
				isItNaughty = true;  // must be over limit
				whatIsNaughty = m + " ";
				whatIsNaughty += o.language_list.getTranslation(1000);
				// PICS labeling level exceeded on the above site.
				whatIsNaughtyCategories = "PICS";
				whatIsNaughtyLog = whatIsNaughty;
			}
		}
	}
}

// The next few functions are flippin' obvious so no explanation...
void NaughtyFilter::checkPICSratingevaluWEB(String r)
{
	checkPICSagainstoption(r, "rating ", (*o.fg[filtergroup]).pics_evaluweb_rating, "evaluWEB age range");
}

void NaughtyFilter::checkPICSratingWeburbia(String r)
{
	checkPICSagainstoption(r, "s ", (*o.fg[filtergroup]).pics_weburbia_rating, "Weburbia rating");
}

void NaughtyFilter::checkPICSratingCyberNOT(String r)
{
	checkPICSagainstoption(r, "sex ", (*o.fg[filtergroup]).pics_cybernot_sex, "CyberNOT sex rating");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "other ", (*o.fg[filtergroup]).pics_cybernot_sex, "CyberNOT other rating");
}

// Korean PICS
void NaughtyFilter::checkPICSratingICEC(String r) {
    checkPICSagainstoption(r, "y ", (*o.fg[filtergroup]).pics_icec_rating, "ICEC rating");
}

// Korean PICS
void NaughtyFilter::checkPICSratingSafeNet(String r) {
	checkPICSagainstoption(r, "n ", (*o.fg[filtergroup]).pics_safenet_nudity, "SafeNet nudity");
	if (isItNaughty) {return;}
	checkPICSagainstoption(r, "s ", (*o.fg[filtergroup]).pics_safenet_sex, "SafeNet sex");
	if (isItNaughty) {return;}
	checkPICSagainstoption(r, "v ", (*o.fg[filtergroup]).pics_safenet_violence, "SafeNet violence");
	if (isItNaughty) {return;}
	checkPICSagainstoption(r, "l ", (*o.fg[filtergroup]).pics_safenet_language, "SafeNet language");
	if (isItNaughty) {return;}
	checkPICSagainstoption(r, "i ", (*o.fg[filtergroup]).pics_safenet_gambling, "SafeNet gambling");
	if (isItNaughty) {return;}
	checkPICSagainstoption(r, "h ", (*o.fg[filtergroup]).pics_safenet_alcoholtobacco, "SafeNet alcohol tobacco");
}

void NaughtyFilter::checkPICSratingRSAC(String r)
{
	checkPICSagainstoption(r, "v ", (*o.fg[filtergroup]).pics_rsac_violence, "RSAC violence");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "s ", (*o.fg[filtergroup]).pics_rsac_sex, "RSAC sex");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "n ", (*o.fg[filtergroup]).pics_rsac_nudity, "RSAC nudity");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "l ", (*o.fg[filtergroup]).pics_rsac_language, "RSAC language");
}

void NaughtyFilter::checkPICSratingVancouver(String r)
{
	checkPICSagainstoption(r, "MC ", (*o.fg[filtergroup]).pics_vancouver_multiculturalism, "Vancouvermulticulturalism");
	checkPICSagainstoption(r, "Edu ", (*o.fg[filtergroup]).pics_vancouver_educationalcontent, "Vancouvereducationalcontent");
	checkPICSagainstoption(r, "Env ", (*o.fg[filtergroup]).pics_vancouver_environmentalawareness, "Vancouverenvironmentalawareness");
	checkPICSagainstoption(r, "Tol ", (*o.fg[filtergroup]).pics_vancouver_tolerance, "Vancouvertolerance");
	checkPICSagainstoption(r, "V ", (*o.fg[filtergroup]).pics_vancouver_violence, "Vancouverviolence");
	checkPICSagainstoption(r, "S ", (*o.fg[filtergroup]).pics_vancouver_sex, "Vancouversex");
	checkPICSagainstoption(r, "P ", (*o.fg[filtergroup]).pics_vancouver_profanity, "Vancouverprofanity");
	checkPICSagainstoption(r, "SF ", (*o.fg[filtergroup]).pics_vancouver_safety, "Vancouversafety");
	checkPICSagainstoption(r, "Can ", (*o.fg[filtergroup]).pics_vancouver_canadiancontent, "Vancouvercanadiancontent");
	checkPICSagainstoption(r, "Com ", (*o.fg[filtergroup]).pics_vancouver_commercialcontent, "Vancouvercommercialcontent");
	checkPICSagainstoption(r, "Gam ", (*o.fg[filtergroup]).pics_vancouver_gambling, "Vancouvergambling");
}

void NaughtyFilter::checkPICSratingSafeSurf(String r)
{
	checkPICSagainstoption(r, "000 ", (*o.fg[filtergroup]).pics_safesurf_agerange, "Safesurf age range");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "001 ", (*o.fg[filtergroup]).pics_safesurf_profanity, "Safesurf profanity");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "002 ", (*o.fg[filtergroup]).pics_safesurf_heterosexualthemes, "Safesurf heterosexualthemes");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "003 ", (*o.fg[filtergroup]).pics_safesurf_homosexualthemes, "Safesurf ");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "004 ", (*o.fg[filtergroup]).pics_safesurf_nudity, "Safesurf nudity");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "005 ", (*o.fg[filtergroup]).pics_safesurf_violence, "Safesurf violence");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "006 ", (*o.fg[filtergroup]).pics_safesurf_sexviolenceandprofanity, "Safesurf sexviolenceandprofanity");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "007 ", (*o.fg[filtergroup]).pics_safesurf_intolerance, "Safesurf intolerance");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "008 ", (*o.fg[filtergroup]).pics_safesurf_druguse, "Safesurf druguse");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "009 ", (*o.fg[filtergroup]).pics_safesurf_otheradultthemes, "Safesurf otheradultthemes");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "00A ", (*o.fg[filtergroup]).pics_safesurf_gambling, "Safesurf gambling");
	if (isItNaughty) {
		return;
	}
}

void NaughtyFilter::checkPICSratingICRA(String r)
{
	checkPICSagainstoption(r, "la ", (*o.fg[filtergroup]).pics_icra_languagesexual, "ICRA languagesexual");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "ca ", (*o.fg[filtergroup]).pics_icra_chat, "ICRA chat");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "cb ", (*o.fg[filtergroup]).pics_icra_moderatedchat, "ICRA moderatedchat");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "lb ", (*o.fg[filtergroup]).pics_icra_languageprofanity, "ICRA languageprofanity");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "lc ", (*o.fg[filtergroup]).pics_icra_languagemildexpletives, "ICRA languagemildexpletives");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "na ", (*o.fg[filtergroup]).pics_icra_nuditygraphic, "ICRA nuditygraphic");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "nb ", (*o.fg[filtergroup]).pics_icra_nuditymalegraphic, "ICRA nuditymalegraphic");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "nc ", (*o.fg[filtergroup]).pics_icra_nudityfemalegraphic, "ICRA nudityfemalegraphic");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "nd ", (*o.fg[filtergroup]).pics_icra_nuditytopless, "ICRA nuditytopless");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "ne ", (*o.fg[filtergroup]).pics_icra_nuditybottoms, "ICRA nuditybottoms");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "nf ", (*o.fg[filtergroup]).pics_icra_nuditysexualacts, "ICRA nuditysexualacts");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "ng ", (*o.fg[filtergroup]).pics_icra_nudityobscuredsexualacts, "ICRA nudityobscuredsexualacts");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "nh ", (*o.fg[filtergroup]).pics_icra_nuditysexualtouching, "ICRA nuditysexualtouching");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "ni ", (*o.fg[filtergroup]).pics_icra_nuditykissing, "ICRA nuditykissing");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "nr ", (*o.fg[filtergroup]).pics_icra_nudityartistic, "ICRA nudityartistic");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "ns ", (*o.fg[filtergroup]).pics_icra_nudityeducational, "ICRA nudityeducational");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "nt ", (*o.fg[filtergroup]).pics_icra_nuditymedical, "ICRA nuditymedical");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "oa ", (*o.fg[filtergroup]).pics_icra_drugstobacco, "ICRA drugstobacco");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "ob ", (*o.fg[filtergroup]).pics_icra_drugsalcohol, "ICRA drugsalcohol");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "oc ", (*o.fg[filtergroup]).pics_icra_drugsuse, "ICRA drugsuse");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "od ", (*o.fg[filtergroup]).pics_icra_gambling, "ICRA gambling");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "oe ", (*o.fg[filtergroup]).pics_icra_weaponuse, "ICRA weaponuse");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "of ", (*o.fg[filtergroup]).pics_icra_intolerance, "ICRA intolerance");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "og ", (*o.fg[filtergroup]).pics_icra_badexample, "ICRA badexample");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "oh ", (*o.fg[filtergroup]).pics_icra_pgmaterial, "ICRA pgmaterial");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "va ", (*o.fg[filtergroup]).pics_icra_violencerape, "ICRA violencerape");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vb ", (*o.fg[filtergroup]).pics_icra_violencetohumans, "ICRA violencetohumans");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vc ", (*o.fg[filtergroup]).pics_icra_violencetoanimals, "ICRA violencetoanimals");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vd ", (*o.fg[filtergroup]).pics_icra_violencetofantasy, "ICRA violencetofantasy");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "ve ", (*o.fg[filtergroup]).pics_icra_violencekillinghumans, "ICRA violencekillinghumans");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vf ", (*o.fg[filtergroup]).pics_icra_violencekillinganimals, "ICRA violencekillinganimals");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vg ", (*o.fg[filtergroup]).pics_icra_violencekillingfantasy, "ICRA violencekillingfantasy");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vh ", (*o.fg[filtergroup]).pics_icra_violenceinjuryhumans, "ICRA violenceinjuryhumans");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vi ", (*o.fg[filtergroup]).pics_icra_violenceinjuryanimals, "ICRA violenceinjuryanimals");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vj ", (*o.fg[filtergroup]).pics_icra_violenceinjuryfantasy, "ICRA violenceinjuryfantasy");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vr ", (*o.fg[filtergroup]).pics_icra_violenceartisitic, "ICRA violenceartisitic");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vs ", (*o.fg[filtergroup]).pics_icra_violenceeducational, "ICRA violenceeducational");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vt ", (*o.fg[filtergroup]).pics_icra_violencemedical, "ICRA violencemedical");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vu ", (*o.fg[filtergroup]).pics_icra_violencesports, "ICRA violencesports");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vk ", (*o.fg[filtergroup]).pics_icra_violenceobjects, "ICRA violenceobjects");

}
