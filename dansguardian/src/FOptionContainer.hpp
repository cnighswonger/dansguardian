// FOptionContainer class - contains the options for a filter group,
// including the banned/grey/exception site lists and the content/site/url regexp lists

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

#ifndef __HPP_FOPTIONCONTAINER
#define __HPP_FOPTIONCONTAINER


// INCLUDES

#include "platform.h"

#include "String.hpp"
#include "HTMLTemplate.hpp"
#include "ListContainer.hpp"
#include "LanguageContainer.hpp"
#include "ImageContainer.hpp"
#include "RegExp.hpp"
#include <string>
#include <deque>


// DECLARATIONS

std::deque<String> *ipToHostname(const char *ip);

class FOptionContainer
{

public:
	int reporting_level;
	int category_threshold;
	int infection_bypass_errors_only;
	int disable_content_scan;
	int weighted_phrase_mode;
	int group_mode;
	int embedded_url_weight;
	int naughtyness_limit;
	int createlistcachefiles;
	int enable_PICS;
	int deep_url_analysis;

#ifdef __EMAIL
	// Email notification patch by J. Gauthier
	int notifyav;
	int notifycontent;
	int use_smtp;
	int violations;
	int current_violations;
	int threshold;
	long threshold_stamp;
	int byuser;
#endif

	bool blanketblock;
	bool blanket_ip_block;
	bool blanketsslblock;
	bool blanketssl_ip_block;
	
	// File filtering mode - should banned or exception lists be used?
	// if true, use exception lists & exception file site list; otherwise,
	// use banned MIME type & extension lists.
	bool block_downloads;
	
	int reverse_lookups;
	int force_quick_search;
	int bypass_mode;
	int infection_bypass_mode;
	int pics_rsac_violence;
	int pics_rsac_sex;
	int pics_rsac_nudity;
	int pics_rsac_language;
	int pics_icra_chat;
	int pics_icra_moderatedchat;
	int pics_icra_languagesexual;
	int pics_icra_languageprofanity;
	int pics_icra_languagemildexpletives;
	int pics_icra_nuditygraphic;
	int pics_icra_nuditymalegraphic;
	int pics_icra_nudityfemalegraphic;
	int pics_icra_nuditytopless;
	int pics_icra_nuditybottoms;
	int pics_icra_nuditysexualacts;
	int pics_icra_nudityobscuredsexualacts;
	int pics_icra_nuditysexualtouching;
	int pics_icra_nuditykissing;
	int pics_icra_nudityartistic;
	int pics_icra_nudityeducational;
	int pics_icra_nuditymedical;
	int pics_icra_drugstobacco;
	int pics_icra_drugsalcohol;
	int pics_icra_drugsuse;
	int pics_icra_gambling;
	int pics_icra_weaponuse;
	int pics_icra_intolerance;
	int pics_icra_badexample;
	int pics_icra_pgmaterial;
	int pics_icra_violencerape;
	int pics_icra_violencetohumans;
	int pics_icra_violencetoanimals;
	int pics_icra_violencetofantasy;
	int pics_icra_violencekillinghumans;
	int pics_icra_violencekillinganimals;
	int pics_icra_violencekillingfantasy;
	int pics_icra_violenceinjuryhumans;
	int pics_icra_violenceinjuryanimals;
	int pics_icra_violenceinjuryfantasy;
	int pics_icra_violenceartisitic;
	int pics_icra_violenceeducational;
	int pics_icra_violencemedical;
	int pics_icra_violencesports;
	int pics_icra_violenceobjects;
	int pics_evaluweb_rating;
	int pics_cybernot_sex;
	int pics_cybernot_other;
	int pics_safesurf_agerange;
	int pics_safesurf_profanity;
	int pics_safesurf_heterosexualthemes;
	int pics_safesurf_homosexualthemes;
	int pics_safesurf_nudity;
	int pics_safesurf_violence;
	int pics_safesurf_sexviolenceandprofanity;
	int pics_safesurf_intolerance;
	int pics_safesurf_druguse;
	int pics_safesurf_otheradultthemes;
	int pics_safesurf_gambling;
	int pics_weburbia_rating;
	int pics_vancouver_multiculturalism;
	int pics_vancouver_educationalcontent;
	int pics_vancouver_environmentalawareness;
	int pics_vancouver_tolerance;
	int pics_vancouver_violence;
	int pics_vancouver_sex;
	int pics_vancouver_profanity;
	int pics_vancouver_safety;
	int pics_vancouver_canadiancontent;
	int pics_vancouver_commercialcontent;
	int pics_vancouver_gambling;

	// new Korean PICS support
	int pics_icec_rating;
	int pics_safenet_nudity;
	int pics_safenet_sex;
	int pics_safenet_violence;
	int pics_safenet_language;
	int pics_safenet_gambling;
	int pics_safenet_alcoholtobacco;

	std::string name;
	std::string magic;
	std::string imagic;
	std::string cookie_magic;

#ifdef __EMAIL
	// Email notification patch by J. Gauthier
	std::string mailfrom;
	std::string avadmin;
	std::string contentadmin;   
	std::string avsubject;
	std::string contentsubject;   
	std::string violationbody;
#endif
   
	unsigned int banned_phrase_list;
	unsigned int exception_site_list;
	unsigned int exception_url_list;
	unsigned int banned_extension_list;
	unsigned int banned_mimetype_list;
	unsigned int banned_site_list;
	unsigned int banned_url_list;
	unsigned int grey_site_list;
	unsigned int grey_url_list;
	unsigned int banned_regexpurl_list;
	unsigned int exception_regexpurl_list;
	unsigned int content_regexp_list;
	unsigned int url_regexp_list;
	unsigned int exception_extension_list;
	unsigned int exception_mimetype_list;
	unsigned int exception_file_site_list;

   
	// regex match lists
	std::deque<RegExp> banned_regexpurl_list_comp;
	std::deque<String> banned_regexpurl_list_source;
	std::deque<unsigned int> banned_regexpurl_list_ref;
	std::deque<RegExp> exception_regexpurl_list_comp;
	std::deque<String> exception_regexpurl_list_source;
	std::deque<unsigned int> exception_regexpurl_list_ref;

	// regex search & replace lists
	std::deque<RegExp> content_regexp_list_comp;
	std::deque<String> content_regexp_list_rep;
	std::deque<RegExp> url_regexp_list_comp;
	std::deque<String> url_regexp_list_rep;

	// precompiled reg exps for speed
	RegExp pics1;
	RegExp pics2;
	RegExp isiphost;
	
	// access denied address & domain - if they override the defaults
	std::string access_denied_address;
	String access_denied_domain;

	FOptionContainer():blanketblock(false), blanket_ip_block(false),
		blanketsslblock(false), blanketssl_ip_block(false),
		block_downloads(false), banned_page(NULL),
		banned_phrase_flag(false), exception_site_flag(false), exception_url_flag(false),
		banned_extension_flag(false), banned_mimetype_flag(false), banned_site_flag(false),
		banned_url_flag(false), grey_site_flag(false), grey_url_flag(false),
		banned_regexpurl_flag(false), exception_regexpurl_flag(false),
		content_regexp_flag(false), url_regexp_flag(false),
		exception_extension_flag(false), exception_mimetype_flag(false),
		exception_file_site_flag(false) {};
	~FOptionContainer();
	bool read(const char *filename);
	void reset();
	bool isOurWebserver(String url);
	char *inBannedSiteList(String url);
	char *inBannedURLList(String url);
	bool inGreySiteList(String url);
	bool inGreyURLList(String url);
	bool inExceptionSiteList(String url);
	bool inExceptionFileSiteList(String url);
	bool inExceptionURLList(String url);
	int inBannedRegExpURLList(String url);
	int inExceptionRegExpURLList(String url);
	char *inExtensionList(unsigned int list, String url);
	bool isIPHostname(String url);
	
	// get HTML template for this group
	HTMLTemplate *getHTMLTemplate();

private:
	// HTML template - if it overrides the default
	HTMLTemplate *banned_page;

	bool banned_phrase_flag;
	bool exception_site_flag;
	bool exception_url_flag;
	bool banned_extension_flag;
	bool banned_mimetype_flag;
	bool banned_site_flag;
	bool banned_url_flag;
	bool grey_site_flag;
	bool grey_url_flag;
	bool banned_regexpurl_flag;
	bool exception_regexpurl_flag;
	bool content_regexp_flag;
	bool url_regexp_flag;
	bool exception_extension_flag;
	bool exception_mimetype_flag;
	bool exception_file_site_flag;
	std::deque<int> banned_phrase_list_index;

	std::deque<std::string > conffile;

	bool precompileregexps();
	bool readbplfile(const char *banned, const char *exception, const char *weighted);
	bool readFile(const char *filename, unsigned int* whichlist, bool sortsw, bool cache, const char *listname);
	bool readRegExURLFile(const char *filename, const char *listname, unsigned int& listref,
		std::deque<RegExp> &list_comp, std::deque<String> &list_source, std::deque<unsigned int> &list_ref);
	bool compileRegExURLFile(unsigned int list, std::deque<RegExp> &list_comp,
		std::deque<String> &list_source, std::deque<unsigned int> &list_ref);
	bool readRegExListFile(const char *filename, const char *listname, unsigned int& listid,
	std::deque<String> &list_rep, std::deque<RegExp> &list_comp);

	int findoptionI(const char *option);
	std::string findoptionS(const char *option);
	bool realitycheck(String s, int minl, int maxl, char *emessage);
	int inRegExpURLList(String &url, std::deque<RegExp> &list_comp, std::deque<unsigned int> &list_ref, unsigned int list);

	char *inURLList(String &url, unsigned int list);
	char *inSiteList(String &url, unsigned int list);
};

#endif
