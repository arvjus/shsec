/* conf.l - SharedSecret project.

   Copyright (C) 2004 - Arvydas Juskaitis <arvydasj@users.sourceforge.net>

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 2, or (at your option) any
   later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
*/

%{
	#include <stdlib.h>
	#include <string.h>
	#include "conf_pars.h"

	int yyparse();
	void yyerror(char*);
	static char file_name[256];
	static char str_buf[2048], *str_ptr;
	static int line_number = 1;

	#define ADD_CHAR(ch) { \
		if (str_ptr >= str_buf + sizeof(str_buf)) \
			 yyerror("string is too long"); \
		*str_ptr ++ = ch; \
	}
%}

%x		comment sqstring dqstring

KWORD	egid|pid-file|keydb-file|sock-file|verbose|flush-db|listen|port
WORD	[a-zA-Z]+[a-zA-Z0-9_\-.@]*
IPAD	[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+			
NETM	[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+
NETC	[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+
OCT		0[1-7]*
DEC		[1-9][0-9]*
HEX		0[xX][a-fA-F0-9]+

%%

"/*"			BEGIN comment; 
<comment>"*/"	BEGIN 0; 
<comment>\n		line_number ++; 
<comment>.		/* ignore */
"//"[^\n]*		/* ignore */
"#"[^\n]*		/* ignore */
[ \t\r]			/* ignore */
\n				line_number ++; 

{IPAD}			{ yylval.str = strdup(yytext); return IPADDR; }
{NETM}			{ yylval.str = strdup(yytext); return NET_MASK; }
{NETC}			{ yylval.str = strdup(yytext); return NET_CIDR; }
{OCT}			{ yylval.num = strtol(yytext,   NULL,  8); return NUMBER; }
{DEC}			{ yylval.num = strtol(yytext,   NULL, 10); return NUMBER; }
{HEX}			{ yylval.num = strtol(yytext+2, NULL, 16); return NUMBER; }

\'				{ BEGIN sqstring; str_ptr = str_buf; }
<sqstring>\\n	{ ADD_CHAR('\n'); }
<sqstring>\\t	{ ADD_CHAR('\t'); }
<sqstring>\\\'	{ ADD_CHAR('\''); } 
<sqstring>\\\"	{ ADD_CHAR('\"'); } 
<sqstring>\'	{
					ADD_CHAR('\0');
					BEGIN 0;
					yylval.str = strdup(str_buf);
					return STRING;
				}
<sqstring>\n	{ yyerror("string was not terminated properly"); }
<sqstring>\\\n	{ line_number ++; }
<sqstring>.		{ ADD_CHAR(*yytext); }

\"				{ BEGIN dqstring; str_ptr = str_buf; }
<dqstring>\\n	{ ADD_CHAR('\n'); }
<dqstring>\\t	{ ADD_CHAR('\t'); }
<dqstring>\\\'	{ ADD_CHAR('\''); } 
<dqstring>\\\"	{ ADD_CHAR('\"'); } 
<dqstring>\"	{
					ADD_CHAR('\0');
					BEGIN 0;
					yylval.str = strdup(str_buf);
					return STRING;
				}
<dqstring>\n	{ yyerror("string was not terminated properly"); }
<dqstring>\\\n	{ line_number ++; }
<dqstring>.		{ ADD_CHAR(*yytext); }

"="				return *yytext;
";"				return *yytext;
"{"				return *yytext;
"}"				return *yytext;
","				return *yytext;

dh-group		return KW_DH_GROUP;
host			return KW_HOST;
peer			return KW_PEER;
auth			return KW_AUTH;
none			return KW_NONE;
psk				return KW_PSK; 
psk-file		return KW_PSK_FILE;
rsa				return KW_RSA;
rsa-pub			return KW_RSA_PUB;
rsa-pub-file	return KW_RSA_PUB_FILE;
rsa-key			return KW_RSA_KEY;
rsa-key-file	return KW_RSA_KEY_FILE;
order			return KW_ORDER;
allow			return KW_ALLOW; 
deny			return KW_DENY; 

{KWORD}			{ yylval.str = strdup(yytext); return KEYWORD; }
{WORD}			{ yylval.str = strdup(yytext); return WORD; }

%%

/*
 * public functions
 */

int conf_init(const char* file)
{
	if (file) {
		yyin = fopen(file, "r");
		strcpy(file_name, file);
	} else
		strcpy(file_name, "<stdin>");
	
	if (file && !yyin)
		return 1;

	yyparse();

	if (file)
		fclose(yyin);

	return 0;
}

/*
 * local functions
 */

int yywrap() {
	return 1;
}

void yyerror(char* s) {
	fprintf(stderr, "error in '%s', line %d: %s\n",
		file_name, line_number, s);
	exit(1);
}

void yywarning(char* s) {
	fprintf(stderr, "warning in '%s', line %d: %s\n",
		file_name, line_number, s);
}
