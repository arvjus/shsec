/* conf.y - SharedSecret project.

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
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <ctype.h>
	#include "conf_defs.h"

	#define YYDEBUG 1
	int yylex();
	void yyerror(char*);
	void yywarning(char*);

	/* macros */
	#define STRCPY(d,s) { \
		if (strlen(s) >= sizeof(d)) yyerror("string is too long"); \
		strncpy(d, s, sizeof(d)); free(s); \
	}

	#define SETPTR(d,s) { \
		if (d) { \
			free(d); yywarning("variable has been already initialized"); } \
		d = s; \
	}

	/* local functions */
	void set_keyword(const char* name, void* value, int type);
	void* str_to_lentry(char* data, char type);
	void append_to_list(void* list, void* item);
	void free_list(LISTENTRY* list);

	/* global conf_XXX variables */
	int			conf_egid = 0;
	char		conf_pid_file[MAX_FILE_LEN];
	char		conf_keydb_file[MAX_FILE_LEN];
	char		conf_sock_file[MAX_FILE_LEN];
	int			conf_verbose = 0;
	int			conf_flush_db = 0;
	int			conf_dh_group = 0;
	char		conf_listen[20];
	int			conf_port = 0;
	char		conf_host[MAX_HOST_LEN];
	char*		conf_rsa_key = NULL;
	char		conf_rsa_key_file[MAX_FILE_LEN];
	int			conf_search_order;
	LISTENTRY*	conf_allow_peers = NULL;
	LISTENTRY*	conf_deny_peers = NULL;
	PEERENTRY*	conf_peers = NULL;
%}

%union {
	long	num;
	char*	str;
	void*	ptr;
}

%type <num> NUMBER
%type <str> IPADDR NET_MASK NET_CIDR STRING WORD KEYWORD identity
%type <ptr> list list_entry peer_statements peer_statement

%token IPADDR NET_MASK NET_CIDR NUMBER STRING WORD KEYWORD
%token KW_DH_GROUP KW_ORDER KW_ALLOW KW_DENY KW_HOST KW_PEER
%token KW_AUTH KW_NONE KW_PSK KW_PSK_FILE KW_RSA
%token KW_RSA_PUB KW_RSA_PUB_FILE KW_RSA_KEY KW_RSA_KEY_FILE

%start statements

%%

statements: /* empty */
	| statements statement ';' 
	;

statement: /* empty */
	| KEYWORD '=' WORD				
		{ set_keyword($1, $3, VT_WORD); }

	| KEYWORD '=' STRING
		{ set_keyword($1, $3, VT_STRING); }

	| KEYWORD '=' NUMBER			
		{ set_keyword($1, &$3, VT_NUMBER); }

	| KEYWORD '=' IPADDR			
		{ set_keyword($1, $3, VT_IPADDR); }

	| KW_DH_GROUP '=' NUMBER
		{
			int		i;
			long	groups[] = { 768, 1024, 1536, 2048, 3072, 4096, 0 };

			/* check validity */
			for (i = 0; groups[i] && groups[i] != $3; i++)
				;

			if (!groups[i])
				yyerror("invalid dh-group");
		
			/* assign value */
			conf_dh_group = $3;
		}

	| KW_HOST '=' identity
		{ STRCPY(conf_host, $3); }

	| KW_RSA_KEY '=' STRING
		{ SETPTR(conf_rsa_key, $3); }

	| KW_RSA_KEY_FILE '=' STRING
		{ STRCPY(conf_rsa_key_file, $3); }

	| KW_PEER identity '{' peer_statements '}'
		{
			PEERENTRY* pe = (PEERENTRY*)malloc(sizeof(PEERENTRY));
			if (!pe) yyerror("nomem");
			pe->identity = $2;
			pe->options = $4;
			pe->next = conf_peers;
			conf_peers = pe;
		}

	| KW_ORDER '=' KW_ALLOW ',' KW_DENY
		{ conf_search_order = SO_ALLOW_DENY; }

	| KW_ORDER '=' KW_DENY  ',' KW_ALLOW
		{ conf_search_order = SO_DENY_ALLOW; }

	| KW_ALLOW '=' list
		{ SETPTR(conf_allow_peers, $3); }

	| KW_DENY  '=' list
		{ SETPTR(conf_deny_peers, $3); }
	;

peer_statements: /* non-empty */
	  peer_statement ';'
	| peer_statements peer_statement ';'
		{ append_to_list($1, $2); }
	;

peer_statement: /* non-empty */
	  KW_PSK '=' STRING
		{ $$ = str_to_lentry($3, ST_PSK); }

	| KW_PSK_FILE '=' STRING
		{ $$ = str_to_lentry($3, ST_PSK_FILE); }

	| KW_RSA_PUB '=' STRING
		{ $$ = str_to_lentry($3, ST_RSA_PUB); }

	| KW_RSA_PUB_FILE '=' STRING
		{ $$ = str_to_lentry($3, ST_RSA_PUB_FILE); }

	| KW_AUTH '=' KW_NONE
		{ $$ = str_to_lentry(NULL, ST_AUTH_NONE); }

	| KW_AUTH '=' KW_PSK
		{ $$ = str_to_lentry(NULL, ST_AUTH_PSK); }

	| KW_AUTH '=' KW_RSA
		{ $$ = str_to_lentry(NULL, ST_AUTH_RSA); }
	;

list: list_entry
	| list ',' list_entry
		{ append_to_list($1, $3); }
	;

list_entry: /* non-empty */
	  WORD		{ $$ = str_to_lentry($1, VT_WORD); }
	| STRING	{ $$ = str_to_lentry($1, VT_STRING); }
	| IPADDR	{ $$ = str_to_lentry($1, VT_IPADDR); }
	| NET_MASK	{ $$ = str_to_lentry($1, VT_NET_MASK); }
	| NET_CIDR	{ $$ = str_to_lentry($1, VT_NET_CIDR); }
	;

identity: WORD | STRING	| IPADDR | NET_MASK	| NET_CIDR
	;

%%

/*
 * public functions
 */

void conf_free()
{
	PEERENTRY* pe;
	
	/* free conf_allow_peers */
	free_list(conf_allow_peers);
	conf_allow_peers = (LISTENTRY*)NULL;
	
	/* free conf_deny_peers */
	free_list(conf_deny_peers);
	conf_deny_peers = (LISTENTRY*)NULL;
	
	/* free conf_peers */
	pe = conf_peers;
	while (pe) {
		PEERENTRY* tmp = pe;
		free(pe->identity);
		free_list(pe->options);
		pe = pe->next;
		free(tmp);
	}
	conf_peers = (PEERENTRY*)NULL;

	/* free host credentials */
	free(conf_rsa_key);
	conf_rsa_key = NULL;

	/* free allow, deny lists */
	free(conf_allow_peers);
	free(conf_deny_peers);
}
	  
/*
 * local functions
 */

void set_keyword(const char* name, void* value, int type) 
{
	typedef struct keyword_entry {
		char*	name;
		void*	value;
		int		size;
		int		type;
	} keyword_entry;
	
	static keyword_entry keyword_map[] = {
	{ "pid-file",	conf_pid_file,		sizeof(conf_pid_file),	 VT_STRING },
	{ "keydb-file",	conf_keydb_file,	sizeof(conf_keydb_file), VT_STRING },
	{ "sock-file",	conf_sock_file,		sizeof(conf_sock_file),	 VT_STRING },
	{ "listen",		conf_listen,		sizeof(conf_listen),	 VT_IPADDR },
	{ "verbose",	&conf_verbose,		0, VT_NUMBER | VT_WORD | VT_STRING },
	{ "flush-db",	&conf_flush_db,		0, VT_NUMBER | VT_WORD | VT_STRING },
	{ "egid",		&conf_egid,			0, 						 VT_NUMBER },
	{ "port",		&conf_port,			0, 						 VT_NUMBER },
	{ (char*)NULL,	0,					0, 0 } };

	int i;
	struct keyword_entry* ke = NULL;

	for (i = 0; keyword_map[i].name; i++)
		if (!strcmp(keyword_map[i].name, name)) {
			ke = &keyword_map[i];
			break;
		}

	if (!ke || !(ke->type & type)) 
		yyerror("syntax error");

	switch (ke->type) {
	case VT_STRING:
	case VT_IPADDR:
		if (strlen((char*)value) >= ke->size)
 			yyerror("string is too long");
		strcpy((char*)ke->value, (char*)value);
		break;

	case VT_NUMBER:
		*((int*)ke->value) = *((int*)value);
		break;

	case VT_NUMBER | VT_WORD | VT_STRING:
		*((int*)ke->value) = (type == VT_NUMBER) ? *((int*)value) :
			(!strcasecmp((char*)value, "yes") ||
			tolower(*((char*)value)) == 'y');
		break;
	}
}

void* str_to_lentry(char* data, char type)
{
	LISTENTRY* le = (LISTENTRY*)malloc(sizeof(LISTENTRY));
	if (!le) yyerror("nomem");
	le->data = data;
	le->type = type;
	le->next = (LISTENTRY*)NULL;
	return (void*)le;
}

void append_to_list(void* list, void* item)
{
	LISTENTRY* curr = (LISTENTRY*)list;
	while (curr->next)
		curr = curr->next;
	curr->next = (LISTENTRY*)item;
}

void free_list(LISTENTRY* le) 
{
	while (le) {
		LISTENTRY* tmp = le;
		free(le->data);
		le = le->next;
		free(tmp);
	}
}

