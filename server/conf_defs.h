/* conf.h - SharedSecret project.

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

#ifndef _CONF_DEFS_H
#define _CONF_DEFS_H

/* common constants */
#ifndef MAX_FILE_LEN
# define MAX_FILE_LEN	256
#endif

#ifndef MAX_HOST_LEN
# define MAX_HOST_LEN	100
#endif

/* value types */
#define	VT_NUMBER		0x01
#define	VT_WORD			0x02
#define	VT_STRING		0x04
#define	VT_IPADDR		0x08
#define	VT_NET_MASK		0x10
#define	VT_NET_CIDR		0x20

/* statement types */
#define	ST_PSK			0x01
#define	ST_PSK_FILE		0x02
#define	ST_RSA_PUB		0x04
#define	ST_RSA_PUB_FILE	0x08
#define	ST_AUTH_NONE	0x10
#define	ST_AUTH_PSK		0x20
#define	ST_AUTH_RSA		0x40

/* search order */
#define	SO_ALLOW_DENY	0
#define	SO_DENY_ALLOW	1

/* list_entry definition */
typedef struct LISTENTRY {
	char*				data;
	char				type;
	struct LISTENTRY*	next;
} LISTENTRY;

/* PEER definition */
typedef struct PEERENTRY {
	char*				identity;
	struct LISTENTRY*	options;
	struct PEERENTRY*	next;
} PEERENTRY;


/* global conf_XXX variables */
extern  int			conf_egid;
extern  char		conf_pid_file[];
extern  char		conf_keydb_file[];
extern  char		conf_sock_file[];
extern  int			conf_verbose;
extern  int			conf_flush_db;
extern  int			conf_dh_group;
extern  char		conf_listen[];
extern  int			conf_port;
extern  char		conf_host[];
extern  char*		conf_rsa_key;
extern  char		conf_rsa_key_file[];
extern	int			conf_search_order;	/* SO_XXX */
extern	LISTENTRY*	conf_allow_peers;
extern	LISTENTRY*	conf_deny_peers;
extern	PEERENTRY*	conf_peers;

/* puclic functions */
int conf_init(const char* file);		/* reads config file and fills-in
										   conf_XXX variables */
void conf_free();						/* frees all allocated structures */

#endif /* _CONF_DEFS_H */
