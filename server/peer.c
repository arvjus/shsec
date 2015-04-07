/* asn1.c - SharedSecret project.

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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <memory.h>
#include <assert.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "defs.h"
#include "conf_defs.h"
#include "shsecd.h"


#define	IPADDR_INVALID	-1

PEER_ENTRY* peer_list = (PEER_ENTRY*)NULL;

/* read value from file as is or fail */
void read_file(const char* path, unsigned char** pval, int* plen)
{
	FILE* file;

	file = fopen(path, "rb");
	if (!file) {
		output(LOG_ERR, "error: fopen failed. %s", path);
		exit(1);
	}
	
	if(fseek(file, 0L, SEEK_END) == -1) {
		output(LOG_ERR, "error: fseek failed. %s", strerror(errno));
		exit(1);
	}
	
	*plen = ftell(file);
	*pval = malloc(*plen);
	if (!*pval) {
		output(LOG_ERR, "error: memory allocation failed");
		exit(1);
	}

	if(fseek(file, 0L, SEEK_SET) == -1) {
		output(LOG_ERR, "error: fseek failed. %s", strerror(errno));
		exit(1);
	}

	if(fread(*pval, *plen, 1, file) != 1) {
		output(LOG_ERR, "error: fread failed. %s", strerror(errno));
		exit(1);
	}

	fclose(file);
}

/* build peer_list form configuration */
void build_peer_list()
{
	PEER_ENTRY*	pentry, *last = (PEER_ENTRY*)NULL;
	PEERENTRY*	pe;
	LISTENTRY*	le, *opt;
	int			count = 0, allow = (conf_search_order == SO_ALLOW_DENY);
	int			auth_count, psk_count, rsa_count;
	int			nums[8], num;
	long		ipaddr, netmask;
	struct hostent* h;
	
	do {
		for (le = (allow ? conf_allow_peers : conf_deny_peers); le;
			 le = le->next) {

			/* set peer entry - common */
			pentry = (PEER_ENTRY*)calloc(sizeof(PEER_ENTRY), 1);
			if (!pentry) {
				output(LOG_ERR, "error: memory allocation failed");
				exit(1);
			}

			pentry->identity = le->data;
			le->data = NULL;
			pentry->type = le->type;
			pentry->allow = allow;

			/* get host/net address, netmask */
			switch (pentry->type) {
			case VT_WORD:
			case VT_STRING:
				h = gethostbyname(pentry->identity);
				if (h) 
					pentry->ipaddr = *((long*)h->h_addr);
				else {
					output(LOG_ERR, "error: cannot resolve name for '%s'."
						"access is denied", pentry->identity);
					pentry->ipaddr = IPADDR_INVALID;
					pentry->allow = 0;
				}
				break;

			case VT_IPADDR:
				num = sscanf(pentry->identity, "%d.%d.%d.%d",
					&nums[0], &nums[1], &nums[2], &nums[3]);
				assert(num == 4);
				ipaddr = nums[0]<<24|nums[1]<<16|nums[2]<<8|nums[3];
				pentry->ipaddr = htonl(ipaddr);
				break;

			case VT_NET_MASK:
				num = sscanf(pentry->identity, "%d.%d.%d.%d/%d.%d.%d.%d",
					&nums[0], &nums[1], &nums[2], &nums[3],
					&nums[4], &nums[5], &nums[6], &nums[7]);
				assert(num == 8);
				ipaddr = nums[0]<<24|nums[1]<<16|nums[2]<<8|nums[3];
				netmask = nums[4]<<24|nums[5]<<16|nums[6]<<8|nums[7];
				pentry->ipaddr = htonl(ipaddr | ~netmask);
				break;

			case VT_NET_CIDR:
				num = sscanf(pentry->identity,"%d.%d.%d.%d/%d",
					&nums[0], &nums[1], &nums[2], &nums[3], &nums[4]);
				assert(num == 5);
				ipaddr = nums[0]<<24|nums[1]<<16|nums[2]<<8|nums[3];
				netmask = 0;
				while (nums[4]--) netmask |= (0x80000000 >> nums[4]);
				pentry->ipaddr = htonl(ipaddr | ~netmask);
				break;
			}
			
			/* add to the end of list */
			if (last) 
				last->next = pentry;
			else 
				peer_list = pentry;
			last = pentry;
			
			if (!pentry->allow)
				continue;
			
			/* find a peer record */
			for (pe = conf_peers; pe; pe = pe->next) 
				if(!strcmp(pe->identity, pentry->identity))
					break;

			if (!pe) {
				output(LOG_ERR, "error: missing definition "
					"for peer '%s'", le->data);
				exit(1);
			}

			/* set peer entry for allow */
			auth_count = psk_count = rsa_count = 0;
			for (opt = pe->options; opt; opt = opt->next) 
				switch (opt->type) {
				case ST_PSK:
					pentry->cred = opt->data;
					pentry->cred_len = strlen(pentry->cred);
					opt->data = NULL;
					psk_count ++;
					break;

				case ST_PSK_FILE:
					read_file(opt->data, &pentry->cred, &pentry->cred_len);
					psk_count ++;
					break;

				case ST_RSA_PUB:
					pentry->cred = opt->data;
					pentry->cred_len = strlen(pentry->cred);
					opt->data = NULL;
					rsa_count ++;
					break;

				case ST_RSA_PUB_FILE:
					read_file(opt->data, &pentry->cred, &pentry->cred_len);
					rsa_count ++;
					break;

				case ST_AUTH_NONE:
					auth_count ++;
					pentry->auth = AUTH_NONE;
					break;

				case ST_AUTH_PSK:
					auth_count ++;
					pentry->auth = AUTH_PSK;
					break;

				case ST_AUTH_RSA:
					auth_count ++;
					pentry->auth = AUTH_RSA;
					break;

				default:
					assert(0);
				}

			/* make sure values corresponds to access method */
			if (auth_count != 1 || psk_count + rsa_count > 1 ||
				(pentry->auth == AUTH_NONE && psk_count + rsa_count) ||
				(pentry->auth == AUTH_PSK && !psk_count) ||
				(pentry->auth == AUTH_RSA && !rsa_count)) {
				output(LOG_ERR, "error: inconsistent/ambiguous definition "
					"for peer '%s'", pentry->identity);
				exit(1);
			}
		}

		allow = !allow;
	} while (++count < 2);
}

/* free allocated structures */
void free_peer_list()
{
	PEER_ENTRY* pe;

	for (pe = peer_list; pe; ) {
		COOKIE* cookie;
		PEER_ENTRY* pe_tmp = pe;
		free(pe->identity);
		free(pe->cred);
		for (cookie = pe->cookies; cookie; ) {
			COOKIE* cookie_tmp = cookie;
			free(cookie->expires);
			cookie = cookie->next;
			free(cookie_tmp);
		}
		
		pe = pe->next;
		free(pe_tmp);
	}

	peer_list = (PEER_ENTRY*)NULL;
}

/* find a peer and return an entry */
PEER_ENTRY* find_peer_by_id(const char* identity)
{
	PEER_ENTRY* 	pe;
	
	for (pe = peer_list; pe; pe = pe->next) 
		if(!strcmp(pe->identity, identity))
			break;

	return pe;
}

/* find a peer and return an entry */
PEER_ENTRY* find_peer_by_ipaddr(long ipaddr)
{
	PEER_ENTRY* pe;

	for (pe = peer_list; pe; pe = pe->next)
		if(pe->ipaddr != IPADDR_INVALID &&
			(!pe->ipaddr || (pe->ipaddr & ipaddr) == ipaddr))
			break;

	return pe;
}

/* find a peer and return an entry */
PEER_ENTRY* find_peer(const char* identity)
{
	char addr_accept[] = "0123456789.";
	struct in_addr	inaddr;
	PEER_ENTRY* 	pe;
	
	if (strspn(identity, addr_accept) == strlen(identity) &&
		inet_aton(identity, &inaddr)) {

		pe = find_peer_by_ipaddr(inaddr.s_addr);
	}
	else {
		pe = find_peer_by_id(identity);
		if (!pe) {
			struct hostent* h = gethostbyname(identity);
			if (h) {
				unsigned long ipaddr = *((unsigned long*)h->h_addr);
				pe = find_peer_by_ipaddr(ipaddr);
			}
		}
	}

	return pe;
}
