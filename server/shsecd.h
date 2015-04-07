/* shsecd.h - SharedSecret project.

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

#ifndef _SHSECD_
#define _SHSECD_

#include <openssl/bn.h>		/* for BIGNUM declaration */
#include <time.h>			/* for time_t declaration */

/* constants for daemon */
#define PROGRAM_NAME	"shsecd"
#define CONF_FILE		SYSCONFDIR "/shsecd.conf"
#define PID_FILE		LOCALSTATEDIR "/run/shsec/shsecd.pid"
#define KEYDB_FILE		LOCALSTATEDIR "/run/shsec/shsecd.db"

/* Authentication method for peer */
#define	AUTH_NONE		0			/* no signatures required */
#define	AUTH_PSK		1			/* HMAC-SHA1 signatures required */
#define	AUTH_RSA		2			/* RSA-MD5 signatures required */

/* list of cookies */
typedef struct COOKIE {
	unsigned char	cookie[4];
	char*			expires;
	struct COOKIE*	next;
} COOKIE;

/* peer's credentials */
typedef	struct PEER_ENTRY {
	char*				identity;
	char				type;		/* VT_ */
	unsigned long		ipaddr;		/* host or network (broadcast addr) */
	char				allow;		/* non-zero to allow access */
	char				auth;		/* AUTH_ */
	unsigned char*		cred;		/* psk or pub */
	int					cred_len;
	struct COOKIE*		cookies;
	struct PEER_ENTRY*	next;
} PEER_ENTRY;


/* structures for internal usage. all values are in hbo */
typedef struct CLI_REQUEST {
	unsigned char	reqType, version, flags;
	unsigned short	keyLen;								/* keyLen in bits */
	unsigned short	port;
	char			tag[MAX_TAG_LEN], peer[MAX_HOST_LEN];
	char			expires[MAX_GENTIME_LEN];
} CLI_REQUEST, *PCLI_REQUEST;

typedef struct CLI_RESPONSE {
	unsigned char	reqType, version, status, key[MAX_KEY_LEN];
	unsigned short	keyLen;								/* keyLen in bits */
} CLI_RESPONSE, *PCLI_RESPONSE;

typedef struct SRV_MESSAGE {
	unsigned char	version, tbsMsg[MAX_TBSBITS_LEN];
	unsigned char	sigAlg[MAX_OID_LEN], sig[MAX_SIG_LEN];
	int				tbsMsg_len, sigAlg_len, sig_len;	/* signature in bits */
} SRV_MESSAGE, *PSRV_MESSAGE;

typedef struct SRV_REQUEST {
	unsigned short	cookie, keyLen, dhGroup;
	char			tag[MAX_TAG_LEN], host[MAX_HOST_LEN];
	char			expires[MAX_GENTIME_LEN];
	unsigned char	dhPublic[MAX_DH_GROUP_BYTES];
	int				dhPublic_len;
} SRV_REQUEST, *PSRV_REQUEST;

typedef struct SRV_RESPONSE {
	unsigned short	cookie;
	unsigned char	status, dhPublic[MAX_DH_GROUP_BYTES];
	int				dhPublic_len;
} SRV_RESPONSE, *PSRV_RESPONSE;


/* function prototypes from keydb.c */
void keydb_open(int flush_keys);		/* open database or flush all keys.
										 * exit on failure */
void keydb_close();						/* close database */
int  keydb_store(const char* keyid, char* buff, int size);	/* store key */
int  keydb_fetch(const char* keyid, char* buff, int* psize);/* fetch key */
int  keydb_delete(const char* keyid);						/* delete key */
int  keydb_exists(const char* keyid);	/* check if key exists  */
/* enum keys. return value: 0 if no (more) items exist, >0 in case of
   success success and <0 if error accours. for the 1st call, caller
   must allocate opaque at least sizeof(char*)+sizeof(int) and fill-in
   with zeros. */
int keydb_enum_keys(char* buff, int* psize, void* opaque);


/* function prototypes from dh.c */
int dh_init_group_params(int dh_group, BIGNUM** pprime, BIGNUM** pbase);
int dh_gen_private_public(int dh_group, BIGNUM* prime, BIGNUM* base,
	BIGNUM** pprivate, unsigned char** ppublic, int* ppublic_len);
int dh_get_secret(const unsigned char* public, short public_len,
	BIGNUM* private, BIGNUM* prime, unsigned char** psecret_key,
	int* psecret_key_len);


/* function prototypes from asn1.c */
void asn1_init();
void asn1_free();
int decode_client_request(unsigned char* buf, int buf_len, PCLI_REQUEST preq);
int encode_client_response(PCLI_RESPONSE presp, unsigned char* buf, int* plen); 
int encode_server_message(PSRV_MESSAGE pmsg, unsigned char* buf, int* plen);
int decode_server_message(unsigned char* buf, int buf_len, PSRV_MESSAGE pmsg);
int encode_server_request(PSRV_REQUEST preq, unsigned char* buf, int* plen);
int decode_server_request(unsigned char* buf, int buf_len, PSRV_REQUEST preq);
int encode_server_response(PSRV_RESPONSE presp, unsigned char* buf, int* plen);
int decode_server_response(unsigned char* buf, int buf_len,
	PSRV_RESPONSE presp);


/* function prototypes from peer.c */
void build_peer_list();
void free_peer_list();
PEER_ENTRY* find_peer_by_id(const char* identity);
PEER_ENTRY* find_peer_by_ipaddr(long ipaddr);
PEER_ENTRY* find_peer(const char* identity);


/* function prototypes from sig.c */
int sign_message(PEER_ENTRY* peer,
	const unsigned char* tbsMsg, int tbsMsg_len,
	unsigned char* sigAlg, int* psigAlg_len,
	unsigned char* sig, int* psig_len);
int verify_signature(PEER_ENTRY* peer,
	const unsigned char* tbsMsg, int tbsMsg_len,
	const unsigned char* sigAlg, int sigAlg_len,
	const unsigned char* sig, int sig_len);


/* function prototypes from utils.c */
void output(int loglevel, const char* fmt, ...);
void check_rc(int rc, const char* fn);
unsigned int get_der_seq_size(unsigned char* buf);
int time_t_to_gentime(time_t time, char* gentime);
time_t gentime_to_time_t(const char* gentime);

	 
#ifndef DEBUG
# define DUMP_BIN(data,len,msg)		/* do nothing */
# define DUMP_BN(bn,msg)			/* do nothing */
#else
# define DUMP_BIN(data,len,msg)		dump_bin(data,len,msg);
# define DUMP_BN(bn,msg)			dump_bn(bn,msg);
extern void dump_bin(unsigned char* data, int len, const char* msg);
extern void dump_bn(BIGNUM* bn, const char* msg);
#endif /* DEBUG */

#endif /* _SHSECD_ */
