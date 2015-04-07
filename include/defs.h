/* defs.h - SharedSecret project.

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


#ifndef _DEFS_H
#define _DEFS_H


/* common constants */
#define SOCK_FILE					LOCALSTATEDIR "/run/shsec/shsecd.sock"
#define	CURRENT_PROTOCOL_VERSION	((char)1)
#define	DEFAULT_PORT				24680


/* status byte encoding:
 * 8-7 bits - scope 
 * 6-1 bits - error code.
 */
#define SCOPE_CLIENT		1
#define SCOPE_HOST			2
#define SCOPE_PEER			3
#define MK_STATUS(s,e)		(((s)<<6)|(e))
#define GET_SCOPE(v)		(((v)&0xC0)>>6)
#define GET_ERR(v)			((v)&0x3F)
#define STATUS_SUCCESS		0

/* error codes */
#define ERR_SUCCESS			0	/* ok */
#define ERR_UNKNOWN			1	/* unknown error */
#define ERR_ACCESS_DENIED	2	/* access denied */
#define ERR_COMM			3	/* communication problems */
#define ERR_INVALID_PARAM	4	/* invalid parameter */
#define ERR_INTERNAL		5	/* internal error */
#define ERR_KEY_EXISTS		6	/* key for requested host:tag already exists */
#define ERR_KEY_NOT_EXISTS	7	/* key does not exists */
#define ERR_KEY_EXPIRED		8	/* key expired and has been deleted */
#define ERR_PROTOCOL		9	/* unsupported protocol */
#define ERR_ENCODING		10	/* package encoding error */
#define ERR_DECODING		11	/* package decoding error */
#define ERR_MALFORMED		12	/* malformed data */
#define ERR_NOT_AVAILABLE	13	/* resource is not available */
#define ERR_NOT_SUPPORTED	14	/* option is not supported */
#define ERR_SIGNATURE		15	/* calculate signature error */
#define ERR_SIG_VERIFY		16	/* verify signature error */


/* algorithm OIDs */
#define	OID_HMAC_SHA1		"1.3.6.1.5.5.8.1.2"
#define	OID_RSA_MD5			"1.2.840.113549.1.1.4"


/* request flags */
#define FLAG_INIT_KEY		1
#define FLAG_STORE_KEY		2
#define FLAG_KEEP_KEY		4
#define FLAG_DELETE_KEY		8
#define FLAG_LIST_KEYS		16

/* return non-zero in case of error */
#define check_flag_validity(f)	\
	/* if delete flags is set, it must be the only one */ \
	(((f) & FLAG_DELETE_KEY) && (f) != FLAG_DELETE_KEY) || \
	/* if responder wants to keep a key, initiator's flags not to be used */ \
	(((f) & FLAG_KEEP_KEY) && (((f) & FLAG_INIT_KEY) || ((f) & FLAG_STORE_KEY)))


/* Diffie-Hellman groups */
#define DH_GROUP_768		768
#define DH_GROUP_1024		1024
#define DH_GROUP_1536		1536
#define DH_GROUP_2048		2048
#define DH_GROUP_3072		3072
#define DH_GROUP_4096		4096


/* define some limits */
#define MAX_PATH_LEN		256
#define MAX_TAG_LEN			20
#define MAX_HOST_LEN		100
#define MAX_KEY_LEN			DH_GROUP_768
#define MAX_DH_GROUP_BYTES	DH_GROUP_4096/8+1
#define MAX_TBSBITS_LEN		MAX_TAG_LEN+MAX_HOST_LEN+MAX_DH_GROUP_BYTES+100
#define MAX_OID_LEN			32
#define MAX_SIG_LEN			32
#define MAX_GENTIME_LEN		20


/* key length is not nessisarally octet aligned */
#define	BITS_TO_BYTES(l)	((l)/8+((l)%8?1:0))

/* convert char[2] into short after asn1 decoding */
#define	ASN1_NTOHS(v,l) \
	((l)==1?(*((unsigned char*)&v)):(ntohs(*((unsigned short*)&v))))


/* client request types */
#define	CRT_REQUEST_KEY		1
#define	CRT_DELETE_KEY		2
#define	CRT_ENUM_KEYS		3


#pragma pack(1)

/* key format 
 * key-id consist of null-terminated string in form of tag@peer */
typedef struct _KEY_VAL {
	unsigned long	expires;			/* In seconds since Epoch (hbo) */
	unsigned char	key_len;			/* number of bits (hbo) */
	unsigned char	key[1];				/* key */
} KEY_VAL, *PKEY_VAL;

#define KEY_VAL_SIZE sizeof(KEY_VAL)-1

#pragma pack()


#endif /* _DEFS_H */

