/* shsecd.c - SharedSecret project.

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
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <getopt.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netdb.h>
#include <openssl/bn.h>
#include "config.h"
#include "defs.h"
#include "conf_defs.h"
#include "shsecd.h"


/*****************************************************************************/
/* command line arguments and configuration options                          */
/*****************************************************************************/

/* command line arguments */
int parm_verbose = 0;	/* command line option has precedence */
int conf_daemon = 1;	/* run as daemon by default */
int conf_child = 0;		/* for child debugging */
int keydb_cleaner = 0;	/* pid of that child process */
char conf_file[MAX_FILE_LEN];


/* print usage */
void print_help(FILE* stream, int exit_code)
{
	fprintf(stream,
"shsec (Shared Secret) daemon. version %s\n"
"Copyright (C) 2004 - Arvydas Juskaitis <arvydasj@users.sourceforge.net>\n\n"
"usage: %s [-hVvdDC] [-c file]\n"
"-h,   --help         Print this option list, then exit.\n"
"-V,   --version      Print version number, then exit.\n"
"-v,   --verbose      Be verbose. To increase level, specify twice.\n"
"-d,   --daemon       Run as daemon, use syslog for logging.\n"
"-D,   --debug        Do not fork and print messages to stderr.\n"
"-C,   --child-debug  If set, children go to sleep to be able to debug.\n"
"-c f, --conf-file f  Path to config file. Default is %s\n\n",
VERSION, PROGRAM_NAME, CONF_FILE);
	
	exit(exit_code);
}

/* set defaults for configurable variables */
void set_conf_defaults()
{
	strcpy(conf_file, CONF_FILE);
	strcpy(conf_pid_file, PID_FILE);
	strcpy(conf_keydb_file, KEYDB_FILE);
	strcpy(conf_sock_file, SOCK_FILE);
	conf_verbose = 0;
	conf_flush_db = 1;
	conf_dh_group = DH_GROUP_1024;
	strcpy(conf_listen, "0.0.0.0");
	conf_port = DEFAULT_PORT;
	conf_search_order = SO_ALLOW_DENY;
	
	if (gethostname(conf_host, MAX_HOST_LEN) == -1) {
		output(LOG_ERR, "error: cannot get current host name\n");
		exit(1);
	}
}

/* parse command line */
void get_options(int argc, char* argv[])
{
	int next_option;

	const char* const short_options = "hVvdDCc:";

	const struct option long_options[] = {
		{ "help",			0, NULL, 'h' },
		{ "version",		0, NULL, 'V' },
		{ "verbose",		0, NULL, 'v' },
		{ "daemon",			0, NULL, 'd' },
		{ "debug",			0, NULL, 'D' },
		{ "child-debug",	0, NULL, 'C' },
		{ "conf-file",		1, NULL, 'c' },
		{ NULL,				0, NULL, 0   }
	};

	/* get options */
	do {
		next_option = getopt_long(argc, argv, short_options, long_options, 0);
		
		switch(next_option) {
		case 'h':
			print_help(stdout, 0);
			
		case 'V':
			fprintf(stdout, "%s %s\n", PROGRAM_NAME, VERSION);
			exit(0);
			break;
			
		case 'v':
			parm_verbose ++;
			break;
			
		case 'd':
			conf_daemon = 1;
			break;
			
		case 'D':
			conf_daemon = 0;
			break;

		case 'C':
			conf_child = 1;
			break;

		case 'c':
			if (strlen(optarg) + 1 >= sizeof(conf_file)) {
				output(LOG_ERR, "error: conf-file name is too long");
				exit(1);
			}
			
			strcpy(conf_file, optarg);
			break;
			
		case '?':
			print_help(stderr, 1);
		};
	} while (next_option != -1);

	/* check for non-options */
	if (optind < argc) {
		print_help(stderr, 1);
	}
}


/*****************************************************************************/
/* various subroutines                                                       */
/*****************************************************************************/
unsigned short generate_unique_cookie()
{
	unsigned short ret;

	do {
		ret = rand();
	} while (!ret);

	return ret;
}


/*****************************************************************************/
/* processing of requests/responses                                          */
/*****************************************************************************/

/* accept and process request form local client */
void process_client_request(int fd_un2) 
{
	int	len, len_toreceive, len_received, len_tosend, len_sent;
	int rc, fd_in = 0;

	CLI_REQUEST		creq;
	CLI_RESPONSE	cresp;
	SRV_REQUEST		sreq;
	SRV_RESPONSE	sresp;
	SRV_MESSAGE		smsg;
	char 			buf[2048];
	
	char			keyid[MAX_TAG_LEN + MAX_HOST_LEN + 10];

	BIGNUM 			*bn_base = NULL, *bn_prime = NULL, *bn_private = NULL;
	unsigned char*	public = NULL;
	int				public_len;
	unsigned char*	secret_key = NULL;
	int				secret_key_len;

	memset(&cresp, 0, sizeof(cresp));
	memset(&sreq, 0, sizeof(sreq));
	memset(&smsg, 0, sizeof(smsg));
		
	/* receive request - we can expect at least 7 first bytes to receive */
	len = recv(fd_un2, buf, 7, 0);
	if (len < 0) {
		output(LOG_ERR, "recv failed. %s", strerror(errno));
		cresp.status = MK_STATUS(SCOPE_HOST, ERR_COMM);
		goto send;
	}
	else if (!len) return;

	len_received = len;
	len_toreceive = get_der_seq_size(buf);
	if (len_toreceive > sizeof(buf)) {
		output(LOG_ERR, "packet sent by client is too big");
		cresp.status = MK_STATUS(SCOPE_CLIENT, ERR_MALFORMED);
		goto send;
	}

	/* get the rest */
	while (len_toreceive > len_received) {
		len = len_toreceive - len_received;
		len = recv(fd_un2, &buf[len_received], len, 0);
		if (len < 0) {
			output(LOG_ERR, "recv failed. %s", strerror(errno));
			cresp.status = MK_STATUS(SCOPE_HOST, ERR_COMM);
			goto send;
		}
		else if (!len) return;

		len_received += len;
	}

	/* decode request message */
	rc = decode_client_request(buf, len_received, &creq);
	if (rc) {
		cresp.status = MK_STATUS(SCOPE_CLIENT, rc);
		goto send;
	}

	/* check if parameters, flags are valid */
	if (creq.version != CURRENT_PROTOCOL_VERSION) {
		output(LOG_ERR, "unsupported protocol version %d", creq.version);
		cresp.status = MK_STATUS(SCOPE_CLIENT, ERR_PROTOCOL);
		goto send;
	}

	if (check_flag_validity(creq.flags)) {
		output(LOG_ERR, "not allowed option combination");
		cresp.status = MK_STATUS(SCOPE_CLIENT, ERR_INVALID_PARAM);
		goto send;
	}

	if (creq.reqType == CRT_ENUM_KEYS) {
		cresp.status = STATUS_SUCCESS;
		goto send;
	}
	else
	if (creq.reqType == CRT_REQUEST_KEY &&
		(!creq.keyLen || creq.keyLen > MAX_KEY_LEN)) {
		output(LOG_ERR, "invalid size of requested key: %d", creq.keyLen);
		cresp.status = MK_STATUS(SCOPE_CLIENT, ERR_INVALID_PARAM);
		goto send;
	}

	/* make keyid */
	sprintf(keyid, "%s@%s", creq.tag, creq.peer);
	
	/* process request */
	if (creq.reqType == CRT_DELETE_KEY) {
		/* check for a key in database and delete it */
		if (keydb_exists(keyid)) {
			rc = keydb_delete(keyid);
			if (rc) {
				output(LOG_ERR, "keydb_delete failed. %s", strerror(errno));
				cresp.status = MK_STATUS(SCOPE_HOST, ERR_INTERNAL);
			}
		}
		else {
			output(LOG_ERR, "requested key does not exist: '%s'", keyid);
			cresp.status = MK_STATUS(SCOPE_HOST, ERR_KEY_NOT_EXISTS);
		}
	}
	/* here we block and get requested key */
	else if (creq.flags & FLAG_INIT_KEY) {
		struct sockaddr_in peer_addr;
		char addr_accept[] = "0123456789.";
		PEER_ENTRY* pe;

		/* locate and check the peer */
		pe = find_peer(creq.peer);
		if (!pe) {
			output(LOG_ERR, "peer '%s' is not available", creq.peer);
			cresp.status = MK_STATUS(SCOPE_HOST, ERR_NOT_AVAILABLE);
			goto send;
		}
		else
		if (!pe->allow) {
			output(LOG_ERR, "access denied for peer '%s'", creq.peer);
			cresp.status = MK_STATUS(SCOPE_HOST, ERR_ACCESS_DENIED);
			goto send;
		}
		
		/* generate secret, calculate public value */
		rc = dh_init_group_params(conf_dh_group, &bn_prime, &bn_base);
		if (rc) {
			output(LOG_ERR, "dh_init_group_params failed");
			cresp.status = MK_STATUS(SCOPE_HOST, rc);
			goto send;
		}
		DUMP_BN(bn_prime, "prime ");
		DUMP_BN(bn_base, "base  ");
		
		rc = dh_gen_private_public(conf_dh_group, bn_prime, bn_base,
			&bn_private, &public, &public_len);
		if (rc) {
			output(LOG_ERR, "dh_gen_private_public failed");
			cresp.status = MK_STATUS(SCOPE_HOST, rc);
			goto send;
		}
		DUMP_BN(bn_private, "priv-i");
		DUMP_BIN(public, public_len, "publ-i");
		
		/* fill-in request */
		sreq.cookie = generate_unique_cookie();
		sreq.keyLen = creq.keyLen;
		strncpy(sreq.tag, creq.tag, sizeof(sreq.tag));
		strncpy(sreq.host, conf_host, sizeof(sreq.host));
		strncpy(sreq.expires, creq.expires, sizeof(sreq.expires));
		sreq.dhGroup = conf_dh_group;
		sreq.dhPublic_len = public_len;
		memcpy(sreq.dhPublic, public, public_len);

		smsg.tbsMsg_len = sizeof(smsg.tbsMsg);
		rc = encode_server_request(&sreq, smsg.tbsMsg, &smsg.tbsMsg_len);
		if (rc) {
			cresp.status = MK_STATUS(SCOPE_HOST, rc);
			goto send;
		}

		/* fill-in request message */
		smsg.version = CURRENT_PROTOCOL_VERSION;

		/* sign request if required */
		if (pe->auth != AUTH_NONE) {
			rc = sign_message(pe, smsg.tbsMsg, smsg.tbsMsg_len,
				smsg.sigAlg, &smsg.sigAlg_len, smsg.sig, &smsg.sig_len);
			if (rc) {
				cresp.status = MK_STATUS(SCOPE_HOST, rc);
				goto send;
			}
		}

		/* encode message */	
		len = sizeof(buf);
		rc = encode_server_message(&smsg, buf, &len);
		if (rc) {
			cresp.status = MK_STATUS(SCOPE_HOST, rc);
			goto send;
		}
	
		/* get peer id & address, connect to socket and send the message */
	
		/* is it ip address? */
		if (strspn(creq.peer, addr_accept) == strlen(creq.peer)) {
			if (!inet_aton(creq.peer, &(peer_addr.sin_addr))) {
				output(LOG_ERR, "inet_aton failed");
				cresp.status = MK_STATUS(SCOPE_HOST, ERR_COMM);
				goto send;
			}
		}

		/* resolve dns */
		else {
			struct hostent* h = gethostbyname(creq.peer);
			if (!h) {
				output(LOG_ERR, "gethostbyname failed");
				cresp.status = MK_STATUS(SCOPE_HOST, ERR_COMM);
				goto send;
			}

			peer_addr.sin_addr = *((struct in_addr*)h->h_addr);
		}
	
		peer_addr.sin_family = AF_INET;
		peer_addr.sin_port = htons(creq.port ? creq.port : DEFAULT_PORT);
		memset(peer_addr.sin_zero, 0, sizeof(peer_addr.sin_zero));

		fd_in = socket(AF_INET, SOCK_STREAM, 0);
		if (!fd_in) {
			output(LOG_ERR, "socket failed. %s", strerror(errno));
			cresp.status = MK_STATUS(SCOPE_HOST, ERR_COMM);
			goto send;
		}

		rc = connect(fd_in, (struct sockaddr*)&peer_addr,
			sizeof(struct sockaddr));
		if (rc == -1) {
			output(LOG_ERR, "connect failed. %s", strerror(errno));
			cresp.status = MK_STATUS(SCOPE_HOST, ERR_COMM);
			goto send;
		}

		/* send request */
		len_sent = 0;
		len_tosend = len;
		while (len_tosend > len_sent) {
			len = len_tosend - len_sent;
			len = send(fd_in, &buf[len_sent], len, 0);
			if (len < 0) {
				output(LOG_ERR, "send failed/connection closed by peer");
				cresp.status = MK_STATUS(SCOPE_HOST, ERR_COMM);
				goto send;
			}
			len_sent += len;
		}

		memset(&smsg, 0, sizeof(smsg));
		
		/* receive response - we can expect at least 14 bytes to receive */
		len = recv(fd_in, buf, 14, 0);
		if (len <= 0) {
			output(LOG_ERR, "recv failed/connection closed by peer");
			cresp.status = MK_STATUS(SCOPE_HOST, ERR_COMM);
			goto send;
		}

		len_received = len;
		len_toreceive = get_der_seq_size(buf);
		assert(len_toreceive <= sizeof(buf));
		if (len_toreceive > sizeof(buf)) {
			output(LOG_ERR, "packet sent by peer is too big");
			cresp.status = MK_STATUS(SCOPE_PEER, ERR_MALFORMED);
			goto send;
		}

		/* get the rest */
		while (len_toreceive > len_received) {
			len = len_toreceive - len_received;
			len = recv(fd_in, &buf[len_received], len, 0);
			if (len < 0) {
				output(LOG_ERR, "recv failed/connection closed by peer");
				cresp.status = MK_STATUS(SCOPE_HOST, ERR_COMM);
				goto send;
			}
			len_received += len;
		}

		close(fd_in);
		fd_in = 0;

		/* decode response message */
		rc = decode_server_message(buf, len_received, &smsg);
 		if (rc) {
			cresp.status = MK_STATUS(SCOPE_HOST, rc);
			goto send;
		}

		/* sanity check */
		if (smsg.version != CURRENT_PROTOCOL_VERSION) {
			output(LOG_ERR, "unsupported protocol version %d", smsg.version);
			cresp.status = MK_STATUS(SCOPE_PEER, ERR_PROTOCOL);
			goto send;
		}

		/* verify signature if required */
		if (smsg.sigAlg_len && smsg.sig_len) {
			rc = verify_signature(pe, smsg.tbsMsg, smsg.tbsMsg_len,
				smsg.sigAlg, smsg.sigAlg_len, smsg.sig, smsg.sig_len);
			if (rc) {
				cresp.status = MK_STATUS(SCOPE_HOST, rc);
				goto send;
			}
		}
		else
		if (pe->auth != AUTH_NONE) {
			output(LOG_ERR, "response is not signed");
			cresp.status = MK_STATUS(SCOPE_PEER, ERR_SIG_VERIFY);
			goto send;
		}
		
		/* decode response */
		rc = decode_server_response(smsg.tbsMsg, smsg.tbsMsg_len, &sresp);
 		if (rc) {
			cresp.status = MK_STATUS(SCOPE_HOST, rc);
			goto send;
		}

		if (GET_ERR(sresp.status)) {
			output(LOG_ERR, "peer returned status 0x%0.2hx", sresp.status);
			cresp.status = MK_STATUS(SCOPE_PEER, GET_ERR(sresp.status));
			goto send;
		}

		/* calculate shared secret, make a requested key */
		rc = dh_get_secret(sresp.dhPublic, sresp.dhPublic_len,
			bn_private, bn_prime, &secret_key, &secret_key_len);
		if (rc) {
			output(LOG_ERR, "dh_get_secret failed");
			cresp.status = MK_STATUS(SCOPE_HOST, rc);
			goto send;
		}

		DUMP_BIN(sresp.dhPublic, sresp.dhPublic_len, "publ-r");
		DUMP_BIN(secret_key, secret_key_len, "secr-i");
		
		assert(secret_key_len >= BITS_TO_BYTES(creq.keyLen));

		/* store a key to database */
		if (creq.flags & FLAG_STORE_KEY) {
			char kval_buf[KEY_VAL_SIZE + MAX_KEY_LEN];
			PKEY_VAL pkey_val = (PKEY_VAL)kval_buf;

			pkey_val->expires = gentime_to_time_t(creq.expires);
			if (pkey_val->expires == -1) {
				output(LOG_ERR, "cannot convert time value %s", creq.expires);
				cresp.status = MK_STATUS(SCOPE_HOST, ERR_INVALID_PARAM);
				goto send;
			}
			
			pkey_val->key_len = creq.keyLen;
			memcpy(pkey_val->key, secret_key,
				BITS_TO_BYTES(pkey_val->key_len));
			
			rc = keydb_store(keyid, kval_buf, sizeof(KEY_VAL) +
				BITS_TO_BYTES(pkey_val->key_len));
			if (rc) {
				output(LOG_ERR, "keydb_store failed. %s", strerror(errno));
				cresp.status = MK_STATUS(SCOPE_HOST, ERR_INTERNAL);
				goto send;
			}

			output(LOG_INFO, "new key '%s' (%dbits) added, validity: %s",
				keyid, pkey_val->key_len, ctime(&pkey_val->expires));
		}

		cresp.keyLen = creq.keyLen;
		memcpy(cresp.key, secret_key, BITS_TO_BYTES(cresp.keyLen));
		cresp.status = STATUS_SUCCESS;
	}
	else {
		char kval_buf[KEY_VAL_SIZE + MAX_KEY_LEN];
		PKEY_VAL pkey_val = (PKEY_VAL)kval_buf;
		time_t	now;
		int		expired;

		/* goto database and look for a key. fail if it does not exist */
		if (!keydb_exists(keyid)) {
			output(LOG_ERR, "requested key does not exist: '%s'", keyid);
			cresp.status = MK_STATUS(SCOPE_HOST, ERR_KEY_NOT_EXISTS);
			goto send;
		}

		len = sizeof(kval_buf);
		rc = keydb_fetch(keyid, kval_buf, &len);
		if (rc) {
			output(LOG_ERR, "keydb_fetch failed. %s", strerror(errno));
			cresp.status = MK_STATUS(SCOPE_HOST, ERR_INTERNAL);
			goto send;
		}

		/* check validity */
		expired = time(&now) >= pkey_val->expires;
		
		if (!(creq.flags & FLAG_KEEP_KEY) || expired) {
			/* delete a key from database */
			rc = keydb_delete(keyid);
			if (rc) {
				output(LOG_ERR, "keydb_delete failed. %s", strerror(errno));
				cresp.status = MK_STATUS(SCOPE_HOST, ERR_INTERNAL);
				goto send;
			}
		}

		if (expired) {
			output(LOG_ERR, "requested key has expired: '%s'", keyid);
			cresp.status = MK_STATUS(SCOPE_HOST, ERR_KEY_EXPIRED);
			goto send;
		}
		
		cresp.keyLen = pkey_val->key_len;
		memcpy(cresp.key, pkey_val->key, BITS_TO_BYTES(cresp.keyLen));
		cresp.status = STATUS_SUCCESS;
	}

 send:;
	output(LOG_INFO, "sending back response to unix socket");

	cresp.reqType = creq.reqType;
	cresp.version = CURRENT_PROTOCOL_VERSION;
	
	/* encode response message */
	len = sizeof(buf);
	rc = encode_client_response(&cresp, buf, &len);
	if (rc) {
		cresp.status = MK_STATUS(SCOPE_HOST, rc);
		goto ret;
	}

	/* send response */
	len_sent = 0;
	len_tosend = len;
	while (len_tosend > len_sent) {
		len = len_tosend - len_sent;
		len = send(fd_un2, &buf[len_sent], len, 0);
		if (len < 0) {
			output(LOG_ERR, "send failed. %s", strerror(errno));
			break;
		}

		len_sent += len;
	}

 ret:;
	/* free resources */
	if (fd_in)
		close(fd_in);
	
	if (bn_prime)
		BN_free(bn_prime);

	if (bn_base)
		BN_free(bn_base);

	if (bn_private)
		BN_free(bn_private);

	if (public)
		free(public);

	if (secret_key)
		free(secret_key);
}

/* accept and process key exchange request */
void process_remote_request(int fd_in2, long ipaddr) 
{
	int	rc, len, len_toreceive, len_received, len_tosend, len_sent;

	SRV_REQUEST		sreq;
	SRV_RESPONSE	sresp;
	SRV_MESSAGE		smsg;
	char 			buf[1024];

	char			keyid[MAX_HOST_LEN * 2 + MAX_TAG_LEN + 10];

	BIGNUM 			*bn_base = NULL, *bn_prime = NULL, *bn_private = NULL;
	unsigned char*	public = NULL;
	int				public_len;
	unsigned char*	secret_key = NULL;
	int				secret_key_len;

	char			kval_buf[KEY_VAL_SIZE + MAX_KEY_LEN];
	PKEY_VAL		pkey_val = (PKEY_VAL)kval_buf;

	PEER_ENTRY*		pe = (PEER_ENTRY*)NULL;

	memset(&sresp, 0, sizeof(sresp));

	/* find a peer by ipaddress */
	pe = find_peer_by_ipaddr(ipaddr);

	/* receive request - we can expect at least 14 bytes to receive */
	len = recv(fd_in2, buf, 14, 0);
	if (len <= 0) {
		output(LOG_ERR, "recv failed/connection closed by peer");
		sresp.status = MK_STATUS(SCOPE_HOST, ERR_COMM);
		goto send;
	}

	len_received = len;
	len_toreceive = get_der_seq_size(buf);
	assert(len_toreceive <= sizeof(buf));
	if (len_toreceive > sizeof(buf)) {
		output(LOG_ERR, "packet sent by peer is too big");
		sresp.status = MK_STATUS(SCOPE_PEER, ERR_MALFORMED);
		goto send;
	}

	/* get the rest */
	while (len_toreceive > len_received) {
		len = len_toreceive - len_received;
		len = recv(fd_in2, &buf[len_received], len, 0);
		if (len < 0) {
			output(LOG_ERR, "recv failed/connection closed by peer");
			sresp.status = MK_STATUS(SCOPE_HOST, ERR_COMM);
			goto send;
		}
		len_received += len;
	}

	/* decode request message */
	rc = decode_server_message(buf, len_received, &smsg);
	if (rc) {
		sresp.status = MK_STATUS(SCOPE_HOST, rc);
		goto send;
	}

	/* sanity check */
	if (smsg.version != CURRENT_PROTOCOL_VERSION) {
		output(LOG_ERR, "unsupported protocol version %d", smsg.version);
		sresp.status = MK_STATUS(SCOPE_PEER, ERR_PROTOCOL);
		goto send;
	}

	/* decode request */
	rc = decode_server_request(smsg.tbsMsg, smsg.tbsMsg_len, &sreq);
	if (rc) {
		sresp.status = MK_STATUS(SCOPE_HOST, rc);
		goto send;
	}

	if (!sreq.keyLen || sreq.keyLen > MAX_KEY_LEN) {
		output(LOG_ERR, "invalid size of requested key: %d", sreq.keyLen);
		sresp.status = MK_STATUS(SCOPE_PEER, ERR_INVALID_PARAM);
		goto send;
	}

	/* locate and check the peer */
	if (strlen(sreq.host))
		pe = find_peer(sreq.host);

	if (!pe) {
		output(LOG_ERR, "peer '%s' is not available", sreq.host);
		sresp.status = MK_STATUS(SCOPE_HOST, ERR_NOT_AVAILABLE);
		goto send;
	}
	else
	if (!pe->allow) {
		output(LOG_ERR, "access denied for peer '%s'", sreq.host);
		sresp.status = MK_STATUS(SCOPE_HOST, ERR_ACCESS_DENIED);
		goto send;
	}

	/* verify signature if required */
	if (smsg.sigAlg_len && smsg.sig_len) {
		rc = verify_signature(pe, smsg.tbsMsg, smsg.tbsMsg_len,
			smsg.sigAlg, smsg.sigAlg_len, smsg.sig, smsg.sig_len);
		if (rc) {
			sresp.status = MK_STATUS(SCOPE_HOST, rc);
			goto send;
		}
	}
	else
	if (pe->auth != AUTH_NONE) {
		output(LOG_ERR, "request is not signed");
		sresp.status = MK_STATUS(SCOPE_PEER, ERR_SIG_VERIFY);
		goto send;
	}

	/* make keyid */
	sprintf(keyid, "%s@%s", sreq.tag, sreq.host);
	
	/* check if requested key does not exist */
	if (keydb_exists(keyid)) {
		time_t	now;

		len = sizeof(kval_buf);
		rc = keydb_fetch(keyid, kval_buf, &len);
		if (rc) {
			output(LOG_ERR, "keydb_fetch failed. %s", strerror(errno));
			sresp.status = MK_STATUS(SCOPE_HOST, ERR_INTERNAL);
			goto send;
		}

		/* check validity */
		if (time(&now) >= pkey_val->expires) {
			/* delete expired key from database */
			rc = keydb_delete(keyid);
			if (rc) {
				output(LOG_ERR, "keydb_delete failed. %s", strerror(errno));
				sresp.status = MK_STATUS(SCOPE_HOST, ERR_INTERNAL);
				goto send;
			}
		}
		else {
			output(LOG_ERR, "requested key already exist: '%s'", keyid);
			sresp.status = MK_STATUS(SCOPE_HOST, ERR_KEY_EXISTS);
			goto send;
		}
	}
	
	/* generate secret, calculate public value */
	rc = dh_init_group_params(sreq.dhGroup, &bn_prime, &bn_base);
	if (rc) {
		output(LOG_ERR, "dh_init_group_params failed");
		sresp.status = MK_STATUS(SCOPE_HOST, rc);
		goto send;
	}
	DUMP_BN(bn_prime, "prime ");
	DUMP_BN(bn_base, "base  ");
		
	rc = dh_gen_private_public(sreq.dhGroup, bn_prime, bn_base,
		&bn_private, &public, &public_len);
	if (rc) {
		output(LOG_ERR, "dh_gen_private_public failed");
		sresp.status = MK_STATUS(SCOPE_HOST, rc);
		goto send;
	}
	DUMP_BN(bn_private, "priv-r");
	DUMP_BIN(public, public_len, "publ-r");

	/* calculate shared secret, make a requested key */
	rc = dh_get_secret(sreq.dhPublic, sreq.dhPublic_len, bn_private,
		bn_prime, &secret_key, &secret_key_len);
	if (rc) {
		output(LOG_ERR, "dh_get_secret failed");
		sresp.status = MK_STATUS(SCOPE_HOST, rc);
		goto send;
	}
	DUMP_BIN(sreq.dhPublic, sreq.dhPublic_len, "publ-i");
	DUMP_BIN(secret_key, secret_key_len, "secr-r");
	
	assert(secret_key_len >= BITS_TO_BYTES(pkey_val->key_len));

	/* store a key into database */
	pkey_val->expires = gentime_to_time_t(sreq.expires);
	if (pkey_val->expires == -1) {
		output(LOG_ERR, "cannot convert time value %s", sreq.expires);
		sresp.status = MK_STATUS(SCOPE_HOST, ERR_INVALID_PARAM);
		goto send;
	}
	pkey_val->key_len = sreq.keyLen;
	memcpy(pkey_val->key, secret_key, BITS_TO_BYTES(pkey_val->key_len));
			
	rc = keydb_store(keyid, kval_buf, sizeof(KEY_VAL) +
		BITS_TO_BYTES(pkey_val->key_len));
	if (rc) {
		output(LOG_ERR, "keydb_store failed. %s", strerror(errno));
		sresp.status = MK_STATUS(SCOPE_HOST, ERR_INTERNAL);
		goto send;
	}

	output(LOG_INFO, "new key '%s' (%dbits) added, validity: %s",
		keyid, pkey_val->key_len, ctime(&pkey_val->expires));
	
	/* get public value and send it back */
	sresp.dhPublic_len = public_len;
	memcpy(sresp.dhPublic, public, public_len);

 send:;	
	output(LOG_INFO, "sending back response to inet socket");

	memset(&smsg, 0, sizeof(smsg));
	
	/* fill-in response */
	sresp.cookie = generate_unique_cookie();

	smsg.tbsMsg_len = sizeof(smsg.tbsMsg);
	rc = encode_server_response(&sresp, smsg.tbsMsg, &smsg.tbsMsg_len);
	if (rc) 
		goto ret;
		
	/* fill-in response message */
	smsg.version = CURRENT_PROTOCOL_VERSION;

	/* sign response if required */
	if (pe && pe->auth != AUTH_NONE) {
		rc = sign_message(pe, smsg.tbsMsg, smsg.tbsMsg_len,
			smsg.sigAlg, &smsg.sigAlg_len, smsg.sig, &smsg.sig_len);
		if (rc) 
			goto ret;
	}

	/* encode message */	
	len = sizeof(buf);
	rc = encode_server_message(&smsg, buf, &len);
	if (rc) 
		goto ret;
	
	/* send response */
	len_sent = 0;
	len_tosend = len;
	while (len_tosend > len_sent) {
		len = len_tosend - len_sent;
		len = send(fd_in2, &buf[len_sent], len, 0);
		if (len < 0) {
			output(LOG_ERR, "send failed/connection closed by peer");
			break;
		}
		len_sent += len;
	}

 ret:;
	/* free resources */
	if (bn_prime)
		BN_free(bn_prime);

	if (bn_base)
		BN_free(bn_base);

	if (bn_private)
		BN_free(bn_private);

	if (public)
		free(public);

	if (secret_key)
		free(secret_key);
}


/*****************************************************************************/
/* main program                                                              */
/*****************************************************************************/

/* fork and exit */
void start_daemon() 
{
	int i;

	i = fork();
	if (i < 0)
		exit(1);	/* cannot fork */
	else if (i > 0)
		exit(0);	/* parent exits */

	/* close descriptors */
	i = open("/dev/null", O_RDWR);
	close(0); close(1); close(2);
	dup(i); dup(i);

	setsid();		/* new process group */ 
	umask(0117);		/* mode 640 for socket */
	if (getuid() == 0)
		setegid(conf_egid);	/* goup shsec */
}

/* fork and continue */
void start_keydb_cleaner() 
{
	int i;

	keydb_cleaner = fork();
	if (keydb_cleaner < 0) {
		output(LOG_ERR, "cannot fork. %s", strerror(errno));
		exit(1);	
	}
	else
	if (keydb_cleaner > 0) {
		output(LOG_INFO, "keydb cleaner has started. pid=%d", keydb_cleaner);			
		return;		/* parent continues */
	}

 start:	
	while (1) {
		char keyid[MAX_TAG_LEN + MAX_HOST_LEN + 1], opaque[16];
		char kval_buf[KEY_VAL_SIZE + MAX_KEY_LEN];
		PKEY_VAL pkey_val = (PKEY_VAL)kval_buf;
		int keyid_len, rc, len;
		time_t now;

		output(LOG_ERR, "keydb cleaner is running..");

		memset(opaque, 0, sizeof(opaque));
		keyid_len = sizeof(keyid);
		while (keydb_enum_keys(keyid, &keyid_len, opaque) > 0) {
			len = sizeof(kval_buf);
			rc = keydb_fetch(keyid, kval_buf, &len);
			if (rc)
				continue;

			output(LOG_INFO, "%s %d %d", keyid, pkey_val->expires, time(&now));
			
			if (pkey_val->expires >= time(&now)) {
				rc = keydb_delete(keyid);
				if (rc) 
					output(LOG_ERR, "keydb_delete failed. %s",
						strerror(errno));
				else
					output(LOG_INFO, "key '%s' has expired and deleted.",
						keyid);
				goto start;
			}
		}
	
		sleep(60);
	}
}

/* signal handling */
void signal_handler(int sig) 
{
	int status;
	
	switch (sig) {
	case SIGCHLD:
		wait(&status);
		break;

	case SIGTERM:
		output(LOG_INFO, "TERM signal catched");

		/* kill a child */
		kill(keydb_cleaner, SIGTERM);
		
		/* deallocate resources */
		keydb_close();
		free_peer_list();
		asn1_free();
		exit(0);
	}
}

/* start program */
int main(int argc, char* argv[]) 
{
	int		fd, fd_un, fd_un2, fd_in, fd_in2, len, rc;
	fd_set	readers, readers_tmp;
	char	buf[10];
	struct sigaction	sigchld_action, sigterm_action;
	struct sockaddr_un	local_un, remote_un;
	struct sockaddr_in	local_in, remote_in;
	time_t				now;

	/* seed random number generator */
	srandom(time(&now));

	/* setup options/configuration */
	set_conf_defaults();
	get_options(argc, argv);
	rc = conf_init(conf_file);
	if (rc) {
		output(LOG_ERR, "reading configuration from '%s' failed. %s", 
			conf_file, strerror(errno));
		exit(1);
	}
	build_peer_list();
	conf_free();

	if (parm_verbose)	/* commad-line argument was set? */
		conf_verbose = parm_verbose;

#ifdef DEBUG
	output(LOG_DEBUG,
		"daemon: %d, child: %d, conf_file: '%s', pid_file: '%s', "
		"keydb_file: '%s', sock_file: '%s', flush_db: %d, dh_group: %d, "
		"listen: '%s', port: %d, search_order: %d, host: '%s'",
		conf_daemon, conf_child, conf_file, conf_pid_file,
		conf_keydb_file, conf_sock_file, conf_flush_db, conf_dh_group,
		conf_listen, conf_port,	conf_search_order, conf_host);
#endif

	/* daemonize */
	if (conf_daemon)
		start_daemon();
	else {
		umask(0117);			/* mode 640 for socket */
		if (getuid() == 0)
			setegid(conf_egid);	/* goup shsec */
	}
	
	/* try to obtain lock or exit */
	fd = open(conf_pid_file, O_RDWR | O_CREAT, 0640);
	if (fd < 0) {
		output(LOG_ERR, "error: cannot create file '%s'", conf_pid_file);
		exit(1);
	}
	
	if (lockf(fd, F_TLOCK, 0) < 0) {
		output(LOG_ERR, "error: cannot obtain file lock. %s", strerror(errno));
		exit(1);
	}

	/* 1st instance continues */
	sprintf(buf, "%d\n", getpid());
	write(fd, buf, strlen(buf));

	/* open/create key database */
	keydb_open(conf_flush_db);

	/* setup signal handler */
	memset(&sigchld_action, 0, sizeof(sigchld_action));
	sigchld_action.sa_handler = &signal_handler;
	sigaction(SIGCHLD, &sigchld_action, NULL);		/* wait for child */
	
	memset(&sigterm_action, 0, sizeof(sigterm_action));
	sigterm_action.sa_handler = &signal_handler;
	sigaction(SIGTERM, &sigterm_action, NULL);		/* catch kill */

	/* start a child */
	/*start_keydb_cleaner();*/
	
	/* initialize asn definitions */
	asn1_init();

	/* prepare for select */
	FD_ZERO(&readers);

	/* setup unix socket */
	fd_un = socket(AF_UNIX, SOCK_STREAM, 0);
	check_rc(fd_un, "socket");
	
	local_un.sun_family = AF_UNIX;
	strncpy(local_un.sun_path, conf_sock_file, sizeof(local_un.sun_path) - 1);
	unlink(conf_sock_file);
	len = (local_un.sun_path - (char*)&local_un) + strlen(local_un.sun_path);
	rc = bind(fd_un, (struct sockaddr*)&local_un, len);
	check_rc(rc, "bind");

	rc = listen(fd_un, 5);
	check_rc(rc, "listen");

	output(LOG_INFO, "start listen on %s", conf_sock_file);
	
	FD_SET(fd_un, &readers);

	/* setup inet socket */
	fd_in = socket(AF_INET, SOCK_STREAM, 0);
	check_rc(fd_in, "socket");
	
	memset(&local_in, 0, sizeof(local_in));
	local_in.sin_family = AF_INET;
	local_in.sin_port = htons(conf_port);
	if (!inet_aton(conf_listen, &(local_in.sin_addr))) {
		output(LOG_ERR, "inet_aton failed. cannot convert from '%s'",
			conf_listen);
		exit(1);
	}
	rc = bind(fd_in, (struct sockaddr*)&local_in, sizeof(local_in));
	check_rc(rc, "bind");

	rc = listen(fd_in, 5);
	check_rc(rc, "listen");

	output(LOG_INFO, "start listen on %s:%d", conf_listen, conf_port);
	
	FD_SET(fd_in, &readers);

	while (1) {
		output(LOG_INFO, "waiting for connection");

		readers_tmp = readers;	/* copy readers */
		
		/* we listen on 2 fds, fd_in is the last allocated descriptor */
		rc = select(fd_in + 1, &readers_tmp, NULL, NULL, NULL);
		if (rc == -1 && errno == EINTR)	/* syscall was interrupted */
			continue;
		check_rc(rc, "select");
		
		if (FD_ISSET(fd_un, &readers_tmp)) {
			len = sizeof(struct sockaddr_un);
			fd_un2 = accept(fd_un, (struct sockaddr*)&remote_un, &len);
			if (fd_un2 == -1 && errno == EINTR)	/* syscall was interrupted */
				continue;
			check_rc(fd_un2, "accept");
			
			output(LOG_INFO, "unix socket has connected");
			
			/* child process connection, parent keeps listening */
			rc = fork();
			if (rc > 0) {
				close(fd_un2);
			}
			else if (rc < 0) {
				close(fd_un2);
				output(LOG_ERR, "cannot fork");
			}
			else {
				if (conf_child) {		/* for child debugging */
					char buf[100];
					sprintf(buf, "fork()'ed to %d", getpid());
					output(LOG_ERR, buf);
					while (conf_child) sleep(1);
				}

				close(fd_un);
				close(fd_in);
				process_client_request(fd_un2);
				close(fd_un2);
				output(LOG_INFO, "done. closing unix socket");
				exit(0);
			}
		}
		else if (FD_ISSET(fd_in, &readers_tmp)) {
			len = sizeof(struct sockaddr_in);
			fd_in2 = accept(fd_in, (struct sockaddr*)&remote_in, &len);
			if (fd_in2 == -1 && errno == EINTR)	/* syscall was interrupted */
				continue;
			check_rc(fd_in2, "accept");
			
			output(LOG_INFO, "inet socket has connected");
			
			/* child process connection, parent keeps listening */
			rc = fork();
			if (rc > 0) {
				close(fd_in2);
			}
			else if (rc < 0) {
				close(fd_in2);
				output(LOG_ERR, "cannot fork");
			}
			else {
				if (conf_child) {		/* for child debugging */
					char buf[100];
					sprintf(buf, "fork()'ed to %d", getpid());
					output(LOG_ERR, buf);
					while (conf_child) sleep(1);
				}

				close(fd_in);
				close(fd_un);
				process_remote_request(fd_in2, remote_in.sin_addr.s_addr);
				close(fd_in2);
				output(LOG_INFO, "done. closing inet socket");
				exit(0);
			}
		}
	}

	return 0;
}
