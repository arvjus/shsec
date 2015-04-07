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
#include <sys/types.h>
#include <netinet/in.h>
#include "shsec_asn1.h"
#include "defs.h"
#include "conf_defs.h"
#include "shsecd.h"


static ASN1_TYPE asn1_definitions = ASN1_TYPE_EMPTY;
extern int conf_daemon;

#define CHECK_RES	{ if (res != ASN1_SUCCESS) { goto done; } }

/* init, free asn1 resources */
void asn1_init()
{
	asn1_retCode	res;

	res = asn1_array2tree(shsec_asn1_tab, &asn1_definitions, NULL);
	if (res != ASN1_SUCCESS) {
		output(LOG_ERR, "error: asn1_array2tree failed: %s\n",
			libtasn1_strerror(res));
		exit(1);
	}
}

void asn1_free()
{
	asn1_delete_structure(&asn1_definitions);
}

/* decode asn1 client request */
int decode_client_request(unsigned char* buf, int buf_len, PCLI_REQUEST preq)
{
	ASN1_TYPE		req = ASN1_TYPE_EMPTY;
	asn1_retCode	res;
	unsigned char	tmp[2];
	int				len;

	memset(preq, 0, sizeof(CLI_REQUEST));
	
	/* create CliReq */
	res = asn1_create_element(asn1_definitions, "SHSEC.CliReq", &req);
	CHECK_RES;

	/* decode whole structure */
	res = asn1_der_decoding(&req, buf, buf_len, NULL);
	CHECK_RES;

#ifdef DEBUG
	if (!conf_daemon && conf_verbose > 1) {
		fprintf(stderr, "CliReq:\n");
		asn1_print_structure(stdout, req, "", ASN1_PRINT_ALL);
		fprintf(stderr, "\n");
	}
#endif

	/* check version */
	len = sizeof(preq->version);
	res = asn1_read_value(req, "version", &preq->version, &len);
	CHECK_RES;
	if (preq->version != CURRENT_PROTOCOL_VERSION) {
		output(LOG_ERR, "unsuported version %d\n", preq->version);
		goto done;
	}

	/* get request type */
	len = sizeof(preq->reqType);
	res = asn1_read_value(req, "reqType", &preq->reqType, &len);
	CHECK_RES;

	/* read values */
	switch (preq->reqType) {
	case CRT_REQUEST_KEY:	/* requestKey */
		len = sizeof(preq->tag);
		res = asn1_read_value(req, "options.tag", preq->tag, &len);
		CHECK_RES;
		preq->tag[len] = '\0';

		len = sizeof(preq->peer);
		res = asn1_read_value(req, "options.peer", preq->peer, &len);
		CHECK_RES;
		preq->peer[len] = '\0';

		len = sizeof(tmp);
		res = asn1_read_value(req, "options.port", tmp, &len);
		CHECK_RES;
		preq->port = ASN1_NTOHS(tmp, len);

		len = sizeof(tmp);
		res = asn1_read_value(req, "options.keyLen", tmp, &len);
		CHECK_RES;
		preq->keyLen = ASN1_NTOHS(tmp, len);

		len = sizeof(preq->flags);
		res = asn1_read_value(req, "options.flags", &preq->flags, &len);
		CHECK_RES;

		len = sizeof(preq->expires);
		res = asn1_read_value(req, "options.expires", preq->expires, &len);
		CHECK_RES;
		break;
		preq->expires[len] = '\0';

	case CRT_DELETE_KEY:	/* deleteKey */
		len = sizeof(preq->tag);
		res = asn1_read_value(req, "options.tag", preq->tag, &len);
		CHECK_RES;
		preq->tag[len] = '\0';

		len = sizeof(preq->peer);
		res = asn1_read_value(req, "options.peer", preq->peer, &len);
		CHECK_RES;
		break;
		preq->peer[len] = '\0';

	case CRT_ENUM_KEYS:	/* enumKeys */
		break;

	default:
		assert(0);
	}

 done:;
	if (req != ASN1_TYPE_EMPTY)
		asn1_delete_structure(&req);

	if (res != ASN1_SUCCESS) 
		output(LOG_ERR, "decode_client_request failed. %s",
			libtasn1_strerror(res));

	return (res ? ERR_DECODING : ERR_SUCCESS);
}

/* encode asn1 client response */
int encode_client_response(PCLI_RESPONSE presp, unsigned char* buf, int* plen) 
{
	ASN1_TYPE		resp = ASN1_TYPE_EMPTY;
	asn1_retCode	res;
	unsigned char	tmp[2];
	int				len;

	/* create CliResp */
	res = asn1_create_element(asn1_definitions, "SHSEC.CliResp", &resp);
	CHECK_RES;

	res = asn1_write_value(resp, "version", &presp->version,
		sizeof(presp->version));
	CHECK_RES;

	res = asn1_write_value(resp, "status", &presp->status,
		sizeof(presp->status));
	CHECK_RES;

	/* set values */
	switch (presp->reqType) {
	case CRT_REQUEST_KEY:
		res = asn1_write_value(resp, "respData", "key", 0);
		CHECK_RES;

		res = asn1_write_value(resp, "respData.key", presp->key,
			presp->keyLen);
		CHECK_RES;
		break;

	case CRT_DELETE_KEY:
		res = asn1_write_value(resp, "respData", NULL, 0);
		CHECK_RES;
		break;

	case CRT_ENUM_KEYS: {
		char keyid[MAX_TAG_LEN + MAX_HOST_LEN + 1], opaque[16];
		char expires[MAX_GENTIME_LEN];
		char kval_buf[KEY_VAL_SIZE + MAX_KEY_LEN];
		PKEY_VAL pkey_val = (PKEY_VAL)kval_buf;
		int keyid_len, rc;

		res = asn1_write_value(resp, "respData", "keyInfo", 0);
		CHECK_RES;

		memset(opaque, 0, sizeof(opaque));
		keyid_len = sizeof(keyid);
		while (keydb_enum_keys(keyid, &keyid_len, opaque) > 0) {
			len = sizeof(kval_buf);
			rc = keydb_fetch(keyid, kval_buf, &len);
			if (rc)
				continue;

			rc = time_t_to_gentime(pkey_val->expires, expires);
			if (rc == -1)
				continue;
			
			res = asn1_write_value(resp, "respData.keyInfo", "NEW", 0);
			CHECK_RES;

			res = asn1_write_value(resp, "respData.keyInfo.?LAST.keyid",
				keyid, 0);
			CHECK_RES;

			*((unsigned short*)tmp) = htons(pkey_val->key_len);
			res = asn1_write_value(resp, "respData.keyInfo.?LAST.keyLen",
				tmp, sizeof(tmp));
			CHECK_RES;

			res = asn1_write_value(resp, "respData.keyInfo.?LAST.expires",
				expires, 0);
			CHECK_RES;
		}
		break;
	}
	default:
		assert(0);
	}
	
	res = asn1_der_coding(resp, "", buf, plen, NULL);
	CHECK_RES;

 done:;
	if (resp != ASN1_TYPE_EMPTY)
		asn1_delete_structure(&resp);

	if (res != ASN1_SUCCESS) 
		output(LOG_ERR, "encode_client_response failed. %s",
			libtasn1_strerror(res));

	return (res ? ERR_ENCODING : ERR_SUCCESS);
}

/* encode asn1 server message */
int encode_server_message(PSRV_MESSAGE pmsg, unsigned char* buf, int* plen) 
{
	ASN1_TYPE		msg = ASN1_TYPE_EMPTY;
	asn1_retCode	res;

	/* create SrvMsg */
	res = asn1_create_element(asn1_definitions, "SHSEC.SrvMsg", &msg);
	CHECK_RES;

	res = asn1_write_value(msg, "version", &pmsg->version,
		sizeof(pmsg->version));
	CHECK_RES;

	res = asn1_write_value(msg, "tbsMsg", pmsg->tbsMsg, pmsg->tbsMsg_len);
	CHECK_RES;

	if (pmsg->sigAlg_len && pmsg->sig_len) {
		res = asn1_write_value(msg, "signature.sigAlg", pmsg->sigAlg, 0);
		CHECK_RES;

		res = asn1_write_value(msg, "signature.sig", pmsg->sig, pmsg->sig_len);
		CHECK_RES;
	} else {
		res = asn1_write_value(msg, "signature", NULL, 0);
		CHECK_RES;
	}

	res = asn1_der_coding(msg, "", buf, plen, NULL);
	CHECK_RES;

 done:;
	if (msg != ASN1_TYPE_EMPTY)
		asn1_delete_structure(&msg);

	if (res != ASN1_SUCCESS) 
		output(LOG_ERR, "encode_server_message failed. %s",
			libtasn1_strerror(res));

	return (res ? ERR_ENCODING : ERR_SUCCESS);
}

/* decode asn1 server message */
int decode_server_message(unsigned char* buf, int buf_len, PSRV_MESSAGE pmsg)
{
	ASN1_TYPE		msg = ASN1_TYPE_EMPTY;
	asn1_retCode	res;
	int				len;

	memset(pmsg, 0, sizeof(SRV_MESSAGE));
	
	/* create SrvMsg */
	res = asn1_create_element(asn1_definitions, "SHSEC.SrvMsg", &msg);
	CHECK_RES;

	/* decode whole structure */
	res = asn1_der_decoding(&msg, buf, buf_len, NULL);
	CHECK_RES;

#ifdef DEBUG
	if (!conf_daemon && conf_verbose > 1) {
		fprintf(stderr, "SrvMsg:\n");
		asn1_print_structure(stdout, msg, "", ASN1_PRINT_ALL);
		fprintf(stderr, "\n");
	}
#endif

	/* check version */
	len = sizeof(pmsg->version);
	res = asn1_read_value(msg, "version", &pmsg->version, &len);
	CHECK_RES;
	if (pmsg->version != CURRENT_PROTOCOL_VERSION) {
		output(LOG_ERR, "unsuported version %d\n", pmsg->version);
		goto done;
	}

	/* get tbs blob */
	pmsg->tbsMsg_len = sizeof(pmsg->tbsMsg);
	res = asn1_read_value(msg, "tbsMsg", pmsg->tbsMsg, &pmsg->tbsMsg_len);
	CHECK_RES;

	/* get optional signature */
	len = sizeof(pmsg->sigAlg);
	res = asn1_read_value(msg, "signature.sigAlg", pmsg->sigAlg, &len);
	if (res != ASN1_ELEMENT_NOT_FOUND) {
		CHECK_RES;
		pmsg->sigAlg_len = len;
		pmsg->sig_len = sizeof(pmsg->sig);
		res = asn1_read_value(msg, "signature.sig", pmsg->sig, &pmsg->sig_len);
		CHECK_RES;
	}
	else
		res = ASN1_SUCCESS;

 done:;
	if (msg != ASN1_TYPE_EMPTY)
		asn1_delete_structure(&msg);

	if (res != ASN1_SUCCESS) 
		output(LOG_ERR, "decode_server_message failed. %s",
			libtasn1_strerror(res));

	return (res ? ERR_ENCODING : ERR_SUCCESS);
}

/* encode asn1 server request */
int encode_server_request(PSRV_REQUEST preq, unsigned char* buf, int* plen) 
{
	ASN1_TYPE		req = ASN1_TYPE_EMPTY;
	asn1_retCode	res;
	unsigned char	tmp[2];

	/* create TBSSrvReq */
	res = asn1_create_element(asn1_definitions, "SHSEC.TBSSrvReq", &req);
	CHECK_RES;

	*((unsigned short*)tmp) = ntohs(preq->cookie);
	res = asn1_write_value(req, "cookie", tmp, sizeof(tmp));
	CHECK_RES;

	res = asn1_write_value(req, "tag", preq->tag, 0);
	CHECK_RES;

	res = asn1_write_value(req, "host", preq->host, 0);
	CHECK_RES;

	*((unsigned short*)tmp) = ntohs(preq->keyLen);
	res = asn1_write_value(req, "keyLen", tmp, sizeof(tmp));
	CHECK_RES;

	res = asn1_write_value(req, "expires", preq->expires, 0);
	CHECK_RES;

	*((unsigned short*)tmp) = ntohs(preq->dhGroup);
	res = asn1_write_value(req, "dhGroup", tmp, sizeof(tmp));
	CHECK_RES;

	res = asn1_write_value(req, "dhPublic", preq->dhPublic,
		preq->dhPublic_len);
	CHECK_RES;
	
	/* encode whole structure */
	res = asn1_der_coding(req, "", buf, plen, NULL);
	CHECK_RES;

#ifdef DEBUG
	if (!conf_daemon && conf_verbose > 1) {
		fprintf(stderr, "TBSSrvReq:\n");
		asn1_print_structure(stdout, req, "", ASN1_PRINT_ALL);
		fprintf(stderr, "\n");
	}
#endif
	
 done:;
	if (req != ASN1_TYPE_EMPTY)
		asn1_delete_structure(&req);

	if (res != ASN1_SUCCESS) 
		output(LOG_ERR, "encode_server_request failed. %s",
			libtasn1_strerror(res));

	return (res ? ERR_ENCODING : ERR_SUCCESS);
}

/* decode asn1 server request */
int decode_server_request(unsigned char* buf, int buf_len, PSRV_REQUEST preq)
{
	ASN1_TYPE		req = ASN1_TYPE_EMPTY;
	asn1_retCode	res;
	unsigned char	tmp[2];
	int				len;

	memset(preq, 0, sizeof(SRV_REQUEST));
	
	/* create TBSSrvReq */
	res = asn1_create_element(asn1_definitions, "SHSEC.TBSSrvReq", &req);
	CHECK_RES;

	/* decode whole structure */
	res = asn1_der_decoding(&req, buf, buf_len, NULL);
	CHECK_RES;

	/* get values */
	len = sizeof(tmp);
	res = asn1_read_value(req, "cookie", tmp, &len);
	CHECK_RES;
	preq->cookie = ASN1_NTOHS(tmp, len);

	len = sizeof(preq->tag);
	res = asn1_read_value(req, "tag", preq->tag, &len);
	CHECK_RES;
	preq->tag[len] = '\0';

	len = sizeof(preq->host);
	res = asn1_read_value(req, "host", preq->host, &len);
	CHECK_RES;
	preq->host[len] = '\0';

	len = sizeof(tmp);
	res = asn1_read_value(req, "keyLen", tmp, &len);
	CHECK_RES;
	preq->keyLen = ASN1_NTOHS(tmp, len);

	len = sizeof(preq->expires);
	res = asn1_read_value(req, "expires", preq->expires, &len);
	CHECK_RES;
	preq->expires[len] = '\0';

	len = sizeof(tmp);
	res = asn1_read_value(req, "dhGroup", tmp, &len);
	CHECK_RES;
	preq->dhGroup = ASN1_NTOHS(tmp, len);
	
	preq->dhPublic_len = sizeof(preq->dhPublic);
	res = asn1_read_value(req, "dhPublic", preq->dhPublic,
		&preq->dhPublic_len);
	CHECK_RES;

 done:;
	if (req != ASN1_TYPE_EMPTY)
		asn1_delete_structure(&req);

	if (res != ASN1_SUCCESS) 
		output(LOG_ERR, "decode_server_request failed. %s",
			libtasn1_strerror(res));

	return (res ? ERR_DECODING : ERR_SUCCESS);
}

/* encode asn1 server response */
int encode_server_response(PSRV_RESPONSE presp, unsigned char* buf, int* plen)
{
	ASN1_TYPE		resp = ASN1_TYPE_EMPTY;
	asn1_retCode	res;
	unsigned char	tmp[2];

	/* create TBSSrvResp */
	res = asn1_create_element(asn1_definitions, "SHSEC.TBSSrvResp", &resp);
	CHECK_RES;

	*((unsigned short*)tmp) = ntohs(presp->cookie);
	res = asn1_write_value(resp, "cookie", tmp, sizeof(tmp));
	CHECK_RES;

	res = asn1_write_value(resp, "status", &presp->status,
		sizeof(presp->status));
	CHECK_RES;

	if (presp->status == STATUS_SUCCESS) {
		res = asn1_write_value(resp, "dhPublic", presp->dhPublic,
			presp->dhPublic_len);
		CHECK_RES;
	} else {
		res = asn1_write_value(resp, "dhPublic", NULL, 0);
		CHECK_RES;
	}

	/* encode whole structure */
	res = asn1_der_coding(resp, "", buf, plen, NULL);
	CHECK_RES;

#ifdef DEBUG
	if (!conf_daemon && conf_verbose > 1) {
		fprintf(stderr, "TBSSrvResp:\n");
		asn1_print_structure(stdout, resp, "", ASN1_PRINT_ALL);
		fprintf(stderr, "\n");
	}
#endif
	
 done:;
	if (resp != ASN1_TYPE_EMPTY)
		asn1_delete_structure(&resp);

	if (res != ASN1_SUCCESS) 
		output(LOG_ERR, "encode_server_response failed. %s",
			libtasn1_strerror(res));

	return (res ? ERR_ENCODING : ERR_SUCCESS);
}

/* decode asn1 server response */
int decode_server_response(unsigned char* buf, int buf_len,
	PSRV_RESPONSE presp)
{
	ASN1_TYPE		resp = ASN1_TYPE_EMPTY;
	asn1_retCode	res;
	unsigned char	tmp[2];
	int				len;

	memset(presp, 0, sizeof(SRV_REQUEST));
	
	/* create TBSSrvResp */
	res = asn1_create_element(asn1_definitions, "SHSEC.TBSSrvResp", &resp);
	CHECK_RES;

	/* decode whole structure */
	res = asn1_der_decoding(&resp, buf, buf_len, NULL);
	CHECK_RES;

	/* get values */
	len = sizeof(tmp);
	res = asn1_read_value(resp, "cookie", tmp, &len);
	CHECK_RES;
	presp->cookie = ASN1_NTOHS(tmp, len);

	len = sizeof(presp->status);
	res = asn1_read_value(resp, "status", &presp->status, &len);
	CHECK_RES;

	if (presp->status == STATUS_SUCCESS) {
		presp->dhPublic_len = sizeof(presp->dhPublic);
		res = asn1_read_value(resp, "dhPublic", presp->dhPublic,
			&presp->dhPublic_len);
		CHECK_RES;
	}

 done:;
	if (resp != ASN1_TYPE_EMPTY)
		asn1_delete_structure(&resp);

	if (res != ASN1_SUCCESS) 
		output(LOG_ERR, "decode_server_response failed. %s",
			libtasn1_strerror(res));

	return (res ? ERR_DECODING : ERR_SUCCESS);
}

