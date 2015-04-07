/* sig.c - SharedSecret project.

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

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include "defs.h"
#include "shsecd.h"



int sign_message(PEER_ENTRY* peer,
	const unsigned char* tbsMsg, int tbsMsg_len,
	unsigned char* sigAlg, int* psigAlg_len,
	unsigned char* sig, int* psig_len)
{
	int ret = ERR_SUCCESS;

	if (peer->auth == AUTH_PSK) {
		memcpy(sigAlg, OID_HMAC_SHA1, sizeof(OID_HMAC_SHA1));
		*psigAlg_len = sizeof(OID_HMAC_SHA1);

		if (!HMAC(EVP_sha1(), peer->cred, peer->cred_len, tbsMsg, tbsMsg_len,
			sig, psig_len) || !*psig_len) {

			output(LOG_ERR, "HMAC failed");
			ret = ERR_SIGNATURE;
			goto done;
		}
	}
	else {
		output(LOG_ERR, "non-supported authentication method");
		ret = ERR_NOT_SUPPORTED;
		goto done;
	}
	
 done:;	
	if (ret != ERR_SUCCESS) 
		output(LOG_ERR, "sign_message failed");

	return ret;
}

int verify_signature(PEER_ENTRY* peer,
	const unsigned char* tbsMsg, int tbsMsg_len,
	const unsigned char* sigAlg, int sigAlg_len,
	const unsigned char* sig, int sig_len)
{
	int ret = ERR_SUCCESS;
	unsigned char sig2[MAX_SIG_LEN];
	int	sig2_len;

	if (peer->auth == AUTH_PSK &&
		sigAlg_len == sizeof(OID_HMAC_SHA1) &&
		!memcmp(sigAlg, OID_HMAC_SHA1, sigAlg_len)) {

		if (HMAC(EVP_sha1(), peer->cred, peer->cred_len, tbsMsg, tbsMsg_len,
				sig2, &sig2_len) && sig2_len) {

			if (sig_len != sig2_len || memcmp(sig, sig2, sig2_len)) {
				output(LOG_ERR, "message digest does not match");
				ret = ERR_SIG_VERIFY;
				goto done;
			}
		}
		else {
			output(LOG_ERR, "HMAC failed");
			ret = ERR_SIGNATURE;
			goto done;
		}
	}
	else {
		output(LOG_ERR, "non-supported algorithm '%s'", sigAlg);
		ret = ERR_NOT_SUPPORTED;
		goto done;
	}

 done:;
	if (ret != ERR_SUCCESS) 
		output(LOG_ERR, "verify_signature failed");

	return ret;
}
