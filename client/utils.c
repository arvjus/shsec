/* utils.c - SharedSecret project.

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
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <errno.h>
#include <assert.h>
#include "defs.h"
#include "shsec.h"


/* exported by shsec.c */
extern int verbose;

/* write to stderr */
void print(int prlevel, const char* fmt, ...) 
{
	va_list list;

	if ((prlevel >= LOG_WARNING && !verbose) ||
		(prlevel >= LOG_DEBUG && verbose < 2))
		return;
	
	va_start(list, fmt);
	vfprintf(stderr, fmt, list);
	va_end(list);
}

/* check value, raise error if -1 */
void check_rc(int rc, const char* fn) 
{
	if (rc != -1)
		return;
	
	print(LOG_ERR, "error: %s failed. %s\n", fn, strerror(errno));
	exit(1);
}

/* check value, raise error if -1 or 0 */
void check_socket(int rc, const char* fn) 
{
	if (rc > 0)
		return;
	else if (!rc) {
		print(LOG_ERR, "error: connection was closed by server\n");
		exit(1);
	}
	
	print(LOG_ERR, "error: %s failed. %s\n", fn, strerror(errno));
	exit(1);
}

/* decode error message */
const char* error_message(char num)
{
	static struct str_num err[] = {
		{ "unknown",					ERR_UNKNOWN			},
		{ "success",					ERR_SUCCESS			},
		{ "access denied",				ERR_ACCESS_DENIED	},
		{ "communication problem",		ERR_COMM			},
		{ "invalid parameter(s)",		ERR_INVALID_PARAM	},
		{ "internal error",				ERR_INTERNAL		},
		{ "key already exists",			ERR_KEY_EXISTS		},
		{ "key does not exist",			ERR_KEY_NOT_EXISTS	},
		{ "key has expired",			ERR_KEY_EXPIRED		},
		{ "unsupported protocol",		ERR_PROTOCOL		},
		{ "encoding error",				ERR_ENCODING		},
		{ "decoding error",				ERR_DECODING		},
		{ "malformed data",				ERR_MALFORMED		},
		{ "resource is not available",	ERR_NOT_AVAILABLE	},
		{ "option is not supported",	ERR_NOT_SUPPORTED	},
		{ "calculate signature error",	ERR_SIGNATURE		},
		{ "verify signature error",		ERR_SIG_VERIFY		},
		{ NULL,							0					}
	};
	
	int i = 0;
	for (i = 0; err[i].str; i++) 
		if (err[i].num == num) 
			break;
	
	return err[i].str;
}

/* get size of DER-encoded sequence. the size value includes
   tag and length bytes itself */
unsigned int get_der_seq_size(unsigned char* buf) 
{
	unsigned int len = 0;

	if (buf[0] == 0x30) {
		if (buf[1] & 0x80) {
			int i, num_bytes = (buf[1] & 0x7f);
			for (i = 0; i < num_bytes; i ++) {
				len *= 256; len += buf[i + 2];
			}
			len += num_bytes + 2;
		}
		else
			len = buf[1] + 2;
	};

	return len;
}

/* converts time_t into GeneralizedTime UTC form. Returns number of bytes written.
   16 bytes for output string must be allocated at least. */
int time_t_to_gentime(time_t time, char* gentime) 
{
	struct tm* ptm;

	ptm = gmtime(&time);
	return sprintf(gentime, "%.4d%.2d%.2d%.2d%.2d%.2dZ", ptm->tm_year+1900,
		ptm->tm_mon+1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
}

/* converts GeneralizedTime in UTC form into time_t value. Return time in seconds
   since Epoch or (time_t)-1 in case of invalid input string. */
time_t gentime_to_time_t(const char* gentime) 
{
	int len;
	struct tm tm;
	char buf[10];

	len = strlen(gentime);
	if (len < 15 || gentime[len - 1] != 'Z')
		return (time_t)-1;

	#define SET_VAL(o,l,v)	{ strncpy(buf, &gentime[o], l); buf[l] = '\0'; v = atoi(buf); }

	memset(&tm, 0, sizeof(struct tm));
	
	SET_VAL( 0, 4, tm.tm_year);
	SET_VAL( 4, 2, tm.tm_mon);
	SET_VAL( 6, 2, tm.tm_mday);
	SET_VAL( 8, 2, tm.tm_hour);
	SET_VAL(10, 2, tm.tm_min);
	SET_VAL(12, 2, tm.tm_sec);
	tm.tm_year -= 1900;
	tm.tm_mon --;
	tm.tm_isdst = -1;

	return timegm(&tm);
}

