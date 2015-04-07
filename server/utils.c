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
#include <openssl/bn.h>
#include <assert.h>
#include <errno.h>
#include <syslog.h>
#include "defs.h"
#include "shsecd.h"


/* exported by conf.y, shsecd.c */
extern int conf_verbose;
extern int conf_daemon;

/* Messages with priority up to LOG_ERR are always sent to output. To output
   any message with priority higher than LOG_ERR, set verbose flag. To print
   LOG_DEBUG messages, set verbose flag twice. */
void output(int loglevel, const char* fmt, ...) 
{
	va_list	list;

	if ((loglevel >= LOG_WARNING && !conf_verbose) ||
		(loglevel >= LOG_DEBUG && conf_verbose < 2))
		return;

	va_start(list, fmt);
	if (conf_daemon) {
		openlog(PROGRAM_NAME, LOG_PID, LOG_DAEMON);
		vsyslog(loglevel, fmt, list);
		closelog();
	}
	else {
		char fmt_tmp[300];
		assert(strlen(fmt) + 1 < sizeof(fmt_tmp));
		strncpy(fmt_tmp, fmt, sizeof(fmt_tmp) - 2);
		strcat(fmt_tmp, "\n");
		vfprintf(stderr, fmt_tmp, list);
	}
	va_end(list);
}

/* check value, raise an error if -1 */
void check_rc(int rc, const char* fn) 
{
	if (rc != -1)
		return;
	
	output(LOG_ERR, "%s failed. %s", fn, strerror(errno));
	exit(1);
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

/* converts time_t into GeneralizedTime UTC form. Returns number of bytes
   written. 20 bytes for output string must be allocated at least. */
int time_t_to_gentime(time_t time, char* gentime) 
{
	struct tm* ptm;

	ptm = gmtime(&time);
	return sprintf(gentime, "%.4d%.2d%.2d%.2d%.2d%.2dZ",
		ptm->tm_year+1900, ptm->tm_mon+1, ptm->tm_mday, ptm->tm_hour,
		ptm->tm_min, ptm->tm_sec);
}

/* converts GeneralizedTime in UTC form into time_t value. Return time in
   seconds since Epoch or (time_t)-1 in case of invalid input string. */
time_t gentime_to_time_t(const char* gentime) 
{
	int len;
	struct tm tm;
	char buf[10];

	len = strlen(gentime);
	if (len < 15 || gentime[len - 1] != 'Z')
		return (time_t)-1;

	#define SET_VAL(o,l,v) \
		{ strncpy(buf, &gentime[o], l); buf[l] = '\0'; v = atoi(buf); }

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

/* this stuff for debugging only */
#ifdef DEBUG

/* dump bin buffer */
void dump_bin(unsigned char* data, int len, const char* msg) 
{
	int i;
	char buf[MAX_DH_GROUP_BYTES * 3], tmp[10];
	assert(len * 3 < sizeof(buf));

	if (conf_verbose < 2)
		return;
	
	buf[0] = '\0';
	for (i = 0; i < 16 && i < len; i++) {
		sprintf(tmp, "%0.2hx ", data[i]);
		strcat(buf, tmp);
	}

	output(LOG_DEBUG, "%s: len: %3d, data: %s%s",
		msg, len, buf, i < 16 ? "" : "..");
}

/* dump BIGNUM value */
void dump_bn(BIGNUM* bn, const char* msg) 
{
	int len;
	char buf[MAX_DH_GROUP_BYTES + 10];
	
	if (conf_verbose < 2)
		return;

	assert(BN_num_bytes(bn) <= sizeof(buf));
	len = BN_bn2bin(bn, buf);
	dump_bin(buf, len, msg);
}

#endif	/* DEBUG */ 
