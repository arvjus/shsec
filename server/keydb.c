/* keydb.c - SharedSecret project.

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
#include <gdbm.h>
#include <syslog.h>
#include <assert.h>
#include "defs.h"
#include "shsecd.h"


/* external symbols */
extern char conf_keydb_file[];

/* local variables */
static GDBM_FILE	dbf;

/* open database or flushes all keys. exits on failure */
void keydb_open(int flush_keys) 
{
	dbf = gdbm_open(conf_keydb_file, 1024,
		flush_keys ? GDBM_NEWDB : GDBM_WRCREAT,	0600, 0);
	if (!dbf) {
		output(LOG_CRIT, "error: cannot open/create '%s'", conf_keydb_file);
		exit(1);
	}
}

/* close database */
void keydb_close() 
{
	gdbm_close(dbf);
}

/* store key */
int keydb_store(const char* keyid, char* buff, int size)
{
	int		ret;
	datum	key, data;
	
	key.dptr = (char*)keyid;
	key.dsize = strlen(keyid) + 1;
	
	data.dptr = buff;
	data.dsize = size;
	
	ret = gdbm_store(dbf, key, data, GDBM_REPLACE);
	if (ret == -1) 
		output(LOG_ERR, "error: cannot store key '%s' to keydb", keyid);

	return ret;
}

/* fetch key */
int keydb_fetch(const char* keyid, char* buff, int* psize)
{
	int		ret = -1;
	datum	key, data;
	
	key.dptr = (char*)keyid;
	key.dsize = strlen(keyid) + 1;
	
	data = gdbm_fetch(dbf, key);
	if (data.dptr) {
		if (data.dsize > *psize) {
			assert("buffer too small" != 0);
			output(LOG_ERR, "error: cannot fetch data. buffer is too small");
		}
		else {
			memcpy(buff, data.dptr, data.dsize);
			*psize = data.dsize;
			ret = 0;
		}
		
		free(data.dptr);
	}

	return ret;
}

/* delete key */
int keydb_delete(const char* keyid)
{
	datum	key;
	
	key.dptr = (char*)keyid;
	key.dsize = strlen(keyid) + 1;
	
	return gdbm_delete(dbf, key);
}

/* key exists */
int keydb_exists(const char* keyid)
{
	datum	key;
	
	key.dptr = (char*)keyid;
	key.dsize = strlen(keyid) + 1;
	
	return gdbm_exists(dbf, key);
}

/* enum keys. return value: 0 if no (more) items exist, >0 in case of
   success success and <0 if error accours. for the 1st call, caller
   must allocate opaque at least sizeof(char*)+sizeof(int) and fill-in
   with zeros. */
int keydb_enum_keys(char* buff, int* psize, void* opaque)
{
	datum* pkey = (datum*)opaque;

	if (pkey->dptr) {
		char* ptr = pkey->dptr;
		*pkey = gdbm_nextkey(dbf, *pkey);
		free(ptr);
	}
	else 
		*pkey = gdbm_firstkey(dbf);

	if (pkey->dptr == NULL)
		return 0;
	else
	if (*psize < pkey->dsize) {
		free(pkey->dptr);
		return -1;
	}
	
	strncpy(buff, pkey->dptr, pkey->dsize);
	*psize = pkey->dsize;
	return 1;
}

