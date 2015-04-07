/* shsec.h - SharedSecret project.

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


#ifndef _SHSEC_H
#define _SHSEC_H


/* client constants */
#define	PROGRAM_NAME	"shsec"

#define	MAX_FILE_LEN	256


/* output format */
#define OUTFORM_RAW		1
#define OUTFORM_HEX		2
#define OUTFORM_BASE64	3
#define OUTFORM_DER		4
#define OUTFORM_PEM		5


/* function prototypes from utils.c */
void print(int prlevel, const char* fmt, ...);
void check_rc(int rc, const char* fn);
void check_socket(int rc, const char* fn);
const char* error_message(char status);
unsigned int get_der_seq_size(unsigned char* buf);
int time_t_to_gentime(time_t time, char* gentime);
time_t gentime_to_time_t(const char* gentime);


/* function prototypes from base64.c */
extern void to64frombits(unsigned char *out, const unsigned char *in, int len);


/* for internal usage */
struct str_num {
	char*	str;
	int		num;
};


#endif /* _SHSEC_H */
