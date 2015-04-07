/* A Bison parser, made by GNU Bison 1.875.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     IPADDR = 258,
     NET_MASK = 259,
     NET_CIDR = 260,
     NUMBER = 261,
     STRING = 262,
     WORD = 263,
     KEYWORD = 264,
     KW_DH_GROUP = 265,
     KW_ORDER = 266,
     KW_ALLOW = 267,
     KW_DENY = 268,
     KW_HOST = 269,
     KW_PEER = 270,
     KW_AUTH = 271,
     KW_NONE = 272,
     KW_PSK = 273,
     KW_PSK_FILE = 274,
     KW_RSA = 275,
     KW_RSA_PUB = 276,
     KW_RSA_PUB_FILE = 277,
     KW_RSA_KEY = 278,
     KW_RSA_KEY_FILE = 279
   };
#endif
#define IPADDR 258
#define NET_MASK 259
#define NET_CIDR 260
#define NUMBER 261
#define STRING 262
#define WORD 263
#define KEYWORD 264
#define KW_DH_GROUP 265
#define KW_ORDER 266
#define KW_ALLOW 267
#define KW_DENY 268
#define KW_HOST 269
#define KW_PEER 270
#define KW_AUTH 271
#define KW_NONE 272
#define KW_PSK 273
#define KW_PSK_FILE 274
#define KW_RSA 275
#define KW_RSA_PUB 276
#define KW_RSA_PUB_FILE 277
#define KW_RSA_KEY 278
#define KW_RSA_KEY_FILE 279




#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 69 "conf_pars.y"
typedef union YYSTYPE {
	long	num;
	char*	str;
	void*	ptr;
} YYSTYPE;
/* Line 1240 of yacc.c.  */
#line 90 "conf_pars.h"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;



