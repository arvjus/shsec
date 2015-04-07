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

/* Written by Richard Stallman by simplifying the original so called
   ``semantic'' parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Using locations.  */
#define YYLSP_NEEDED 0



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




/* Copy the first part of user declarations.  */
#line 20 "conf_pars.y"

	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <ctype.h>
	#include "conf_defs.h"

	#define YYDEBUG 1
	int yylex();
	void yyerror(char*);
	void yywarning(char*);

	/* macros */
	#define STRCPY(d,s) { \
		if (strlen(s) >= sizeof(d)) yyerror("string is too long"); \
		strncpy(d, s, sizeof(d)); free(s); \
	}

	#define SETPTR(d,s) { \
		if (d) { \
			free(d); yywarning("variable has been already initialized"); } \
		d = s; \
	}

	/* local functions */
	void set_keyword(const char* name, void* value, int type);
	void* str_to_lentry(char* data, char type);
	void append_to_list(void* list, void* item);
	void free_list(LISTENTRY* list);

	/* global conf_XXX variables */
	int			conf_egid = 0;
	char		conf_pid_file[MAX_FILE_LEN];
	char		conf_keydb_file[MAX_FILE_LEN];
	char		conf_sock_file[MAX_FILE_LEN];
	int			conf_verbose = 0;
	int			conf_flush_db = 0;
	int			conf_dh_group = 0;
	char		conf_listen[20];
	int			conf_port = 0;
	char		conf_host[MAX_HOST_LEN];
	char*		conf_rsa_key = NULL;
	char		conf_rsa_key_file[MAX_FILE_LEN];
	int			conf_search_order;
	LISTENTRY*	conf_allow_peers = NULL;
	LISTENTRY*	conf_deny_peers = NULL;
	PEERENTRY*	conf_peers = NULL;


/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 69 "conf_pars.y"
typedef union YYSTYPE {
	long	num;
	char*	str;
	void*	ptr;
} YYSTYPE;
/* Line 191 of yacc.c.  */
#line 178 "conf_pars.c"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 214 of yacc.c.  */
#line 190 "conf_pars.c"

#if ! defined (yyoverflow) || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# if YYSTACK_USE_ALLOCA
#  define YYSTACK_ALLOC alloca
# else
#  ifndef YYSTACK_USE_ALLOCA
#   if defined (alloca) || defined (_ALLOCA_H)
#    define YYSTACK_ALLOC alloca
#   else
#    ifdef __GNUC__
#     define YYSTACK_ALLOC __builtin_alloca
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning. */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
# else
#  if defined (__STDC__) || defined (__cplusplus)
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   define YYSIZE_T size_t
#  endif
#  define YYSTACK_ALLOC malloc
#  define YYSTACK_FREE free
# endif
#endif /* ! defined (yyoverflow) || YYERROR_VERBOSE */


#if (! defined (yyoverflow) \
     && (! defined (__cplusplus) \
	 || (YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  short yyss;
  YYSTYPE yyvs;
  };

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short) + sizeof (YYSTYPE))				\
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  register YYSIZE_T yyi;		\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (0)
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (0)

#endif

#if defined (__STDC__) || defined (__cplusplus)
   typedef signed char yysigned_char;
#else
   typedef short yysigned_char;
#endif

/* YYFINAL -- State number of the termination state. */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   72

/* YYNTOKENS -- Number of terminals. */
#define YYNTOKENS  30
/* YYNNTS -- Number of nonterminals. */
#define YYNNTS  8
/* YYNRULES -- Number of rules. */
#define YYNRULES  38
/* YYNRULES -- Number of states. */
#define YYNSTATES  76

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   279

#define YYTRANSLATE(YYX) 						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const unsigned char yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,    29,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,    25,
       2,    26,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    27,     2,    28,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const unsigned char yyprhs[] =
{
       0,     0,     3,     4,     8,     9,    13,    17,    21,    25,
      29,    33,    37,    41,    47,    53,    59,    63,    67,    70,
      74,    78,    82,    86,    90,    94,    98,   102,   104,   108,
     110,   112,   114,   116,   118,   120,   122,   124,   126
};

/* YYRHS -- A `-1'-separated list of the rules' RHS. */
static const yysigned_char yyrhs[] =
{
      31,     0,    -1,    -1,    31,    32,    25,    -1,    -1,     9,
      26,     8,    -1,     9,    26,     7,    -1,     9,    26,     6,
      -1,     9,    26,     3,    -1,    10,    26,     6,    -1,    14,
      26,    37,    -1,    23,    26,     7,    -1,    24,    26,     7,
      -1,    15,    37,    27,    33,    28,    -1,    11,    26,    12,
      29,    13,    -1,    11,    26,    13,    29,    12,    -1,    12,
      26,    35,    -1,    13,    26,    35,    -1,    34,    25,    -1,
      33,    34,    25,    -1,    18,    26,     7,    -1,    19,    26,
       7,    -1,    21,    26,     7,    -1,    22,    26,     7,    -1,
      16,    26,    17,    -1,    16,    26,    18,    -1,    16,    26,
      20,    -1,    36,    -1,    35,    29,    36,    -1,     8,    -1,
       7,    -1,     3,    -1,     4,    -1,     5,    -1,     8,    -1,
       7,    -1,     3,    -1,     4,    -1,     5,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const unsigned char yyrline[] =
{
       0,    88,    88,    89,    92,    93,    96,    99,   102,   105,
     121,   124,   127,   130,   140,   143,   146,   149,   154,   155,
     160,   163,   166,   169,   172,   175,   178,   182,   183,   188,
     189,   190,   191,   192,   195,   195,   195,   195,   195
};
#endif

#if YYDEBUG || YYERROR_VERBOSE
/* YYTNME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals. */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "IPADDR", "NET_MASK", "NET_CIDR", "NUMBER", 
  "STRING", "WORD", "KEYWORD", "KW_DH_GROUP", "KW_ORDER", "KW_ALLOW", 
  "KW_DENY", "KW_HOST", "KW_PEER", "KW_AUTH", "KW_NONE", "KW_PSK", 
  "KW_PSK_FILE", "KW_RSA", "KW_RSA_PUB", "KW_RSA_PUB_FILE", "KW_RSA_KEY", 
  "KW_RSA_KEY_FILE", "';'", "'='", "'{'", "'}'", "','", "$accept", 
  "statements", "statement", "peer_statements", "peer_statement", "list", 
  "list_entry", "identity", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const unsigned short yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,    59,    61,   123,   125,    44
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const unsigned char yyr1[] =
{
       0,    30,    31,    31,    32,    32,    32,    32,    32,    32,
      32,    32,    32,    32,    32,    32,    32,    32,    33,    33,
      34,    34,    34,    34,    34,    34,    34,    35,    35,    36,
      36,    36,    36,    36,    37,    37,    37,    37,    37
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const unsigned char yyr2[] =
{
       0,     2,     0,     3,     0,     3,     3,     3,     3,     3,
       3,     3,     3,     5,     5,     5,     3,     3,     2,     3,
       3,     3,     3,     3,     3,     3,     3,     1,     3,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const unsigned char yydefact[] =
{
       2,     4,     1,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    36,
      37,    38,    35,    34,     0,     0,     0,     3,     8,     7,
       6,     5,     9,     0,     0,    31,    32,    33,    30,    29,
      16,    27,    17,    10,     0,    11,    12,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    14,    15,    28,
       0,     0,     0,     0,     0,    13,     0,    18,    24,    25,
      26,    20,    21,    22,    23,    19
};

/* YYDEFGOTO[NTERM-NUM]. */
static const yysigned_char yydefgoto[] =
{
      -1,     1,    12,    55,    56,    40,    41,    24
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -25
static const yysigned_char yypact[] =
{
     -25,     0,   -25,   -24,   -21,   -18,    -7,    -4,     3,    13,
      15,    16,     1,    37,    42,    20,    31,    31,    13,   -25,
     -25,   -25,   -25,   -25,    23,    44,    45,   -25,   -25,   -25,
     -25,   -25,   -25,    24,    25,   -25,   -25,   -25,   -25,   -25,
      26,   -25,    26,   -25,   -15,   -25,   -25,    43,    46,    31,
      33,    34,    35,    36,    38,     9,    32,   -25,   -25,   -25,
      29,    56,    58,    59,    60,   -25,    47,   -25,   -25,   -25,
     -25,   -25,   -25,   -25,   -25,   -25
};

/* YYPGOTO[NTERM-NUM].  */
static const yysigned_char yypgoto[] =
{
     -25,   -25,   -25,   -25,    14,    51,    21,    53
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const unsigned char yytable[] =
{
       2,    50,    13,    51,    52,    14,    53,    54,    15,     3,
       4,     5,     6,     7,     8,     9,    19,    20,    21,    16,
      22,    23,    17,    10,    11,    50,    27,    51,    52,    18,
      53,    54,    33,    34,    35,    36,    37,    65,    38,    39,
      28,    25,    26,    29,    30,    31,    68,    69,    32,    70,
      44,    45,    46,    47,    48,    49,    57,    67,    58,    60,
      61,    62,    63,    71,    64,    72,    73,    74,    42,    66,
      59,    43,    75
};

static const unsigned char yycheck[] =
{
       0,    16,    26,    18,    19,    26,    21,    22,    26,     9,
      10,    11,    12,    13,    14,    15,     3,     4,     5,    26,
       7,     8,    26,    23,    24,    16,    25,    18,    19,    26,
      21,    22,    12,    13,     3,     4,     5,    28,     7,     8,
       3,    26,    26,     6,     7,     8,    17,    18,     6,    20,
      27,     7,     7,    29,    29,    29,    13,    25,    12,    26,
      26,    26,    26,     7,    26,     7,     7,     7,    17,    55,
      49,    18,    25
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const unsigned char yystos[] =
{
       0,    31,     0,     9,    10,    11,    12,    13,    14,    15,
      23,    24,    32,    26,    26,    26,    26,    26,    26,     3,
       4,     5,     7,     8,    37,    26,    26,    25,     3,     6,
       7,     8,     6,    12,    13,     3,     4,     5,     7,     8,
      35,    36,    35,    37,    27,     7,     7,    29,    29,    29,
      16,    18,    19,    21,    22,    33,    34,    13,    12,    36,
      26,    26,    26,    26,    26,    28,    34,    25,    17,    18,
      20,     7,     7,     7,     7,    25
};

#if ! defined (YYSIZE_T) && defined (__SIZE_TYPE__)
# define YYSIZE_T __SIZE_TYPE__
#endif
#if ! defined (YYSIZE_T) && defined (size_t)
# define YYSIZE_T size_t
#endif
#if ! defined (YYSIZE_T)
# if defined (__STDC__) || defined (__cplusplus)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# endif
#endif
#if ! defined (YYSIZE_T)
# define YYSIZE_T unsigned int
#endif

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrlab1


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { 								\
      yyerror ("syntax error: cannot back up");\
      YYERROR;							\
    }								\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

/* YYLLOC_DEFAULT -- Compute the default location (before the actions
   are run).  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)         \
  Current.first_line   = Rhs[1].first_line;      \
  Current.first_column = Rhs[1].first_column;    \
  Current.last_line    = Rhs[N].last_line;       \
  Current.last_column  = Rhs[N].last_column;
#endif

/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (0)

# define YYDSYMPRINT(Args)			\
do {						\
  if (yydebug)					\
    yysymprint Args;				\
} while (0)

# define YYDSYMPRINTF(Title, Token, Value, Location)		\
do {								\
  if (yydebug)							\
    {								\
      YYFPRINTF (stderr, "%s ", Title);				\
      yysymprint (stderr, 					\
                  Token, Value);	\
      YYFPRINTF (stderr, "\n");					\
    }								\
} while (0)

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (cinluded).                                                   |
`------------------------------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yy_stack_print (short *bottom, short *top)
#else
static void
yy_stack_print (bottom, top)
    short *bottom;
    short *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (/* Nothing. */; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yy_reduce_print (int yyrule)
#else
static void
yy_reduce_print (yyrule)
    int yyrule;
#endif
{
  int yyi;
  unsigned int yylineno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %u), ",
             yyrule - 1, yylineno);
  /* Print the symbols being reduced, and their result.  */
  for (yyi = yyprhs[yyrule]; 0 <= yyrhs[yyi]; yyi++)
    YYFPRINTF (stderr, "%s ", yytname [yyrhs[yyi]]);
  YYFPRINTF (stderr, "-> %s\n", yytname [yyr1[yyrule]]);
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (Rule);		\
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YYDSYMPRINT(Args)
# define YYDSYMPRINTF(Title, Token, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   SIZE_MAX < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#if YYMAXDEPTH == 0
# undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined (__GLIBC__) && defined (_STRING_H)
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
#   if defined (__STDC__) || defined (__cplusplus)
yystrlen (const char *yystr)
#   else
yystrlen (yystr)
     const char *yystr;
#   endif
{
  register const char *yys = yystr;

  while (*yys++ != '\0')
    continue;

  return yys - yystr - 1;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined (__GLIBC__) && defined (_STRING_H) && defined (_GNU_SOURCE)
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
#   if defined (__STDC__) || defined (__cplusplus)
yystpcpy (char *yydest, const char *yysrc)
#   else
yystpcpy (yydest, yysrc)
     char *yydest;
     const char *yysrc;
#   endif
{
  register char *yyd = yydest;
  register const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

#endif /* !YYERROR_VERBOSE */



#if YYDEBUG
/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yysymprint (FILE *yyoutput, int yytype, YYSTYPE *yyvaluep)
#else
static void
yysymprint (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvaluep;

  if (yytype < YYNTOKENS)
    {
      YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
# ifdef YYPRINT
      YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
    }
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  switch (yytype)
    {
      default:
        break;
    }
  YYFPRINTF (yyoutput, ")");
}

#endif /* ! YYDEBUG */
/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yydestruct (int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yytype, yyvaluep)
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvaluep;

  switch (yytype)
    {

      default:
        break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
int yyparse (void *YYPARSE_PARAM);
# else
int yyparse ();
# endif
#else /* ! YYPARSE_PARAM */
#if defined (__STDC__) || defined (__cplusplus)
int yyparse (void);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */



/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;



/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
int yyparse (void *YYPARSE_PARAM)
# else
int yyparse (YYPARSE_PARAM)
  void *YYPARSE_PARAM;
# endif
#else /* ! YYPARSE_PARAM */
#if defined (__STDC__) || defined (__cplusplus)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{
  
  register int yystate;
  register int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  short	yyssa[YYINITDEPTH];
  short *yyss = yyssa;
  register short *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  register YYSTYPE *yyvsp;



#define YYPOPSTACK   (yyvsp--, yyssp--)

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;


  /* When reducing, the number of symbols on the RHS of the reduced
     rule.  */
  int yylen;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed. so pushing a state here evens the stacks.
     */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack. Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	short *yyss1 = yyss;


	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),

		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyoverflowlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyoverflowlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	short *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyoverflowlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);

#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;


      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YYDSYMPRINTF ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */
  YYDPRINTF ((stderr, "Shifting token %s, ", yytname[yytoken]));

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;


  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  yystate = yyn;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 5:
#line 94 "conf_pars.y"
    { set_keyword(yyvsp[-2].str, yyvsp[0].str, VT_WORD); }
    break;

  case 6:
#line 97 "conf_pars.y"
    { set_keyword(yyvsp[-2].str, yyvsp[0].str, VT_STRING); }
    break;

  case 7:
#line 100 "conf_pars.y"
    { set_keyword(yyvsp[-2].str, &yyvsp[0].num, VT_NUMBER); }
    break;

  case 8:
#line 103 "conf_pars.y"
    { set_keyword(yyvsp[-2].str, yyvsp[0].str, VT_IPADDR); }
    break;

  case 9:
#line 106 "conf_pars.y"
    {
			int		i;
			long	groups[] = { 768, 1024, 1536, 2048, 3072, 4096, 0 };

			/* check validity */
			for (i = 0; groups[i] && groups[i] != yyvsp[0].num; i++)
				;

			if (!groups[i])
				yyerror("invalid dh-group");
		
			/* assign value */
			conf_dh_group = yyvsp[0].num;
		}
    break;

  case 10:
#line 122 "conf_pars.y"
    { STRCPY(conf_host, yyvsp[0].str); }
    break;

  case 11:
#line 125 "conf_pars.y"
    { SETPTR(conf_rsa_key, yyvsp[0].str); }
    break;

  case 12:
#line 128 "conf_pars.y"
    { STRCPY(conf_rsa_key_file, yyvsp[0].str); }
    break;

  case 13:
#line 131 "conf_pars.y"
    {
			PEERENTRY* pe = (PEERENTRY*)malloc(sizeof(PEERENTRY));
			if (!pe) yyerror("nomem");
			pe->identity = yyvsp[-3].str;
			pe->options = yyvsp[-1].ptr;
			pe->next = conf_peers;
			conf_peers = pe;
		}
    break;

  case 14:
#line 141 "conf_pars.y"
    { conf_search_order = SO_ALLOW_DENY; }
    break;

  case 15:
#line 144 "conf_pars.y"
    { conf_search_order = SO_DENY_ALLOW; }
    break;

  case 16:
#line 147 "conf_pars.y"
    { SETPTR(conf_allow_peers, yyvsp[0].ptr); }
    break;

  case 17:
#line 150 "conf_pars.y"
    { SETPTR(conf_deny_peers, yyvsp[0].ptr); }
    break;

  case 19:
#line 156 "conf_pars.y"
    { append_to_list(yyvsp[-2].ptr, yyvsp[-1].ptr); }
    break;

  case 20:
#line 161 "conf_pars.y"
    { yyval.ptr = str_to_lentry(yyvsp[0].str, ST_PSK); }
    break;

  case 21:
#line 164 "conf_pars.y"
    { yyval.ptr = str_to_lentry(yyvsp[0].str, ST_PSK_FILE); }
    break;

  case 22:
#line 167 "conf_pars.y"
    { yyval.ptr = str_to_lentry(yyvsp[0].str, ST_RSA_PUB); }
    break;

  case 23:
#line 170 "conf_pars.y"
    { yyval.ptr = str_to_lentry(yyvsp[0].str, ST_RSA_PUB_FILE); }
    break;

  case 24:
#line 173 "conf_pars.y"
    { yyval.ptr = str_to_lentry(NULL, ST_AUTH_NONE); }
    break;

  case 25:
#line 176 "conf_pars.y"
    { yyval.ptr = str_to_lentry(NULL, ST_AUTH_PSK); }
    break;

  case 26:
#line 179 "conf_pars.y"
    { yyval.ptr = str_to_lentry(NULL, ST_AUTH_RSA); }
    break;

  case 28:
#line 184 "conf_pars.y"
    { append_to_list(yyvsp[-2].ptr, yyvsp[0].ptr); }
    break;

  case 29:
#line 188 "conf_pars.y"
    { yyval.ptr = str_to_lentry(yyvsp[0].str, VT_WORD); }
    break;

  case 30:
#line 189 "conf_pars.y"
    { yyval.ptr = str_to_lentry(yyvsp[0].str, VT_STRING); }
    break;

  case 31:
#line 190 "conf_pars.y"
    { yyval.ptr = str_to_lentry(yyvsp[0].str, VT_IPADDR); }
    break;

  case 32:
#line 191 "conf_pars.y"
    { yyval.ptr = str_to_lentry(yyvsp[0].str, VT_NET_MASK); }
    break;

  case 33:
#line 192 "conf_pars.y"
    { yyval.ptr = str_to_lentry(yyvsp[0].str, VT_NET_CIDR); }
    break;


    }

/* Line 999 of yacc.c.  */
#line 1274 "conf_pars.c"

  yyvsp -= yylen;
  yyssp -= yylen;


  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;


  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (YYPACT_NINF < yyn && yyn < YYLAST)
	{
	  YYSIZE_T yysize = 0;
	  int yytype = YYTRANSLATE (yychar);
	  char *yymsg;
	  int yyx, yycount;

	  yycount = 0;
	  /* Start YYX at -YYN if negative to avoid negative indexes in
	     YYCHECK.  */
	  for (yyx = yyn < 0 ? -yyn : 0;
	       yyx < (int) (sizeof (yytname) / sizeof (char *)); yyx++)
	    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	      yysize += yystrlen (yytname[yyx]) + 15, yycount++;
	  yysize += yystrlen ("syntax error, unexpected ") + 1;
	  yysize += yystrlen (yytname[yytype]);
	  yymsg = (char *) YYSTACK_ALLOC (yysize);
	  if (yymsg != 0)
	    {
	      char *yyp = yystpcpy (yymsg, "syntax error, unexpected ");
	      yyp = yystpcpy (yyp, yytname[yytype]);

	      if (yycount < 5)
		{
		  yycount = 0;
		  for (yyx = yyn < 0 ? -yyn : 0;
		       yyx < (int) (sizeof (yytname) / sizeof (char *));
		       yyx++)
		    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
		      {
			const char *yyq = ! yycount ? ", expecting " : " or ";
			yyp = yystpcpy (yyp, yyq);
			yyp = yystpcpy (yyp, yytname[yyx]);
			yycount++;
		      }
		}
	      yyerror (yymsg);
	      YYSTACK_FREE (yymsg);
	    }
	  else
	    yyerror ("syntax error; also virtual memory exhausted");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror ("syntax error");
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      /* Return failure if at end of input.  */
      if (yychar == YYEOF)
        {
	  /* Pop the error token.  */
          YYPOPSTACK;
	  /* Pop the rest of the stack.  */
	  while (yyss < yyssp)
	    {
	      YYDSYMPRINTF ("Error: popping", yystos[*yyssp], yyvsp, yylsp);
	      yydestruct (yystos[*yyssp], yyvsp);
	      YYPOPSTACK;
	    }
	  YYABORT;
        }

      YYDSYMPRINTF ("Error: discarding", yytoken, &yylval, &yylloc);
      yydestruct (yytoken, &yylval);
      yychar = YYEMPTY;

    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*----------------------------------------------------.
| yyerrlab1 -- error raised explicitly by an action.  |
`----------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;

      YYDSYMPRINTF ("Error: popping", yystos[*yyssp], yyvsp, yylsp);
      yydestruct (yystos[yystate], yyvsp);
      yyvsp--;
      yystate = *--yyssp;

      YY_STACK_PRINT (yyss, yyssp);
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  YYDPRINTF ((stderr, "Shifting error token, "));

  *++yyvsp = yylval;


  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#ifndef yyoverflow
/*----------------------------------------------.
| yyoverflowlab -- parser overflow comes here.  |
`----------------------------------------------*/
yyoverflowlab:
  yyerror ("parser stack overflow");
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  return yyresult;
}


#line 198 "conf_pars.y"


/*
 * public functions
 */

void conf_free()
{
	PEERENTRY* pe;
	
	/* free conf_allow_peers */
	free_list(conf_allow_peers);
	conf_allow_peers = (LISTENTRY*)NULL;
	
	/* free conf_deny_peers */
	free_list(conf_deny_peers);
	conf_deny_peers = (LISTENTRY*)NULL;
	
	/* free conf_peers */
	pe = conf_peers;
	while (pe) {
		PEERENTRY* tmp = pe;
		free(pe->identity);
		free_list(pe->options);
		pe = pe->next;
		free(tmp);
	}
	conf_peers = (PEERENTRY*)NULL;

	/* free host credentials */
	free(conf_rsa_key);
	conf_rsa_key = NULL;

	/* free allow, deny lists */
	free(conf_allow_peers);
	free(conf_deny_peers);
}
	  
/*
 * local functions
 */

void set_keyword(const char* name, void* value, int type) 
{
	typedef struct keyword_entry {
		char*	name;
		void*	value;
		int		size;
		int		type;
	} keyword_entry;
	
	static keyword_entry keyword_map[] = {
	{ "pid-file",	conf_pid_file,		sizeof(conf_pid_file),	 VT_STRING },
	{ "keydb-file",	conf_keydb_file,	sizeof(conf_keydb_file), VT_STRING },
	{ "sock-file",	conf_sock_file,		sizeof(conf_sock_file),	 VT_STRING },
	{ "listen",		conf_listen,		sizeof(conf_listen),	 VT_IPADDR },
	{ "verbose",	&conf_verbose,		0, VT_NUMBER | VT_WORD | VT_STRING },
	{ "flush-db",	&conf_flush_db,		0, VT_NUMBER | VT_WORD | VT_STRING },
	{ "egid",		&conf_egid,			0, 						 VT_NUMBER },
	{ "port",		&conf_port,			0, 						 VT_NUMBER },
	{ (char*)NULL,	0,					0, 0 } };

	int i;
	struct keyword_entry* ke = NULL;

	for (i = 0; keyword_map[i].name; i++)
		if (!strcmp(keyword_map[i].name, name)) {
			ke = &keyword_map[i];
			break;
		}

	if (!ke || !(ke->type & type)) 
		yyerror("syntax error");

	switch (ke->type) {
	case VT_STRING:
	case VT_IPADDR:
		if (strlen((char*)value) >= ke->size)
 			yyerror("string is too long");
		strcpy((char*)ke->value, (char*)value);
		break;

	case VT_NUMBER:
		*((int*)ke->value) = *((int*)value);
		break;

	case VT_NUMBER | VT_WORD | VT_STRING:
		*((int*)ke->value) = (type == VT_NUMBER) ? *((int*)value) :
			(!strcasecmp((char*)value, "yes") ||
			tolower(*((char*)value)) == 'y');
		break;
	}
}

void* str_to_lentry(char* data, char type)
{
	LISTENTRY* le = (LISTENTRY*)malloc(sizeof(LISTENTRY));
	if (!le) yyerror("nomem");
	le->data = data;
	le->type = type;
	le->next = (LISTENTRY*)NULL;
	return (void*)le;
}

void append_to_list(void* list, void* item)
{
	LISTENTRY* curr = (LISTENTRY*)list;
	while (curr->next)
		curr = curr->next;
	curr->next = (LISTENTRY*)item;
}

void free_list(LISTENTRY* le) 
{
	while (le) {
		LISTENTRY* tmp = le;
		free(le->data);
		le = le->next;
		free(tmp);
	}
}


