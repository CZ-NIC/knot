/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

#ifndef YY_CF_CF_PARSE_TAB_H_INCLUDED
# define YY_CF_CF_PARSE_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int cf_debug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    END = 258,
    INVALID_TOKEN = 259,
    TEXT = 260,
    NUM = 261,
    INTERVAL = 262,
    SIZE = 263,
    BOOL = 264,
    SYSTEM = 265,
    IDENTITY = 266,
    HOSTNAME = 267,
    SVERSION = 268,
    NSID = 269,
    KEY = 270,
    KEYS = 271,
    MAX_UDP_PAYLOAD = 272,
    TSIG_ALGO_NAME = 273,
    WORKERS = 274,
    BACKGROUND_WORKERS = 275,
    ASYNC_START = 276,
    USER = 277,
    RUNDIR = 278,
    PIDFILE = 279,
    REMOTES = 280,
    GROUPS = 281,
    ZONES = 282,
    FILENAME = 283,
    DISABLE_ANY = 284,
    SEMANTIC_CHECKS = 285,
    NOTIFY_RETRIES = 286,
    NOTIFY_TIMEOUT = 287,
    DBSYNC_TIMEOUT = 288,
    IXFR_FSLIMIT = 289,
    MAX_ZONE_SIZE = 290,
    XFR_IN = 291,
    XFR_OUT = 292,
    UPDATE_IN = 293,
    NOTIFY_IN = 294,
    NOTIFY_OUT = 295,
    BUILD_DIFFS = 296,
    MAX_CONN_IDLE = 297,
    MAX_CONN_HS = 298,
    MAX_CONN_REPLY = 299,
    MAX_TCP_CLIENTS = 300,
    RATE_LIMIT = 301,
    RATE_LIMIT_SIZE = 302,
    RATE_LIMIT_SLIP = 303,
    TRANSFERS = 304,
    STORAGE = 305,
    TIMER_DB = 306,
    DNSSEC_ENABLE = 307,
    DNSSEC_KEYDIR = 308,
    SIGNATURE_LIFETIME = 309,
    SERIAL_POLICY = 310,
    SERIAL_POLICY_VAL = 311,
    QUERY_MODULE = 312,
    INTERFACES = 313,
    ADDRESS = 314,
    PORT = 315,
    IPA = 316,
    IPA6 = 317,
    VIA = 318,
    CONTROL = 319,
    ALLOW = 320,
    LISTEN_ON = 321,
    LOG = 322,
    LOG_DEST = 323,
    LOG_SRC = 324,
    LOG_LEVEL = 325
  };
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 352 "cf-parse.y" /* yacc.c:1909  */

	struct {
		char *t;
		long i;
		size_t l;
	} tok;

#line 133 "cf-parse.tab.h" /* yacc.c:1909  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int cf_parse (void *scanner);

#endif /* !YY_CF_CF_PARSE_TAB_H_INCLUDED  */
