/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison implementation for Yacc-like parsers in C

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

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.0.4"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         cf_parse
#define yylex           cf_lex
#define yyerror         cf_error
#define yydebug         cf_debug
#define yynerrs         cf_nerrs


/* Copy the first part of user declarations.  */
#line 16 "cf-parse.y" /* yacc.c:339  */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "utils/knot1to2/scheme.h"
#include "utils/knot1to2/extra.h"
#include "utils/knot1to2/cf-parse.tab.h"
#include "contrib/openbsd/strlcat.h"
#include "contrib/openbsd/strlcpy.h"

#define DEFAULT_PORT		53
#define DEFAULT_CTL_PORT	5533

static char *_addr = NULL;
static int _port = -1;
static int _mask = -1;
static char *_str = NULL;
static int _acl_run = -1;
static bool _first = true;

#define ERROR_BUFFER_SIZE       512
extern int cf_lex (YYSTYPE *lvalp, void *scanner);
extern int cf_get_lineno(void *scanner);
extern char *cf_get_text(void *scanner);
extern conf_extra_t *cf_get_extra(void *scanner);
volatile int parser_ret = 0;

static void cf_print_error(void *scanner, const char *prefix, const char *msg)
{
	int lineno = -1;
	char *filename = "";
	conf_include_t *inc = NULL;

	if (scanner) {
		conf_extra_t *extra = cf_get_extra(scanner);
		lineno = cf_get_lineno(scanner);
		inc = conf_includes_top(extra->includes);
	}

	if (inc && inc->filename) {
		filename = inc->filename;
	}

	printf("%s: %s (file '%s', line %d)\n", prefix, msg, filename, lineno);

	fflush(stdout);
}


void cf_error(void *scanner, const char *format, ...)
{
	char buffer[ERROR_BUFFER_SIZE];
	va_list ap;

	va_start(ap, format);
	vsnprintf(buffer, sizeof(buffer), format, ap);
	va_end(ap);

	cf_print_error(scanner, "Error", buffer);
	parser_ret = -1;

	conf_extra_t *extra = cf_get_extra(scanner);
	extra->error = true;
}

void cf_warning(void *scanner, const char *format, ...)
{
	char buffer[ERROR_BUFFER_SIZE];
	va_list ap;

	va_start(ap, format);
	vsnprintf(buffer, sizeof(buffer), format, ap);
	va_end(ap);

	cf_print_error(scanner, "Warning", buffer);
}

static bool f_section(void *scanner, int run, section_t id)
{
	conf_extra_t *extra = cf_get_extra(scanner);
	if (extra->run != run) return false;
	if (extra->share->have_sections[id]) return false;

	fprintf(extra->share->out, "\n%s:\n", section_name(id) + 1);
	extra->share->have_sections[id] = true;
	return true;
}

static void f_name(void *scanner, int run, const char *name, bool is_id)
{
	conf_extra_t *extra = cf_get_extra(scanner);
	if (extra->run != run) return;

	fprintf(extra->share->out, "%s%s: ", is_id ? "  - " : "    ", name + 1);
}

static void f_val(void *scanner, int run, bool quote, const char *format, ...)
{
	conf_extra_t *extra = cf_get_extra(scanner);
	if (extra->run != run) return;

	if (quote) {
		fprintf(extra->share->out, "\"");
	}

	va_list ap;
	va_start(ap, format);
	vfprintf(extra->share->out, format, ap);
	va_end(ap);

	if (quote) {
		fprintf(extra->share->out, "\"");
	}
}

static void f_quote(void *scanner, int run, const char *name, const char *val)
{
	f_name(scanner, run, name, false);
	f_val(scanner, run, true, "%s", val);
	f_val(scanner, run, false, "\n");
}

static void f_str(void *scanner, int run, const char *name, const char *val)
{
	if (val != NULL) {
		f_name(scanner, run, name, false);
		f_val(scanner, run, false, "%s\n", val);
	}
}

static void f_auto_str(void *scanner, int run, const char *name, long val)
{
	if (val == 0) {
		f_name(scanner, run, name, false);
		f_val(scanner, run, true, "");
		f_val(scanner, run, false, "\n");
	}
}

static void f_bool(void *scanner, int run, const char *name, long val)
{
	f_name(scanner, run, name, false);
	f_val(scanner, run, false, "%s\n", val != 0 ? "on" : "off");
}

static void f_int(void *scanner, int run, const char *name, long val)
{
	f_name(scanner, run, name, false);
	f_val(scanner, run, false, "%ld\n", val);
}

static void f_id(void *scanner, int run, const char *name, const char *val)
{
	f_name(scanner, run, name, true);
	f_val(scanner, run, false, "%s\n", val);
}

static void if_add(void *scanner, const char *key, const char *value)
{
	conf_extra_t *extra = cf_get_extra(scanner);

	if (extra->run == S_FIRST) {
		*hattrie_get(extra->share->ifaces, key, strlen(key)) = strdup(value);
	}
}

static const char* if_get(void *scanner, int run, const char *key)
{
	conf_extra_t *extra = cf_get_extra(scanner);

	if (extra->run == run) {
		return *hattrie_get(extra->share->ifaces, key, strlen(key));
	}

	return NULL;
}

typedef enum {
	ACL_RMT,
	ACL_XFR,
	ACL_NTF,
	ACL_UPD,
} acl_type_t;

static void acl_start(void *scanner, acl_type_t type)
{
	conf_extra_t *extra = cf_get_extra(scanner);

	if (extra->run == S_FIRST) {
		switch (type) {
		case ACL_RMT: extra->current_trie = extra->share->remotes; break;
		case ACL_XFR: extra->current_trie = extra->share->acl_xfer; break;
		case ACL_NTF: extra->current_trie = extra->share->acl_notify; break;
		case ACL_UPD: extra->current_trie = extra->share->acl_update; break;
		}
	}

	if (extra->run != _acl_run) return;

	fprintf(extra->share->out, "[");
	_first = true;
}

static void acl_next(void *scanner, const char *value)
{
	conf_extra_t *extra = cf_get_extra(scanner);

	hattrie_t **trie = (hattrie_t **)hattrie_tryget(extra->share->groups,
	                                                value, strlen(value));

	if (extra->run == S_FIRST) {
		if (trie != NULL) {
			hattrie_iter_t *it = hattrie_iter_begin(*trie, false);
			for (; !hattrie_iter_finished(it); hattrie_iter_next(it)) {
				size_t len = 0;
				const char *data = hattrie_iter_key(it, &len);
				*hattrie_get(extra->current_trie, data, len) = NULL;
			}
			hattrie_iter_free(it);
		} else {
			*hattrie_get(extra->current_trie, value, strlen(value)) = NULL;
		}
	}

	if (extra->run != _acl_run) return;

	if (_first) {
		_first = false;
	} else {
		fprintf(extra->share->out, ", ");
	}

	if (trie != NULL) {
		bool init = true;
		hattrie_iter_t *it = hattrie_iter_begin(*trie, false);
		for (; !hattrie_iter_finished(it); hattrie_iter_next(it)) {
			size_t len = 0;
			const char *data = hattrie_iter_key(it, &len);
			if (init) {
				init = false;
			} else {
				fprintf(extra->share->out, ", ");
			}
			f_val(scanner, extra->run, false, "%s", _str);
			f_val(scanner, extra->run, false, "%.*s", (int)len, data);
		}
		hattrie_iter_free(it);
	} else {
		f_val(scanner, extra->run, false, "%s", _str);
		f_val(scanner, extra->run, false, "%s", value);
	}
}

static void acl_end(void *scanner)
{
	conf_extra_t *extra = cf_get_extra(scanner);
	if (extra->run != _acl_run) return;

	fprintf(extra->share->out, "]\n");
}

static bool is_acl(void *scanner, const char *str) {
	conf_extra_t *extra = cf_get_extra(scanner);

	return hattrie_tryget(extra->share->acl_xfer, str, strlen(str))    != NULL ||
	       hattrie_tryget(extra->share->acl_notify, str, strlen(str))  != NULL ||
	       hattrie_tryget(extra->share->acl_update, str, strlen(str))  != NULL;
}

static bool have_acl(void *scanner) {
	conf_extra_t *extra = cf_get_extra(scanner);

	return (hattrie_weight(extra->share->acl_xfer) +
	        hattrie_weight(extra->share->acl_notify) +
	        hattrie_weight(extra->share->acl_update)) > 0;
}

static char *acl_actions(void *scanner, const char *str) {
	conf_extra_t *extra = cf_get_extra(scanner);

	static char actions[64] = { 0 };
	_first = true;

	strlcpy(actions, "[", sizeof(actions));

	if (hattrie_tryget(extra->share->acl_xfer, str, strlen(str)) != NULL) {
		strlcat(actions, _first ? "" : ", ", sizeof(actions)); _first = false;
		strlcat(actions, "transfer", sizeof(actions));
	}
	if (hattrie_tryget(extra->share->acl_notify, str, strlen(str)) != NULL) {
		strlcat(actions, _first ? "" : ", ", sizeof(actions)); _first = false;
		strlcat(actions, "notify", sizeof(actions));
	}
	if (hattrie_tryget(extra->share->acl_update, str, strlen(str)) != NULL) {
		strlcat(actions, _first ? "" : ", ", sizeof(actions)); _first = false;
		strlcat(actions, "update", sizeof(actions));
	}

	strlcat(actions, "]", sizeof(actions));

	return actions;
}

static void grp_init(void *scanner, const char *name)
{
	conf_extra_t *extra = cf_get_extra(scanner);

	if (extra->run == S_FIRST) {
		hattrie_t **trie = (hattrie_t **)hattrie_get(extra->share->groups,
		                                             name, strlen(name));
		if (*trie == NULL) {
			*trie = hattrie_create();
		}
		extra->current_trie = *trie;
	}
}

static void grp_add(void *scanner, const char *value)
{
	conf_extra_t *extra = cf_get_extra(scanner);

	if (extra->run == S_FIRST) {
		*hattrie_get(extra->current_trie, value, strlen(value)) = NULL;
	}
}


#line 403 "cf-parse.tab.c" /* yacc.c:339  */

# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* In a future release of Bison, this section will be replaced
   by #include "cf-parse.tab.h".  */
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
#line 352 "cf-parse.y" /* yacc.c:355  */

	struct {
		char *t;
		long i;
		size_t l;
	} tok;

#line 522 "cf-parse.tab.c" /* yacc.c:355  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int cf_parse (void *scanner);

#endif /* !YY_CF_CF_PARSE_TAB_H_INCLUDED  */

/* Copy the second part of user declarations.  */

#line 538 "cf-parse.tab.c" /* yacc.c:358  */

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

#if !defined _Noreturn \
     && (!defined __STDC_VERSION__ || __STDC_VERSION__ < 201112)
# if defined _MSC_VER && 1200 <= _MSC_VER
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn YY_ATTRIBUTE ((__noreturn__))
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif


#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  3
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   349

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  77
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  42
/* YYNRULES -- Number of rules.  */
#define YYNRULES  178
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  369

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   325

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,    76,     2,     2,    75,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,    71,
       2,     2,     2,     2,    72,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    73,     2,    74,     2,     2,     2,     2,
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
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   425,   425,   427,   429,   432,   433,   434,   435,   436,
     437,   438,   441,   442,   443,   444,   445,   446,   450,   454,
     454,   472,   473,   474,   475,   476,   477,   478,   479,   480,
     481,   482,   483,   484,   485,   486,   487,   488,   489,   490,
     491,   492,   493,   494,   495,   496,   497,   508,   511,   518,
     519,   520,   521,   522,   523,   526,   527,   528,   529,   530,
     531,   532,   533,   534,   541,   542,   543,   547,   554,   554,
     590,   593,   595,   596,   600,   604,   605,   609,   610,   611,
     612,   613,   616,   617,   618,   619,   620,   621,   624,   625,
     626,   630,   633,   634,   637,   638,   639,   640,   641,   642,
     643,   644,   650,   654,   655,   656,   657,   658,   659,   660,
     661,   662,   663,   664,   665,   666,   667,   668,   669,   670,
     671,   672,   673,   674,   674,   683,   685,   686,   690,   696,
     697,   698,   699,   700,   701,   702,   703,   704,   705,   706,
     707,   708,   709,   710,   711,   712,   713,   714,   715,   715,
     723,   724,   725,   728,   729,   729,   734,   738,   745,   746,
     747,   751,   751,   756,   760,   764,   765,   765,   773,   774,
     777,   777,   777,   777,   777,   777,   777,   777,   777
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "END", "INVALID_TOKEN", "TEXT", "NUM",
  "INTERVAL", "SIZE", "BOOL", "SYSTEM", "IDENTITY", "HOSTNAME", "SVERSION",
  "NSID", "KEY", "KEYS", "MAX_UDP_PAYLOAD", "TSIG_ALGO_NAME", "WORKERS",
  "BACKGROUND_WORKERS", "ASYNC_START", "USER", "RUNDIR", "PIDFILE",
  "REMOTES", "GROUPS", "ZONES", "FILENAME", "DISABLE_ANY",
  "SEMANTIC_CHECKS", "NOTIFY_RETRIES", "NOTIFY_TIMEOUT", "DBSYNC_TIMEOUT",
  "IXFR_FSLIMIT", "MAX_ZONE_SIZE", "XFR_IN", "XFR_OUT", "UPDATE_IN",
  "NOTIFY_IN", "NOTIFY_OUT", "BUILD_DIFFS", "MAX_CONN_IDLE", "MAX_CONN_HS",
  "MAX_CONN_REPLY", "MAX_TCP_CLIENTS", "RATE_LIMIT", "RATE_LIMIT_SIZE",
  "RATE_LIMIT_SLIP", "TRANSFERS", "STORAGE", "TIMER_DB", "DNSSEC_ENABLE",
  "DNSSEC_KEYDIR", "SIGNATURE_LIFETIME", "SERIAL_POLICY",
  "SERIAL_POLICY_VAL", "QUERY_MODULE", "INTERFACES", "ADDRESS", "PORT",
  "IPA", "IPA6", "VIA", "CONTROL", "ALLOW", "LISTEN_ON", "LOG", "LOG_DEST",
  "LOG_SRC", "LOG_LEVEL", "';'", "'@'", "'{'", "'}'", "'/'", "','",
  "$accept", "config", "conf_entries", "interface_start", "interface",
  "interfaces", "$@1", "system", "keys", "remote_start", "remote",
  "remotes", "$@2", "group_member", "group", "group_start", "groups",
  "zone_acl_start", "zone_acl_item", "zone_acl_list", "query_module",
  "query_module_list", "zone_start", "zone", "$@3", "query_genmodule",
  "query_genmodule_list", "zones", "$@4", "log_prios", "log_src", "$@5",
  "log_dest", "log_file", "log_start", "log", "$@6", "ctl_listen_start",
  "ctl_allow_start", "control", "$@7", "conf", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,    59,    64,   123,   125,    47,    44
};
# endif

#define YYPACT_NINF -67

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-67)))

#define YYTABLE_NINF -83

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -67,     4,    77,   -67,   -67,   -66,   -63,   -42,   -31,   -22,
       6,     9,    12,   -67,    14,   107,     0,    22,     1,     3,
       2,   -44,   -67,   -67,   -67,   -67,   -67,   -67,   -67,   -67,
     -67,   -67,   -67,   -67,   -67,   -67,   -67,   -67,    21,    96,
     108,   101,   102,    98,   127,   134,   141,   169,   174,   181,
     183,   182,   184,   185,   187,   188,   106,   189,   190,   192,
     -67,   172,   -67,   -67,   -67,   -67,   -67,   -67,   -67,   125,
     -67,   -67,   128,   -67,   124,   -67,   -67,   191,   193,   197,
     199,    17,   109,   117,   198,   201,   203,   200,   205,    93,
     155,   140,   -67,   -67,   -67,   -67,   -67,   142,   130,   -67,
     -67,   -67,   -67,    -4,   207,   -67,   -67,   143,   145,   146,
     147,   148,   149,   150,   217,   152,   153,   154,   156,   157,
     158,   159,   160,   161,   162,   163,   164,   165,   166,   167,
     168,   170,   221,   -67,   235,   237,   173,   175,   176,   177,
     178,   179,   180,   186,   194,   195,   196,   202,   204,   206,
     208,   209,   210,   211,   -67,   -67,   238,   236,   243,   247,
     248,   136,   126,   131,   -67,   -67,   -67,   -67,   -67,   246,
     251,   249,   254,   139,   212,   213,   -67,   -67,   214,   -67,
     216,   -25,   -67,   -67,   -67,   -67,   -67,   -67,   -67,   -67,
     218,   -67,   -67,   -67,   -67,   -67,   -67,   -67,   -67,   -67,
     -67,   -67,   -67,   -67,   -67,   -67,   -67,   -67,   219,   -67,
     -67,   -67,    62,   -67,   -67,   -67,   -67,   -67,   -67,   -67,
     -67,   -67,   -67,   -67,   -67,   -67,   -67,   -67,   -67,   -67,
     -67,   -67,   255,   220,   222,   223,   224,   225,   226,   227,
     228,   229,   230,   231,   232,   233,   234,   239,   240,   241,
     242,   -67,    -5,   -67,   -67,   -67,   256,   -67,   215,   244,
     -48,   -67,   -67,   -13,   -67,   235,   257,   245,   250,   -67,
     -67,   -67,   -67,   -67,   -67,   -67,   -67,   -67,   -67,   -67,
     -67,   -67,   -67,   -67,   -67,   -67,   -67,   258,   -67,   -67,
     -67,   -67,   -67,   -58,   -45,   -67,   -67,   -67,    47,   263,
     -67,   259,   111,   264,    36,   -67,   -67,   -67,   255,   -67,
     266,   252,   253,   -67,   -67,   -67,   -29,    -6,   103,   105,
     260,   261,   -55,   -23,   262,   265,   267,   268,   -67,   -67,
     258,   -67,   -67,   -67,   -67,   -67,   270,   -67,   272,   -67,
     -67,   -67,   277,   278,   -67,   286,   300,   -67,   -67,   -67,
     -67,   -67,   -67,   269,   271,   273,   274,   275,   276,   279,
     -67,   -67,   -67,   -67,   -67,   -67,    19,   -67,   -67
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       3,     0,     0,     1,     2,     0,     0,     0,     0,     0,
       0,     0,     0,   170,     5,     0,     0,    49,     0,    94,
       0,     0,     4,    21,    47,    67,    75,   128,    18,   165,
     161,     6,     7,    11,     9,     8,    10,   172,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     171,     0,   173,    50,    54,    52,    51,    53,   174,     0,
      74,   175,     0,   102,     0,    95,    96,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   100,    98,    97,    99,   176,     0,     0,   177,
     164,   163,   178,     0,     0,   158,    19,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    68,    71,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   148,   103,     0,     0,     0,     0,
       0,     0,     0,     0,    77,    78,    81,    79,    80,     0,
       0,     0,     0,     0,     0,     0,   129,    88,     0,   166,
       0,   162,    12,    24,    25,    43,    22,    23,    26,    27,
       0,    28,    31,    32,    33,    46,    29,    30,    34,    35,
      36,    37,    38,    40,    39,    41,    42,    44,     0,    55,
      70,    72,     0,   101,   130,   132,   146,   147,   137,   138,
     134,   133,   136,   135,   131,   139,   140,   141,   142,   144,
     145,   143,   126,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   123,   104,   168,    12,   169,     0,   156,     0,     0,
       0,    45,    48,     0,    76,     0,     0,     0,     0,   105,
     106,   108,   121,   122,   113,   114,   110,   109,   112,   111,
     107,   115,   116,   117,   119,   120,   118,    92,    83,    87,
      85,    84,    86,     0,     0,   157,   153,   153,     0,     0,
      20,     0,     0,     0,     0,    69,    73,   125,   126,   149,
       0,     0,     0,    90,    89,   167,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   127,    91,
      92,   124,   154,   159,   160,    14,     0,    16,     0,    13,
      63,    57,     0,     0,    60,     0,     0,    56,    66,    64,
      65,    93,   150,     0,     0,     0,     0,     0,     0,   155,
      15,    17,    58,    59,    61,    62,     0,   152,   151
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -67,   -67,   -67,   -67,    18,   -67,   -67,   -67,   -67,   -67,
     -67,   -67,   -67,    42,   -67,   -67,   -67,   -67,   -67,   -67,
     -67,   -56,   -67,   -67,   -67,   -67,     7,   -67,   -67,   -67,
      11,   -67,   -67,   -67,   -67,   -67,   -67,   -67,   -67,   -67,
     -67,   -67
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,     2,    38,   260,    14,   182,    15,    16,    69,
     263,    17,   209,   211,   212,    72,    18,   177,   293,   252,
     311,   312,    97,    98,   287,   267,   268,    19,   232,   359,
     316,   352,   258,   259,   181,    20,   105,   103,   104,    21,
     254,    22
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
     288,   178,   301,   256,     3,    61,    70,    23,    73,    74,
      24,   298,   299,   313,   298,   299,   341,   342,   314,    31,
     343,   100,   101,   140,   141,    75,   300,    63,    76,   315,
     102,    25,    77,    78,    79,    80,    81,    82,    83,    32,
     332,   325,    26,   257,    84,   333,   302,   303,   344,   345,
     304,    27,   346,    85,    86,    87,    88,    89,    90,   289,
      91,   305,   290,   332,   291,   292,   -82,    92,   334,   179,
      93,   -82,    94,    95,    62,    71,    99,    96,    33,    28,
       4,    34,    29,    35,    36,    30,    64,     5,    37,    65,
     367,    66,    67,     6,   106,   368,    68,   326,   327,   151,
     152,   107,     7,     8,     9,   108,   110,   112,   318,   319,
     111,   113,   127,   109,   128,   142,   114,   143,    39,    40,
      41,    42,    43,   144,    44,   145,    45,    46,    47,    48,
      49,    50,   240,   115,   241,    10,   264,   242,   265,   243,
     116,    11,   238,   239,    12,   248,   249,   117,    13,    51,
      52,    53,    54,    55,    56,    57,    58,    59,   156,   157,
     158,   159,   160,   161,   162,   163,   164,   165,   166,   167,
     168,   169,   322,   323,   335,   336,   337,   338,   118,   119,
     170,    60,   171,   172,   173,   174,   120,   175,   121,   122,
     132,   123,   124,   125,   126,   129,   130,   131,   133,   135,
     136,   134,   137,   138,   176,   139,   147,   146,   148,   149,
     150,   153,   180,   154,   183,   155,   184,   185,   186,   187,
     188,   189,   190,   191,   192,   193,   208,   194,   195,   196,
     197,   198,   199,   200,   201,   202,   203,   204,   205,   206,
     210,   207,   213,   233,   214,   234,   215,   216,   217,   218,
     219,   220,   235,   236,   237,   244,   245,   221,   246,   247,
     266,   295,   307,   310,   321,   222,   223,   224,   250,   320,
     324,   329,   294,   225,   351,   226,   353,   227,   354,   228,
     229,   230,   231,   355,   356,   253,   251,   255,   296,   261,
     262,   269,   357,   270,   271,   272,   273,   274,   275,   276,
     277,   278,   279,   280,   281,   282,   358,   306,   317,     0,
     283,   284,   285,   286,     0,   328,   308,   297,     0,     0,
       0,     0,     0,   330,   309,     0,     0,   331,     0,     0,
       0,   339,   340,   347,     0,     0,   348,     0,   349,   350,
     360,     0,   361,     0,   362,   363,   364,   365,     0,   366
};

static const yytype_int16 yycheck[] =
{
       5,     5,    15,    28,     0,     5,     5,    73,     5,     6,
      73,    59,    60,    71,    59,    60,    71,    72,    76,     5,
      75,    65,    66,     6,     7,    22,    74,     5,    25,    74,
      74,    73,    29,    30,    31,    32,    33,    34,    35,    25,
      69,     5,    73,    68,    41,    74,    59,    60,    71,    72,
      63,    73,    75,    50,    51,    52,    53,    54,    55,    64,
      57,    74,    67,    69,    69,    70,    71,    64,    74,    73,
      67,    76,    69,    70,    74,    74,    74,    74,    64,    73,
       3,    67,    73,    69,    70,    73,    64,    10,    74,    67,
      71,    69,    70,    16,    73,    76,    74,    61,    62,     6,
       7,     5,    25,    26,    27,     9,     5,     5,    61,    62,
       9,     9,     6,     5,     8,     6,    18,     8,    11,    12,
      13,    14,    15,     6,    17,     8,    19,    20,    21,    22,
      23,    24,     6,     6,     8,    58,    74,     6,    76,     8,
       6,    64,     6,     7,    67,     6,     7,     6,    71,    42,
      43,    44,    45,    46,    47,    48,    49,    50,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,    41,    61,    62,    71,    72,    71,    72,     9,     5,
      50,    74,    52,    53,    54,    55,     5,    57,     5,     7,
      18,     7,     7,     6,     6,     6,     6,     5,    73,    75,
       9,    73,     9,     6,    74,     6,     5,     9,     5,     9,
       5,    56,     5,    73,    71,    73,    71,    71,    71,    71,
      71,    71,     5,    71,    71,    71,     5,    71,    71,    71,
      71,    71,    71,    71,    71,    71,    71,    71,    71,    71,
       5,    71,     5,     5,    71,     9,    71,    71,    71,    71,
      71,    71,     9,     6,     6,     9,     5,    71,     9,     5,
       5,     5,     5,     5,     5,    71,    71,    71,    56,     6,
       6,     5,   254,    71,   330,    71,     6,    71,     6,    71,
      71,    71,    71,     6,     6,    71,    73,    71,    73,    71,
      71,    71,     6,    71,    71,    71,    71,    71,    71,    71,
      71,    71,    71,    71,    71,    71,     6,   265,   297,    -1,
      71,    71,    71,    71,    -1,   308,    71,    73,    -1,    -1,
      -1,    -1,    -1,    71,    74,    -1,    -1,    74,    -1,    -1,
      -1,    71,    71,    71,    -1,    -1,    71,    -1,    71,    71,
      71,    -1,    71,    -1,    71,    71,    71,    71,    -1,    70
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    78,    79,     0,     3,    10,    16,    25,    26,    27,
      58,    64,    67,    71,    82,    84,    85,    88,    93,   104,
     112,   116,   118,    73,    73,    73,    73,    73,    73,    73,
      73,     5,    25,    64,    67,    69,    70,    74,    80,    11,
      12,    13,    14,    15,    17,    19,    20,    21,    22,    23,
      24,    42,    43,    44,    45,    46,    47,    48,    49,    50,
      74,     5,    74,     5,    64,    67,    69,    70,    74,    86,
       5,    74,    92,     5,     6,    22,    25,    29,    30,    31,
      32,    33,    34,    35,    41,    50,    51,    52,    53,    54,
      55,    57,    64,    67,    69,    70,    74,    99,   100,    74,
      65,    66,    74,   114,   115,   113,    73,     5,     9,     5,
       5,     9,     5,     9,    18,     6,     6,     6,     9,     5,
       5,     5,     7,     7,     7,     6,     6,     6,     8,     6,
       6,     5,    18,    73,    73,    75,     9,     9,     6,     6,
       6,     7,     6,     8,     6,     8,     9,     5,     5,     9,
       5,     6,     7,    56,    73,    73,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,    41,
      50,    52,    53,    54,    55,    57,    74,    94,     5,    73,
       5,   111,    83,    71,    71,    71,    71,    71,    71,    71,
       5,    71,    71,    71,    71,    71,    71,    71,    71,    71,
      71,    71,    71,    71,    71,    71,    71,    71,     5,    89,
       5,    90,    91,     5,    71,    71,    71,    71,    71,    71,
      71,    71,    71,    71,    71,    71,    71,    71,    71,    71,
      71,    71,   105,     5,     9,     9,     6,     6,     6,     7,
       6,     8,     6,     8,     9,     5,     9,     5,     6,     7,
      56,    73,    96,    71,   117,    71,    28,    68,   109,   110,
      81,    71,    71,    87,    74,    76,     5,   102,   103,    71,
      71,    71,    71,    71,    71,    71,    71,    71,    71,    71,
      71,    71,    71,    71,    71,    71,    71,   101,     5,    64,
      67,    69,    70,    95,    81,     5,    73,    73,    59,    60,
      74,    15,    59,    60,    63,    74,    90,     5,    71,    74,
       5,    97,    98,    71,    76,    74,   107,   107,    61,    62,
       6,     5,    61,    62,     6,     5,    61,    62,   103,     5,
      71,    74,    69,    74,    74,    71,    72,    71,    72,    71,
      71,    71,    72,    75,    71,    72,    75,    71,    71,    71,
      71,    98,   108,     6,     6,     6,     6,     6,     6,   106,
      71,    71,    71,    71,    71,    71,    70,    71,    76
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    77,    78,    79,    79,    80,    80,    80,    80,    80,
      80,    80,    81,    81,    81,    81,    81,    81,    82,    83,
      82,    84,    84,    84,    84,    84,    84,    84,    84,    84,
      84,    84,    84,    84,    84,    84,    84,    84,    84,    84,
      84,    84,    84,    84,    84,    84,    84,    85,    85,    86,
      86,    86,    86,    86,    86,    87,    87,    87,    87,    87,
      87,    87,    87,    87,    87,    87,    87,    88,    89,    88,
      90,    91,    91,    91,    92,    93,    93,    94,    94,    94,
      94,    94,    95,    95,    95,    95,    95,    95,    96,    96,
      96,    97,    98,    98,    99,    99,    99,    99,    99,    99,
      99,    99,    99,   100,   100,   100,   100,   100,   100,   100,
     100,   100,   100,   100,   100,   100,   100,   100,   100,   100,
     100,   100,   100,   101,   100,   102,   103,   103,   104,   104,
     104,   104,   104,   104,   104,   104,   104,   104,   104,   104,
     104,   104,   104,   104,   104,   104,   104,   104,   105,   104,
     106,   106,   106,   107,   108,   107,   109,   110,   111,   111,
     111,   113,   112,   114,   115,   116,   117,   116,   116,   116,
     118,   118,   118,   118,   118,   118,   118,   118,   118
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     2,     0,     2,     0,     1,     1,     1,     1,
       1,     1,     0,     4,     4,     6,     4,     6,     2,     0,
       6,     2,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     5,     4,     2,     5,     0,
       1,     1,     1,     1,     1,     0,     4,     4,     6,     6,
       4,     6,     6,     4,     4,     4,     4,     2,     0,     6,
       1,     0,     1,     3,     1,     2,     5,     1,     1,     1,
       1,     1,     0,     1,     1,     1,     1,     1,     0,     3,
       3,     2,     0,     3,     0,     1,     1,     1,     1,     1,
       1,     3,     1,     2,     3,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     0,     6,     2,     0,     3,     2,     3,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     0,     6,
       0,     3,     3,     0,     0,     4,     1,     2,     0,     5,
       5,     0,     4,     1,     1,     2,     0,     6,     4,     4,
       1,     2,     2,     2,     2,     2,     2,     2,     2
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY)                                        \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      YYPOPSTACK (yylen);                                       \
      yystate = *yyssp;                                         \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (scanner, YY_("syntax error: cannot back up")); \
      YYERROR;                                                  \
    }                                                           \
while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)

/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value, scanner); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*----------------------------------------.
| Print this symbol's value on YYOUTPUT.  |
`----------------------------------------*/

static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, void *scanner)
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  YYUSE (scanner);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, void *scanner)
{
  YYFPRINTF (yyoutput, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep, scanner);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, int yyrule, void *scanner)
{
  unsigned long int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &(yyvsp[(yyi + 1) - (yynrhs)])
                                              , scanner);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule, scanner); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
yystrlen (const char *yystr)
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            /* Fall through.  */
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, void *scanner)
{
  YYUSE (yyvaluep);
  YYUSE (scanner);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/*----------.
| yyparse.  |
`----------*/

int
yyparse (void *scanner)
{
/* The lookahead symbol.  */
int yychar;


/* The semantic value of the lookahead symbol.  */
/* Default value used for initialization, for pacifying older GCCs
   or non-GCC compilers.  */
YY_INITIAL_VALUE (static YYSTYPE yyval_default;)
YYSTYPE yylval YY_INITIAL_VALUE (= yyval_default);

    /* Number of syntax errors so far.  */
    int yynerrs;

    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        YYSTYPE *yyvs1 = yyvs;
        yytype_int16 *yyss1 = yyss;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * sizeof (*yyssp),
                    &yyvs1, yysize * sizeof (*yyvsp),
                    &yystacksize);

        yyss = yyss1;
        yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yytype_int16 *yyss1 = yyss;
        union yyalloc *yyptr =
          (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
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

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex (&yylval, scanner);
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

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
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:
#line 425 "cf-parse.y" /* yacc.c:1646  */
    { return 0; }
#line 1878 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 6:
#line 433 "cf-parse.y" /* yacc.c:1646  */
    { _str = (yyvsp[0].tok).t; }
#line 1884 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 7:
#line 434 "cf-parse.y" /* yacc.c:1646  */
    { _str = strdup((yyvsp[0].tok).t); }
#line 1890 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 8:
#line 435 "cf-parse.y" /* yacc.c:1646  */
    { _str = strdup((yyvsp[0].tok).t + 1); }
#line 1896 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 9:
#line 436 "cf-parse.y" /* yacc.c:1646  */
    { _str = strdup((yyvsp[0].tok).t); }
#line 1902 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 10:
#line 437 "cf-parse.y" /* yacc.c:1646  */
    { _str = strdup((yyvsp[0].tok).t); }
#line 1908 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 11:
#line 438 "cf-parse.y" /* yacc.c:1646  */
    { _str = strdup((yyvsp[0].tok).t); }
#line 1914 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 13:
#line 442 "cf-parse.y" /* yacc.c:1646  */
    { _port = (yyvsp[-1].tok).i; }
#line 1920 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 14:
#line 443 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-1].tok).t; }
#line 1926 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 15:
#line 444 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-3].tok).t; _port = (yyvsp[-1].tok).i; }
#line 1932 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 16:
#line 445 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-1].tok).t; }
#line 1938 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 17:
#line 446 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-3].tok).t; _port = (yyvsp[-1].tok).i; }
#line 1944 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 18:
#line 450 "cf-parse.y" /* yacc.c:1646  */
    {
   	_str = NULL;
   	f_section(scanner, R_IF, S_SRV);
   }
#line 1953 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 19:
#line 454 "cf-parse.y" /* yacc.c:1646  */
    {
   	_addr = NULL, _port = -1;
   	f_name(scanner, R_IF, C_LISTEN, false);
   }
#line 1962 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 20:
#line 458 "cf-parse.y" /* yacc.c:1646  */
    {
   	if (_addr != NULL && _port == -1) {
   		if_add(scanner, _str, _addr);
   		f_val(scanner, R_IF, false, "%s\n", _addr);
   	} else if (_addr != NULL) {
   		if_add(scanner, _str, _addr);
   		f_val(scanner, R_IF, false, "%s@%i\n", _addr, _port);
   	}
   	free(_str);
   	free(_addr);
   }
#line 1978 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 21:
#line 472 "cf-parse.y" /* yacc.c:1646  */
    { f_section(scanner,  R_SYS, S_SRV); }
#line 1984 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 22:
#line 473 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner,    R_SYS, C_VERSION,             (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 1990 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 23:
#line 474 "cf-parse.y" /* yacc.c:1646  */
    { f_auto_str(scanner, R_SYS, C_VERSION,             (yyvsp[-1].tok).i); }
#line 1996 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 24:
#line 475 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner,    R_SYS, C_IDENT,               (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2002 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 25:
#line 476 "cf-parse.y" /* yacc.c:1646  */
    { f_auto_str(scanner, R_SYS, C_IDENT,               (yyvsp[-1].tok).i); }
#line 2008 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 26:
#line 477 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner,    R_SYS, C_NSID,                (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2014 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 27:
#line 478 "cf-parse.y" /* yacc.c:1646  */
    { f_auto_str(scanner, R_SYS, C_NSID,                (yyvsp[-1].tok).i); }
#line 2020 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 28:
#line 479 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_MAX_UDP_PAYLOAD,     (yyvsp[-1].tok).i); }
#line 2026 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 29:
#line 480 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner,    R_SYS, C_RUNDIR,              (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2032 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 30:
#line 481 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner,    R_SYS, C_PIDFILE,             (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2038 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 31:
#line 482 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_UDP_WORKERS,         (yyvsp[-1].tok).i); }
#line 2044 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 32:
#line 483 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_BG_WORKERS,          (yyvsp[-1].tok).i); }
#line 2050 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 33:
#line 484 "cf-parse.y" /* yacc.c:1646  */
    { f_bool(scanner,     R_SYS, C_ASYNC_START,         (yyvsp[-1].tok).i); }
#line 2056 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 34:
#line 485 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_TCP_IDLE_TIMEOUT,    (yyvsp[-1].tok).i); }
#line 2062 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 35:
#line 486 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_TCP_HSHAKE_TIMEOUT,  (yyvsp[-1].tok).i); }
#line 2068 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 36:
#line 487 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_TCP_REPLY_TIMEOUT,   (yyvsp[-1].tok).i); }
#line 2074 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 37:
#line 488 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_MAX_TCP_CLIENTS,     (yyvsp[-1].tok).i); }
#line 2080 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 38:
#line 489 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_RATE_LIMIT,          (yyvsp[-1].tok).i); }
#line 2086 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 39:
#line 490 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_RATE_LIMIT_TBL_SIZE, (yyvsp[-1].tok).l); }
#line 2092 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 40:
#line 491 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_RATE_LIMIT_TBL_SIZE, (yyvsp[-1].tok).i); }
#line 2098 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 41:
#line 492 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_RATE_LIMIT_SLIP,     (yyvsp[-1].tok).i); }
#line 2104 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 42:
#line 493 "cf-parse.y" /* yacc.c:1646  */
    { /* Not used. */ }
#line 2110 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 43:
#line 494 "cf-parse.y" /* yacc.c:1646  */
    { /* Deprecated */ free((yyvsp[-1].tok).t); }
#line 2116 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 44:
#line 495 "cf-parse.y" /* yacc.c:1646  */
    { /* Deprecated */ free((yyvsp[-1].tok).t); }
#line 2122 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 45:
#line 496 "cf-parse.y" /* yacc.c:1646  */
    { /* Deprecated */ free((yyvsp[-2].tok).t); free((yyvsp[-1].tok).t); }
#line 2128 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 46:
#line 497 "cf-parse.y" /* yacc.c:1646  */
    {
   	char *sep = strchr((yyvsp[-1].tok).t, '.');
   	if (sep != NULL) {
   		*sep = ':';
   	}
   	f_str(scanner, R_SYS, C_USER, (yyvsp[-1].tok).t);
   	free((yyvsp[-1].tok).t);
   }
#line 2141 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 47:
#line 508 "cf-parse.y" /* yacc.c:1646  */
    {
   	f_section(scanner, R_KEY, S_KEY);
   }
#line 2149 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 48:
#line 511 "cf-parse.y" /* yacc.c:1646  */
    {
   	f_id(scanner, R_KEY, C_ID, (yyvsp[-3].tok).t); free((yyvsp[-3].tok).t);
   	f_str(scanner, R_KEY, C_ALG, (yyvsp[-2].tok).t); free((yyvsp[-2].tok).t);
   	f_quote(scanner, R_KEY, C_SECRET, (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t);
   }
#line 2159 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 50:
#line 519 "cf-parse.y" /* yacc.c:1646  */
    { _str = (yyvsp[0].tok).t; }
#line 2165 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 51:
#line 520 "cf-parse.y" /* yacc.c:1646  */
    { _str = strdup((yyvsp[0].tok).t + 1); }
#line 2171 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 52:
#line 521 "cf-parse.y" /* yacc.c:1646  */
    { _str = strdup((yyvsp[0].tok).t); }
#line 2177 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 53:
#line 522 "cf-parse.y" /* yacc.c:1646  */
    { _str = strdup((yyvsp[0].tok).t); }
#line 2183 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 54:
#line 523 "cf-parse.y" /* yacc.c:1646  */
    { _str = strdup((yyvsp[0].tok).t); }
#line 2189 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 56:
#line 527 "cf-parse.y" /* yacc.c:1646  */
    { _port = (yyvsp[-1].tok).i; }
#line 2195 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 57:
#line 528 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-1].tok).t; }
#line 2201 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 58:
#line 529 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-3].tok).t; _port = (yyvsp[-1].tok).i; }
#line 2207 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 59:
#line 530 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-3].tok).t; _mask = (yyvsp[-1].tok).i; }
#line 2213 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 60:
#line 531 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-1].tok).t; }
#line 2219 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 61:
#line 532 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-3].tok).t; _port = (yyvsp[-1].tok).i; }
#line 2225 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 62:
#line 533 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-3].tok).t; _mask = (yyvsp[-1].tok).i; }
#line 2231 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 63:
#line 534 "cf-parse.y" /* yacc.c:1646  */
    {
   	f_str(scanner, R_RMT, C_KEY, (yyvsp[-1].tok).t);
   	if (is_acl(scanner, _str)) {
   		f_str(scanner, R_RMT_ACL, C_KEY, (yyvsp[-1].tok).t);
   	}
   	free((yyvsp[-1].tok).t);
   }
#line 2243 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 64:
#line 541 "cf-parse.y" /* yacc.c:1646  */
    { f_str(scanner, R_RMT, C_VIA, (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2249 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 65:
#line 542 "cf-parse.y" /* yacc.c:1646  */
    { f_str(scanner, R_RMT, C_VIA, (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2255 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 66:
#line 543 "cf-parse.y" /* yacc.c:1646  */
    { f_str(scanner, R_RMT, C_VIA, if_get(scanner, R_RMT, (yyvsp[-1].tok).t)); free((yyvsp[-1].tok).t); }
#line 2261 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 67:
#line 547 "cf-parse.y" /* yacc.c:1646  */
    {
   	_str = NULL;
   	f_section(scanner, R_RMT, S_RMT);
   	if (have_acl(scanner)) {
   		f_section(scanner, R_RMT_ACL, S_ACL);
   	}
   }
#line 2273 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 68:
#line 554 "cf-parse.y" /* yacc.c:1646  */
    {
   	_addr = NULL, _port = -1; _mask = -1;
   	f_id(scanner, R_RMT, C_ID, _str);
   	if (is_acl(scanner, _str)) {
   		f_name(scanner, R_RMT_ACL, C_ID, true);
   		f_val(scanner, R_RMT_ACL, false, "acl_%s\n", _str);
   	}
   }
#line 2286 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 69:
#line 562 "cf-parse.y" /* yacc.c:1646  */
    {
   	if (_addr == NULL) {
   		cf_error(scanner, "remote.address not defined");
   	} else if (_port == -1) {
   		f_name(scanner, R_RMT, C_ADDR, false);
   		f_val(scanner, R_RMT, false, "%s\n", _addr);
   	} else {
   		f_name(scanner, R_RMT, C_ADDR, false);
   		f_val(scanner, R_RMT, false, "%s@%i\n", _addr, _port);
   	}
   	if (is_acl(scanner, _str) && _addr != NULL) {
   		if (_mask == -1) {
   			f_name(scanner, R_RMT_ACL, C_ADDR, false);
   			f_val(scanner, R_RMT_ACL, false, "%s\n", _addr);
   		} else {
   			f_name(scanner, R_RMT_ACL, C_ADDR, false);
   			f_val(scanner, R_RMT_ACL, false, "%s/%i\n", _addr, _mask);
   		}

   		f_name(scanner, R_RMT_ACL, C_ACTION, false);
   		f_val(scanner, R_RMT_ACL, false, "%s\n", acl_actions(scanner, _str));
   	}
   	free(_addr);
   	free(_str);
   }
#line 2316 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 70:
#line 590 "cf-parse.y" /* yacc.c:1646  */
    { grp_add(scanner, (yyvsp[0].tok).t); free((yyvsp[0].tok).t); }
#line 2322 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 74:
#line 600 "cf-parse.y" /* yacc.c:1646  */
    { grp_init(scanner, (yyvsp[0].tok).t); free((yyvsp[0].tok).t); }
#line 2328 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 77:
#line 609 "cf-parse.y" /* yacc.c:1646  */
    { f_name(scanner, R_ZONE, C_MASTER, false); acl_start(scanner, ACL_RMT); _str = ""; }
#line 2334 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 78:
#line 610 "cf-parse.y" /* yacc.c:1646  */
    { f_name(scanner, R_ZONE, C_ACL, false);    acl_start(scanner, ACL_XFR); _str = "acl_"; }
#line 2340 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 79:
#line 611 "cf-parse.y" /* yacc.c:1646  */
    { f_name(scanner, R_ZONE, C_ACL, false);    acl_start(scanner, ACL_NTF); _str = "acl_"; }
#line 2346 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 80:
#line 612 "cf-parse.y" /* yacc.c:1646  */
    { f_name(scanner, R_ZONE, C_NOTIFY, false); acl_start(scanner, ACL_RMT); _str = ""; }
#line 2352 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 81:
#line 613 "cf-parse.y" /* yacc.c:1646  */
    { f_name(scanner, R_ZONE, C_ACL, false);    acl_start(scanner, ACL_UPD); _str = "acl_"; }
#line 2358 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 83:
#line 617 "cf-parse.y" /* yacc.c:1646  */
    { acl_next(scanner, (yyvsp[0].tok).t); free((yyvsp[0].tok).t); }
#line 2364 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 84:
#line 618 "cf-parse.y" /* yacc.c:1646  */
    { acl_next(scanner, (yyvsp[0].tok).t + 1); }
#line 2370 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 85:
#line 619 "cf-parse.y" /* yacc.c:1646  */
    { acl_next(scanner, (yyvsp[0].tok).t); }
#line 2376 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 86:
#line 620 "cf-parse.y" /* yacc.c:1646  */
    { acl_next(scanner, (yyvsp[0].tok).t); }
#line 2382 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 87:
#line 621 "cf-parse.y" /* yacc.c:1646  */
    { acl_next(scanner, (yyvsp[0].tok).t); }
#line 2388 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 90:
#line 626 "cf-parse.y" /* yacc.c:1646  */
    { acl_end(scanner); }
#line 2394 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 95:
#line 638 "cf-parse.y" /* yacc.c:1646  */
    { f_id(scanner, R_ZONE, C_DOMAIN, (yyvsp[0].tok).t); free((yyvsp[0].tok).t); }
#line 2400 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 96:
#line 639 "cf-parse.y" /* yacc.c:1646  */
    { f_id(scanner, R_ZONE, C_DOMAIN, (yyvsp[0].tok).t); }
#line 2406 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 97:
#line 640 "cf-parse.y" /* yacc.c:1646  */
    { f_id(scanner, R_ZONE, C_DOMAIN, (yyvsp[0].tok).t + 1); }
#line 2412 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 98:
#line 641 "cf-parse.y" /* yacc.c:1646  */
    { f_id(scanner, R_ZONE, C_DOMAIN, (yyvsp[0].tok).t); }
#line 2418 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 99:
#line 642 "cf-parse.y" /* yacc.c:1646  */
    { f_id(scanner, R_ZONE, C_DOMAIN, (yyvsp[0].tok).t); }
#line 2424 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 100:
#line 643 "cf-parse.y" /* yacc.c:1646  */
    { f_id(scanner, R_ZONE, C_DOMAIN, (yyvsp[0].tok).t); }
#line 2430 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 101:
#line 644 "cf-parse.y" /* yacc.c:1646  */
    {
   	f_name(scanner, R_ZONE, C_DOMAIN, true);
   	f_val(scanner, R_ZONE, false, "%i/%s", (yyvsp[-2].tok).i, (yyvsp[0].tok).t);
   	f_val(scanner, R_ZONE, false, "\n");
   	free((yyvsp[0].tok).t);
   }
#line 2441 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 102:
#line 650 "cf-parse.y" /* yacc.c:1646  */
    { f_id(scanner, R_ZONE, C_DOMAIN, (yyvsp[0].tok).t); free((yyvsp[0].tok).t); }
#line 2447 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 105:
#line 656 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner, R_ZONE, C_FILE,             (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2453 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 106:
#line 657 "cf-parse.y" /* yacc.c:1646  */
    { f_bool(scanner,  R_ZONE, C_DISABLE_ANY,      (yyvsp[-1].tok).i); }
#line 2459 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 107:
#line 658 "cf-parse.y" /* yacc.c:1646  */
    { f_bool(scanner,  R_ZONE, C_IXFR_DIFF,        (yyvsp[-1].tok).i); }
#line 2465 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 108:
#line 659 "cf-parse.y" /* yacc.c:1646  */
    { f_bool(scanner,  R_ZONE, C_SEM_CHECKS,       (yyvsp[-1].tok).i); }
#line 2471 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 109:
#line 660 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE, C_MAX_JOURNAL_SIZE, (yyvsp[-1].tok).l); }
#line 2477 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 110:
#line 661 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE, C_MAX_JOURNAL_SIZE, (yyvsp[-1].tok).i); }
#line 2483 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 111:
#line 662 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE, C_MAX_ZONE_SIZE,    (yyvsp[-1].tok).l); }
#line 2489 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 112:
#line 663 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE, C_MAX_ZONE_SIZE,    (yyvsp[-1].tok).i); }
#line 2495 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 113:
#line 664 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE, C_ZONEFILE_SYNC,    (yyvsp[-1].tok).i); }
#line 2501 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 114:
#line 665 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE, C_ZONEFILE_SYNC,    (yyvsp[-1].tok).i); }
#line 2507 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 115:
#line 666 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner, R_ZONE, C_STORAGE,          (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2513 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 116:
#line 667 "cf-parse.y" /* yacc.c:1646  */
    { f_bool(scanner,  R_ZONE, C_DNSSEC_SIGNING,   (yyvsp[-1].tok).i); }
#line 2519 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 117:
#line 668 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner, R_ZONE, C_KASP_DB,          (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2525 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 118:
#line 669 "cf-parse.y" /* yacc.c:1646  */
    { f_str(scanner,   R_ZONE, C_SERIAL_POLICY,    (yyvsp[-1].tok).t); }
#line 2531 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 119:
#line 670 "cf-parse.y" /* yacc.c:1646  */
    { /* Not used. */ }
#line 2537 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 120:
#line 671 "cf-parse.y" /* yacc.c:1646  */
    { /* Not used. */ }
#line 2543 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 121:
#line 672 "cf-parse.y" /* yacc.c:1646  */
    { /* Not used. */ }
#line 2549 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 122:
#line 673 "cf-parse.y" /* yacc.c:1646  */
    { /* Not used. */ }
#line 2555 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 123:
#line 674 "cf-parse.y" /* yacc.c:1646  */
    {
   	if (cf_get_extra(scanner)->run == S_FIRST) {
   		cf_warning(scanner, "query module is not supported by knot1to2");
   	}
   }
#line 2565 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 128:
#line 690 "cf-parse.y" /* yacc.c:1646  */
    {
   	f_section(scanner, R_ZONE, S_ZONE); _acl_run = R_ZONE;
   	if (f_section(scanner, R_ZONE_TPL, S_TPL)) {
   		f_id(scanner, R_ZONE_TPL, C_ID, "default");
   	}
   }
#line 2576 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 130:
#line 697 "cf-parse.y" /* yacc.c:1646  */
    { f_bool(scanner,  R_ZONE_TPL, C_DISABLE_ANY,      (yyvsp[-1].tok).i); }
#line 2582 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 131:
#line 698 "cf-parse.y" /* yacc.c:1646  */
    { f_bool(scanner,  R_ZONE_TPL, C_IXFR_DIFF,        (yyvsp[-1].tok).i); }
#line 2588 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 132:
#line 699 "cf-parse.y" /* yacc.c:1646  */
    { f_bool(scanner,  R_ZONE_TPL, C_SEM_CHECKS,       (yyvsp[-1].tok).i); }
#line 2594 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 133:
#line 700 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE_TPL, C_MAX_JOURNAL_SIZE, (yyvsp[-1].tok).l); }
#line 2600 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 134:
#line 701 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE_TPL, C_MAX_JOURNAL_SIZE, (yyvsp[-1].tok).i); }
#line 2606 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 135:
#line 702 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE_TPL, C_MAX_ZONE_SIZE,    (yyvsp[-1].tok).l); }
#line 2612 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 136:
#line 703 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE_TPL, C_MAX_ZONE_SIZE,    (yyvsp[-1].tok).i); }
#line 2618 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 137:
#line 704 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE_TPL, C_ZONEFILE_SYNC,    (yyvsp[-1].tok).i); }
#line 2624 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 138:
#line 705 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE_TPL, C_ZONEFILE_SYNC,    (yyvsp[-1].tok).i); }
#line 2630 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 139:
#line 706 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner, R_ZONE_TPL, C_STORAGE,          (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2636 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 140:
#line 707 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner, R_ZONE_TPL, C_TIMER_DB,         (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2642 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 141:
#line 708 "cf-parse.y" /* yacc.c:1646  */
    { f_bool(scanner,  R_ZONE_TPL, C_DNSSEC_SIGNING,   (yyvsp[-1].tok).i); }
#line 2648 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 142:
#line 709 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner, R_ZONE_TPL, C_KASP_DB,          (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2654 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 143:
#line 710 "cf-parse.y" /* yacc.c:1646  */
    { f_str(scanner,   R_ZONE_TPL, C_SERIAL_POLICY,    (yyvsp[-1].tok).t); }
#line 2660 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 144:
#line 711 "cf-parse.y" /* yacc.c:1646  */
    { /* Not used. */ }
#line 2666 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 145:
#line 712 "cf-parse.y" /* yacc.c:1646  */
    { /* Not used. */ }
#line 2672 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 146:
#line 713 "cf-parse.y" /* yacc.c:1646  */
    { /* Not used. */ }
#line 2678 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 147:
#line 714 "cf-parse.y" /* yacc.c:1646  */
    { /* Not used. */ }
#line 2684 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 148:
#line 715 "cf-parse.y" /* yacc.c:1646  */
    {
   	if (cf_get_extra(scanner)->run == S_FIRST) {
   		cf_warning(scanner, "query module is not supported by knot1to2");
   	}
   }
#line 2694 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 151:
#line 724 "cf-parse.y" /* yacc.c:1646  */
    { if (_str == NULL) _str = (yyvsp[-1].tok).t; }
#line 2700 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 152:
#line 725 "cf-parse.y" /* yacc.c:1646  */
    { if (_str == NULL) _str = (yyvsp[-1].tok).t; }
#line 2706 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 154:
#line 729 "cf-parse.y" /* yacc.c:1646  */
    { f_name(scanner, R_LOG, (yyvsp[0].tok).t, false); _str = NULL; }
#line 2712 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 155:
#line 730 "cf-parse.y" /* yacc.c:1646  */
    { f_val(scanner, R_LOG, false, "%s\n", _str); }
#line 2718 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 156:
#line 734 "cf-parse.y" /* yacc.c:1646  */
    { f_id(scanner, R_LOG, C_TARGET, (yyvsp[0].tok).t); }
#line 2724 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 157:
#line 738 "cf-parse.y" /* yacc.c:1646  */
    {
   	f_name(scanner, R_LOG, C_TARGET, true);
   	f_val(scanner, R_LOG, true, "%s", (yyvsp[0].tok).t); free((yyvsp[0].tok).t);
   	f_val(scanner, R_LOG, false, "\n");
   }
#line 2734 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 161:
#line 751 "cf-parse.y" /* yacc.c:1646  */
    { f_section(scanner, R_LOG, S_LOG); }
#line 2740 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 165:
#line 764 "cf-parse.y" /* yacc.c:1646  */
    { f_section(scanner, R_CTL, S_CTL); _acl_run = R_CTL; }
#line 2746 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 166:
#line 765 "cf-parse.y" /* yacc.c:1646  */
    { f_name(scanner, R_CTL, C_LISTEN, false); _addr = NULL, _port = -1; }
#line 2752 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 167:
#line 766 "cf-parse.y" /* yacc.c:1646  */
    {
   	f_val(scanner, R_CTL, true, "knot.sock");
   	if (cf_get_extra(scanner)->run == S_CTL) {
   		cf_warning(scanner, "remote control over INET socket is no longer supported");
   	}
   	free(_addr);
   }
#line 2764 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 168:
#line 773 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner, R_CTL, C_LISTEN, (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2770 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 169:
#line 774 "cf-parse.y" /* yacc.c:1646  */
    { free((yyvsp[-1].tok).t); }
#line 2776 "cf-parse.tab.c" /* yacc.c:1646  */
    break;


#line 2780 "cf-parse.tab.c" /* yacc.c:1646  */
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (scanner, YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (scanner, yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval, scanner);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
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


      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp, scanner);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

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

#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (scanner, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, scanner);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[*yyssp], yyvsp, scanner);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
#line 779 "cf-parse.y" /* yacc.c:1906  */

