/* A Bison parser, made by GNU Bison 3.0.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2013 Free Software Foundation, Inc.

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
#define YYBISON_VERSION "3.0.2"

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


#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "utils/knot1to2/scheme.h"
#include "utils/knot1to2/extra.h"
#include "utils/knot1to2/cf-parse.tab.h"
#include "libknot/internal/strlcat.h"
#include "libknot/internal/strlcpy.h"

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
	ACL_CTL
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
		case ACL_CTL: extra->current_trie = extra->share->acl_control; break;
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
	       hattrie_tryget(extra->share->acl_update, str, strlen(str))  != NULL ||
	       hattrie_tryget(extra->share->acl_control, str, strlen(str)) != NULL;
}

static bool have_acl(void *scanner) {
	conf_extra_t *extra = cf_get_extra(scanner);

	return (hattrie_weight(extra->share->acl_xfer) +
	        hattrie_weight(extra->share->acl_notify) +
	        hattrie_weight(extra->share->acl_update) +
	        hattrie_weight(extra->share->acl_control)) > 0;
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
	if (hattrie_tryget(extra->share->acl_control, str, strlen(str)) != NULL) {
		strlcat(actions, _first ? "" : ", ", sizeof(actions)); _first = false;
		strlcat(actions, "control", sizeof(actions));
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


#line 412 "cf-parse.tab.c" /* yacc.c:339  */

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
    XFR_IN = 290,
    XFR_OUT = 291,
    UPDATE_IN = 292,
    NOTIFY_IN = 293,
    NOTIFY_OUT = 294,
    BUILD_DIFFS = 295,
    MAX_CONN_IDLE = 296,
    MAX_CONN_HS = 297,
    MAX_CONN_REPLY = 298,
    MAX_TCP_CLIENTS = 299,
    RATE_LIMIT = 300,
    RATE_LIMIT_SIZE = 301,
    RATE_LIMIT_SLIP = 302,
    TRANSFERS = 303,
    STORAGE = 304,
    TIMER_DB = 305,
    DNSSEC_ENABLE = 306,
    DNSSEC_KEYDIR = 307,
    SIGNATURE_LIFETIME = 308,
    SERIAL_POLICY = 309,
    SERIAL_POLICY_VAL = 310,
    QUERY_MODULE = 311,
    INTERFACES = 312,
    ADDRESS = 313,
    PORT = 314,
    IPA = 315,
    IPA6 = 316,
    VIA = 317,
    CONTROL = 318,
    ALLOW = 319,
    LISTEN_ON = 320,
    LOG = 321,
    LOG_DEST = 322,
    LOG_SRC = 323,
    LOG_LEVEL = 324
  };
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE YYSTYPE;
union YYSTYPE
{
#line 361 "cf-parse.y" /* yacc.c:355  */

	struct {
		char *t;
		long i;
		size_t l;
	} tok;

#line 530 "cf-parse.tab.c" /* yacc.c:355  */
};
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int cf_parse (void *scanner);

#endif /* !YY_CF_CF_PARSE_TAB_H_INCLUDED  */

/* Copy the second part of user declarations.  */

#line 544 "cf-parse.tab.c" /* yacc.c:358  */

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
#define YYLAST   341

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  76
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  42
/* YYNRULES -- Number of rules.  */
#define YYNRULES  174
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  358

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   324

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
       2,     2,     2,     2,    75,     2,     2,    74,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,    70,
       2,     2,     2,     2,    71,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    72,     2,    73,     2,     2,     2,     2,
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
      65,    66,    67,    68,    69
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   433,   433,   435,   437,   440,   441,   442,   443,   444,
     445,   446,   449,   450,   451,   452,   453,   454,   458,   462,
     462,   480,   481,   482,   483,   484,   485,   486,   487,   488,
     489,   490,   491,   492,   493,   494,   495,   496,   497,   498,
     499,   500,   501,   502,   503,   504,   505,   516,   519,   526,
     527,   528,   529,   530,   531,   534,   535,   536,   537,   538,
     539,   540,   541,   542,   549,   550,   551,   555,   562,   562,
     598,   601,   603,   604,   608,   612,   613,   617,   618,   619,
     620,   621,   624,   625,   626,   627,   628,   629,   632,   633,
     634,   638,   641,   642,   645,   646,   647,   648,   649,   650,
     651,   652,   658,   662,   663,   664,   665,   666,   667,   668,
     669,   670,   671,   672,   673,   674,   675,   676,   677,   678,
     679,   680,   680,   689,   691,   692,   696,   702,   703,   704,
     705,   706,   707,   708,   709,   710,   711,   712,   713,   714,
     715,   716,   717,   718,   719,   719,   727,   728,   729,   732,
     733,   733,   738,   742,   749,   750,   751,   755,   755,   760,
     764,   768,   769,   769,   780,   781,   784,   784,   784,   784,
     784,   784,   784,   784,   784
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
  "IXFR_FSLIMIT", "XFR_IN", "XFR_OUT", "UPDATE_IN", "NOTIFY_IN",
  "NOTIFY_OUT", "BUILD_DIFFS", "MAX_CONN_IDLE", "MAX_CONN_HS",
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
      59,    64,   123,   125,    47,    44
};
# endif

#define YYPACT_NINF -66

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-66)))

#define YYTABLE_NINF -83

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -66,     4,    76,   -66,   -66,   -65,   -62,   -41,   -24,   -22,
       6,     9,    40,   -66,    14,   106,     0,    22,     1,     3,
       2,   -43,   -66,   -66,   -66,   -66,   -66,   -66,   -66,   -66,
     -66,   -66,   -66,   -66,   -66,   -66,   -66,   -66,    43,    42,
     133,    91,   100,   127,   150,   164,   165,   163,   168,   169,
     170,   177,   179,   180,   171,   182,   102,   183,   184,   186,
     -66,   158,   -66,   -66,   -66,   -66,   -66,   -66,   -66,   120,
     -66,   -66,   121,   -66,   122,   -66,   -66,   185,   188,   189,
     192,    17,   105,   190,   195,   196,   194,   199,   125,   151,
     135,   -66,   -66,   -66,   -66,   -66,   136,   129,   -66,   -66,
     -66,   -66,    -4,   -66,   -66,   -66,   139,   140,   141,   142,
     143,   144,   145,   200,   146,   147,   148,   149,   152,   153,
     154,   155,   156,   157,   159,   160,   161,   162,   166,   167,
     172,   215,   -66,   216,   223,   173,   174,   175,   176,   178,
     181,   187,   191,   193,   197,   198,   201,   202,   203,   204,
     205,   -66,   -66,   228,   225,   226,   232,   233,   128,   108,
     -66,   -66,   -66,   -66,   -66,   231,   236,   238,   244,   130,
     207,   206,   -66,   -66,   209,   -66,    -5,   -25,   -66,   -66,
     -66,   -66,   -66,   -66,   -66,   -66,   210,   -66,   -66,   -66,
     -66,   -66,   -66,   -66,   -66,   -66,   -66,   -66,   -66,   -66,
     -66,   -66,   -66,   -66,   211,   -66,   -66,   -66,    49,   -66,
     -66,   -66,   -66,   -66,   -66,   -66,   -66,   -66,   -66,   -66,
     -66,   -66,   -66,   -66,   -66,   -66,   245,   212,   213,   214,
     217,   218,   219,   220,   221,   222,   224,   227,   229,   230,
     234,   235,   237,   -66,    -5,   -66,   -66,   -66,   -66,   -66,
     -66,   -66,   -57,   247,   -66,   239,   240,   -47,   -66,   -66,
     -13,   -66,   216,   248,   243,   241,   -66,   -66,   -66,   -66,
     -66,   -66,   -66,   -66,   -66,   -66,   -66,   -66,   -66,   -66,
     -66,   -66,   249,   -44,   -66,   -66,   -66,   -66,   -66,    37,
     250,   -66,   253,    46,   254,    33,   -66,   -66,   -66,   245,
     -66,   259,   246,   242,   -66,    -6,    16,    70,    73,   251,
     252,   -54,   -30,   255,   256,   257,   258,   -66,   -66,   249,
     -66,   -66,   -66,   -66,   -66,   260,   -66,   263,   -66,   -66,
     -66,   264,   270,   -66,   271,   279,   -66,   -66,   -66,   -66,
     -66,   -66,   261,   262,   265,   266,   267,   268,   272,   -66,
     -66,   -66,   -66,   -66,   -66,    29,   -66,   -66
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       3,     0,     0,     1,     2,     0,     0,     0,     0,     0,
       0,     0,     0,   166,     5,     0,     0,    49,     0,    94,
       0,     0,     4,    21,    47,    67,    75,   126,    18,   161,
     157,     6,     7,    11,     9,     8,    10,   168,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     167,     0,   169,    50,    54,    52,    51,    53,   170,     0,
      74,   171,     0,   102,     0,    95,    96,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   100,    98,    97,    99,   172,     0,     0,   173,   160,
     159,   174,     0,    88,   154,    19,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    68,    71,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   144,   103,     0,     0,     0,     0,     0,     0,     0,
      77,    78,    81,    79,    80,     0,     0,     0,     0,     0,
       0,     0,   127,    88,     0,   162,   165,   158,    12,    24,
      25,    43,    22,    23,    26,    27,     0,    28,    31,    32,
      33,    46,    29,    30,    34,    35,    36,    37,    38,    40,
      39,    41,    42,    44,     0,    55,    70,    72,     0,   101,
     128,   130,   142,   143,   133,   134,   132,   131,   129,   135,
     136,   137,   138,   140,   141,   139,   124,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   121,   104,   164,    12,    83,    87,    85,
      84,    86,     0,     0,   152,     0,     0,     0,    45,    48,
       0,    76,     0,     0,     0,     0,   105,   106,   108,   119,
     120,   111,   112,   110,   109,   107,   113,   114,   115,   117,
     118,   116,    92,     0,    90,    89,   153,   149,   149,     0,
       0,    20,     0,     0,     0,     0,    69,    73,   123,   124,
     145,     0,     0,     0,   163,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   125,    91,    92,
     122,   150,   155,   156,    14,     0,    16,     0,    13,    63,
      57,     0,     0,    60,     0,     0,    56,    66,    64,    65,
      93,   146,     0,     0,     0,     0,     0,     0,   151,    15,
      17,    58,    59,    61,    62,     0,   148,   147
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -66,   -66,   -66,   -66,    13,   -66,   -66,   -66,   -66,   -66,
     -66,   -66,   -66,    -7,   -66,   -66,   -66,   -66,   -66,    92,
     -66,   -33,   -66,   -66,   -66,   -66,    -3,   -66,   -66,   -66,
       5,   -66,   -66,   -66,   -66,   -66,   -66,   -66,   -66,   -66,
     -66,   -66
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,     2,    38,   257,    14,   178,    15,    16,    69,
     260,    17,   205,   207,   208,    72,    18,   173,   252,   176,
     302,   303,    96,    97,   282,   264,   265,    19,   226,   348,
     305,   341,   255,   256,   177,    20,   104,   102,   103,    21,
     246,    22
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
     247,   174,   292,   253,     3,    61,    70,    23,    73,    74,
      24,   289,   290,   284,   289,   290,   330,   331,   285,    31,
     332,    99,   100,   139,   140,    75,   291,    63,    76,   304,
     101,    25,    77,    78,    79,    80,    81,    82,   314,    32,
     333,   334,   254,    83,   335,   293,   294,   106,    26,   295,
      27,   107,    84,    85,    86,    87,    88,    89,   248,    90,
     296,   249,   321,   250,   251,   -82,    91,   322,   175,    92,
     -82,    93,    94,    62,    71,    98,    95,    33,    28,     4,
      34,    29,    35,    36,   321,    64,     5,    37,    65,   323,
      66,    67,     6,   315,   316,    68,   109,   307,   308,   356,
     110,     7,     8,     9,   357,   111,   311,   312,   126,   112,
     127,   141,    30,   142,   234,   105,   235,    39,    40,    41,
      42,    43,   261,    44,   262,    45,    46,    47,    48,    49,
      50,   148,   149,    10,   232,   233,   240,   241,   108,    11,
     324,   325,    12,   326,   327,   113,    13,    51,    52,    53,
      54,    55,    56,    57,    58,    59,   114,   153,   154,   155,
     156,   157,   158,   159,   160,   161,   162,   163,   164,   165,
     115,   116,   117,   118,   119,   120,   131,   124,   166,    60,
     167,   168,   169,   170,   121,   171,   122,   123,   125,   128,
     129,   130,   132,   133,   135,   137,   134,   136,   138,   143,
     144,   145,   172,   146,   147,   186,   150,   151,   152,   179,
     180,   181,   182,   183,   184,   185,   187,   188,   189,   190,
     204,   206,   191,   192,   193,   194,   195,   196,   209,   197,
     198,   199,   200,   227,   228,   229,   201,   202,   230,   231,
     236,   237,   203,   210,   211,   212,   213,   238,   214,   239,
     263,   215,   286,   298,   301,   297,   309,   216,   310,   283,
     313,   217,   242,   218,   318,   244,   342,   219,   220,   343,
     344,   221,   222,   223,   224,   225,   345,   346,   243,   245,
     258,   259,   266,   267,   268,   347,   340,   269,   270,   271,
     272,   273,   274,   306,   275,     0,   317,   276,     0,   277,
     278,     0,     0,     0,   279,   280,     0,   281,     0,     0,
       0,   287,   288,   299,   300,   320,   319,     0,     0,     0,
       0,   328,   329,     0,     0,   336,   337,   338,   339,     0,
       0,   349,   350,     0,     0,   351,   352,   353,   354,     0,
       0,   355
};

static const yytype_int16 yycheck[] =
{
       5,     5,    15,    28,     0,     5,     5,    72,     5,     6,
      72,    58,    59,    70,    58,    59,    70,    71,    75,     5,
      74,    64,    65,     6,     7,    22,    73,     5,    25,    73,
      73,    72,    29,    30,    31,    32,    33,    34,     5,    25,
      70,    71,    67,    40,    74,    58,    59,     5,    72,    62,
      72,     9,    49,    50,    51,    52,    53,    54,    63,    56,
      73,    66,    68,    68,    69,    70,    63,    73,    72,    66,
      75,    68,    69,    73,    73,    73,    73,    63,    72,     3,
      66,    72,    68,    69,    68,    63,    10,    73,    66,    73,
      68,    69,    16,    60,    61,    73,     5,    60,    61,    70,
       9,    25,    26,    27,    75,     5,    60,    61,     6,     9,
       8,     6,    72,     8,     6,    72,     8,    11,    12,    13,
      14,    15,    73,    17,    75,    19,    20,    21,    22,    23,
      24,     6,     7,    57,     6,     7,     6,     7,     5,    63,
      70,    71,    66,    70,    71,    18,    70,    41,    42,    43,
      44,    45,    46,    47,    48,    49,     6,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    40,
       6,     6,     9,     5,     5,     5,    18,     6,    49,    73,
      51,    52,    53,    54,     7,    56,     7,     7,     6,     6,
       6,     5,    72,    72,     9,     6,    74,     9,     6,     9,
       5,     5,    73,     9,     5,     5,    55,    72,    72,    70,
      70,    70,    70,    70,    70,    70,    70,    70,    70,    70,
       5,     5,    70,    70,    70,    70,    70,    70,     5,    70,
      70,    70,    70,     5,     9,     9,    70,    70,     6,     6,
       9,     5,    70,    70,    70,    70,    70,     9,    70,     5,
       5,    70,     5,     5,     5,   262,     6,    70,     5,   246,
       6,    70,    55,    70,     5,   173,     6,    70,    70,     6,
       6,    70,    70,    70,    70,    70,     6,     6,    72,    70,
      70,    70,    70,    70,    70,     6,   319,    70,    70,    70,
      70,    70,    70,   288,    70,    -1,   299,    70,    -1,    70,
      70,    -1,    -1,    -1,    70,    70,    -1,    70,    -1,    -1,
      -1,    72,    72,    70,    73,    73,    70,    -1,    -1,    -1,
      -1,    70,    70,    -1,    -1,    70,    70,    70,    70,    -1,
      -1,    70,    70,    -1,    -1,    70,    70,    70,    70,    -1,
      -1,    69
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    77,    78,     0,     3,    10,    16,    25,    26,    27,
      57,    63,    66,    70,    81,    83,    84,    87,    92,   103,
     111,   115,   117,    72,    72,    72,    72,    72,    72,    72,
      72,     5,    25,    63,    66,    68,    69,    73,    79,    11,
      12,    13,    14,    15,    17,    19,    20,    21,    22,    23,
      24,    41,    42,    43,    44,    45,    46,    47,    48,    49,
      73,     5,    73,     5,    63,    66,    68,    69,    73,    85,
       5,    73,    91,     5,     6,    22,    25,    29,    30,    31,
      32,    33,    34,    40,    49,    50,    51,    52,    53,    54,
      56,    63,    66,    68,    69,    73,    98,    99,    73,    64,
      65,    73,   113,   114,   112,    72,     5,     9,     5,     5,
       9,     5,     9,    18,     6,     6,     6,     9,     5,     5,
       5,     7,     7,     7,     6,     6,     6,     8,     6,     6,
       5,    18,    72,    72,    74,     9,     9,     6,     6,     6,
       7,     6,     8,     9,     5,     5,     9,     5,     6,     7,
      55,    72,    72,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    49,    51,    52,    53,
      54,    56,    73,    93,     5,    72,    95,   110,    82,    70,
      70,    70,    70,    70,    70,    70,     5,    70,    70,    70,
      70,    70,    70,    70,    70,    70,    70,    70,    70,    70,
      70,    70,    70,    70,     5,    88,     5,    89,    90,     5,
      70,    70,    70,    70,    70,    70,    70,    70,    70,    70,
      70,    70,    70,    70,    70,    70,   104,     5,     9,     9,
       6,     6,     6,     7,     6,     8,     9,     5,     9,     5,
       6,     7,    55,    72,    95,    70,   116,     5,    63,    66,
      68,    69,    94,    28,    67,   108,   109,    80,    70,    70,
      86,    73,    75,     5,   101,   102,    70,    70,    70,    70,
      70,    70,    70,    70,    70,    70,    70,    70,    70,    70,
      70,    70,   100,    80,    70,    75,     5,    72,    72,    58,
      59,    73,    15,    58,    59,    62,    73,    89,     5,    70,
      73,     5,    96,    97,    73,   106,   106,    60,    61,     6,
       5,    60,    61,     6,     5,    60,    61,   102,     5,    70,
      73,    68,    73,    73,    70,    71,    70,    71,    70,    70,
      70,    71,    74,    70,    71,    74,    70,    70,    70,    70,
      97,   107,     6,     6,     6,     6,     6,     6,   105,    70,
      70,    70,    70,    70,    70,    69,    70,    75
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    76,    77,    78,    78,    79,    79,    79,    79,    79,
      79,    79,    80,    80,    80,    80,    80,    80,    81,    82,
      81,    83,    83,    83,    83,    83,    83,    83,    83,    83,
      83,    83,    83,    83,    83,    83,    83,    83,    83,    83,
      83,    83,    83,    83,    83,    83,    83,    84,    84,    85,
      85,    85,    85,    85,    85,    86,    86,    86,    86,    86,
      86,    86,    86,    86,    86,    86,    86,    87,    88,    87,
      89,    90,    90,    90,    91,    92,    92,    93,    93,    93,
      93,    93,    94,    94,    94,    94,    94,    94,    95,    95,
      95,    96,    97,    97,    98,    98,    98,    98,    98,    98,
      98,    98,    98,    99,    99,    99,    99,    99,    99,    99,
      99,    99,    99,    99,    99,    99,    99,    99,    99,    99,
      99,   100,    99,   101,   102,   102,   103,   103,   103,   103,
     103,   103,   103,   103,   103,   103,   103,   103,   103,   103,
     103,   103,   103,   103,   104,   103,   105,   105,   105,   106,
     107,   106,   108,   109,   110,   110,   110,   112,   111,   113,
     114,   115,   116,   115,   115,   115,   117,   117,   117,   117,
     117,   117,   117,   117,   117
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
       4,     0,     6,     2,     0,     3,     2,     3,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     0,     6,     0,     3,     3,     0,
       0,     4,     1,     2,     0,     5,     5,     0,     4,     1,
       1,     2,     0,     6,     4,     3,     1,     2,     2,     2,
       2,     2,     2,     2,     2
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
#line 433 "cf-parse.y" /* yacc.c:1646  */
    { return 0; }
#line 1881 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 6:
#line 441 "cf-parse.y" /* yacc.c:1646  */
    { _str = (yyvsp[0].tok).t; }
#line 1887 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 7:
#line 442 "cf-parse.y" /* yacc.c:1646  */
    { _str = strdup((yyvsp[0].tok).t); }
#line 1893 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 8:
#line 443 "cf-parse.y" /* yacc.c:1646  */
    { _str = strdup((yyvsp[0].tok).t + 1); }
#line 1899 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 9:
#line 444 "cf-parse.y" /* yacc.c:1646  */
    { _str = strdup((yyvsp[0].tok).t); }
#line 1905 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 10:
#line 445 "cf-parse.y" /* yacc.c:1646  */
    { _str = strdup((yyvsp[0].tok).t); }
#line 1911 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 11:
#line 446 "cf-parse.y" /* yacc.c:1646  */
    { _str = strdup((yyvsp[0].tok).t); }
#line 1917 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 13:
#line 450 "cf-parse.y" /* yacc.c:1646  */
    { _port = (yyvsp[-1].tok).i; }
#line 1923 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 14:
#line 451 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-1].tok).t; }
#line 1929 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 15:
#line 452 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-3].tok).t; _port = (yyvsp[-1].tok).i; }
#line 1935 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 16:
#line 453 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-1].tok).t; }
#line 1941 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 17:
#line 454 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-3].tok).t; _port = (yyvsp[-1].tok).i; }
#line 1947 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 18:
#line 458 "cf-parse.y" /* yacc.c:1646  */
    {
   	_str = NULL;
   	f_section(scanner, R_IF, S_SRV);
   }
#line 1956 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 19:
#line 462 "cf-parse.y" /* yacc.c:1646  */
    {
   	_addr = NULL, _port = -1;
   	f_name(scanner, R_IF, C_LISTEN, false);
   }
#line 1965 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 20:
#line 466 "cf-parse.y" /* yacc.c:1646  */
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
#line 1981 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 21:
#line 480 "cf-parse.y" /* yacc.c:1646  */
    { f_section(scanner,  R_SYS, S_SRV); }
#line 1987 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 22:
#line 481 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner,    R_SYS, C_VERSION,             (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 1993 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 23:
#line 482 "cf-parse.y" /* yacc.c:1646  */
    { f_auto_str(scanner, R_SYS, C_VERSION,             (yyvsp[-1].tok).i); }
#line 1999 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 24:
#line 483 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner,    R_SYS, C_IDENT,               (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2005 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 25:
#line 484 "cf-parse.y" /* yacc.c:1646  */
    { f_auto_str(scanner, R_SYS, C_IDENT,               (yyvsp[-1].tok).i); }
#line 2011 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 26:
#line 485 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner,    R_SYS, C_NSID,                (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2017 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 27:
#line 486 "cf-parse.y" /* yacc.c:1646  */
    { f_auto_str(scanner, R_SYS, C_NSID,                (yyvsp[-1].tok).i); }
#line 2023 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 28:
#line 487 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_MAX_UDP_PAYLOAD,     (yyvsp[-1].tok).i); }
#line 2029 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 29:
#line 488 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner,    R_SYS, C_RUNDIR,              (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2035 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 30:
#line 489 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner,    R_SYS, C_PIDFILE,             (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2041 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 31:
#line 490 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_UDP_WORKERS,         (yyvsp[-1].tok).i); }
#line 2047 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 32:
#line 491 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_BG_WORKERS,          (yyvsp[-1].tok).i); }
#line 2053 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 33:
#line 492 "cf-parse.y" /* yacc.c:1646  */
    { f_bool(scanner,     R_SYS, C_ASYNC_START,         (yyvsp[-1].tok).i); }
#line 2059 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 34:
#line 493 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_TCP_IDLE_TIMEOUT,    (yyvsp[-1].tok).i); }
#line 2065 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 35:
#line 494 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_TCP_HSHAKE_TIMEOUT,  (yyvsp[-1].tok).i); }
#line 2071 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 36:
#line 495 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_TCP_REPLY_TIMEOUT,   (yyvsp[-1].tok).i); }
#line 2077 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 37:
#line 496 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_MAX_TCP_CLIENTS,     (yyvsp[-1].tok).i); }
#line 2083 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 38:
#line 497 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_RATE_LIMIT,          (yyvsp[-1].tok).i); }
#line 2089 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 39:
#line 498 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_RATE_LIMIT_TBL_SIZE, (yyvsp[-1].tok).l); }
#line 2095 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 40:
#line 499 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_RATE_LIMIT_TBL_SIZE, (yyvsp[-1].tok).i); }
#line 2101 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 41:
#line 500 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,      R_SYS, C_RATE_LIMIT_SLIP,     (yyvsp[-1].tok).i); }
#line 2107 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 42:
#line 501 "cf-parse.y" /* yacc.c:1646  */
    { /* Not used. */ }
#line 2113 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 43:
#line 502 "cf-parse.y" /* yacc.c:1646  */
    { /* Deprecated */ free((yyvsp[-1].tok).t); }
#line 2119 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 44:
#line 503 "cf-parse.y" /* yacc.c:1646  */
    { /* Deprecated */ free((yyvsp[-1].tok).t); }
#line 2125 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 45:
#line 504 "cf-parse.y" /* yacc.c:1646  */
    { /* Deprecated */ free((yyvsp[-2].tok).t); free((yyvsp[-1].tok).t); }
#line 2131 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 46:
#line 505 "cf-parse.y" /* yacc.c:1646  */
    {
   	char *sep = strchr((yyvsp[-1].tok).t, '.');
   	if (sep != NULL) {
   		*sep = ':';
   	}
   	f_str(scanner, R_SYS, C_USER, (yyvsp[-1].tok).t);
   	free((yyvsp[-1].tok).t);
   }
#line 2144 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 47:
#line 516 "cf-parse.y" /* yacc.c:1646  */
    {
   	f_section(scanner, R_KEY, S_KEY);
   }
#line 2152 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 48:
#line 519 "cf-parse.y" /* yacc.c:1646  */
    {
   	f_id(scanner, R_KEY, C_ID, (yyvsp[-3].tok).t); free((yyvsp[-3].tok).t);
   	f_str(scanner, R_KEY, C_ALG, (yyvsp[-2].tok).t); free((yyvsp[-2].tok).t);
   	f_quote(scanner, R_KEY, C_SECRET, (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t);
   }
#line 2162 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 50:
#line 527 "cf-parse.y" /* yacc.c:1646  */
    { _str = (yyvsp[0].tok).t; }
#line 2168 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 51:
#line 528 "cf-parse.y" /* yacc.c:1646  */
    { _str = strdup((yyvsp[0].tok).t + 1); }
#line 2174 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 52:
#line 529 "cf-parse.y" /* yacc.c:1646  */
    { _str = strdup((yyvsp[0].tok).t); }
#line 2180 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 53:
#line 530 "cf-parse.y" /* yacc.c:1646  */
    { _str = strdup((yyvsp[0].tok).t); }
#line 2186 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 54:
#line 531 "cf-parse.y" /* yacc.c:1646  */
    { _str = strdup((yyvsp[0].tok).t); }
#line 2192 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 56:
#line 535 "cf-parse.y" /* yacc.c:1646  */
    { _port = (yyvsp[-1].tok).i; }
#line 2198 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 57:
#line 536 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-1].tok).t; }
#line 2204 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 58:
#line 537 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-3].tok).t; _port = (yyvsp[-1].tok).i; }
#line 2210 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 59:
#line 538 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-3].tok).t; _mask = (yyvsp[-1].tok).i; }
#line 2216 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 60:
#line 539 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-1].tok).t; }
#line 2222 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 61:
#line 540 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-3].tok).t; _port = (yyvsp[-1].tok).i; }
#line 2228 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 62:
#line 541 "cf-parse.y" /* yacc.c:1646  */
    { _addr = (yyvsp[-3].tok).t; _mask = (yyvsp[-1].tok).i; }
#line 2234 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 63:
#line 542 "cf-parse.y" /* yacc.c:1646  */
    {
   	f_str(scanner, R_RMT, C_KEY, (yyvsp[-1].tok).t);
   	if (is_acl(scanner, _str)) {
   		f_str(scanner, R_RMT_ACL, C_KEY, (yyvsp[-1].tok).t);
   	}
   	free((yyvsp[-1].tok).t);
   }
#line 2246 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 64:
#line 549 "cf-parse.y" /* yacc.c:1646  */
    { f_str(scanner, R_RMT, C_VIA, (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2252 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 65:
#line 550 "cf-parse.y" /* yacc.c:1646  */
    { f_str(scanner, R_RMT, C_VIA, (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2258 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 66:
#line 551 "cf-parse.y" /* yacc.c:1646  */
    { f_str(scanner, R_RMT, C_VIA, if_get(scanner, R_RMT, (yyvsp[-1].tok).t)); free((yyvsp[-1].tok).t); }
#line 2264 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 67:
#line 555 "cf-parse.y" /* yacc.c:1646  */
    {
   	_str = NULL;
   	f_section(scanner, R_RMT, S_RMT);
   	if (have_acl(scanner)) {
   		f_section(scanner, R_RMT_ACL, S_ACL);
   	}
   }
#line 2276 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 68:
#line 562 "cf-parse.y" /* yacc.c:1646  */
    {
   	_addr = NULL, _port = -1; _mask = -1;
   	f_id(scanner, R_RMT, C_ID, _str);
   	if (is_acl(scanner, _str)) {
   		f_name(scanner, R_RMT_ACL, C_ID, true);
   		f_val(scanner, R_RMT_ACL, false, "acl_%s\n", _str);
   	}
   }
#line 2289 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 69:
#line 570 "cf-parse.y" /* yacc.c:1646  */
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
#line 2319 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 70:
#line 598 "cf-parse.y" /* yacc.c:1646  */
    { grp_add(scanner, (yyvsp[0].tok).t); free((yyvsp[0].tok).t); }
#line 2325 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 74:
#line 608 "cf-parse.y" /* yacc.c:1646  */
    { grp_init(scanner, (yyvsp[0].tok).t); free((yyvsp[0].tok).t); }
#line 2331 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 77:
#line 617 "cf-parse.y" /* yacc.c:1646  */
    { f_name(scanner, R_ZONE, C_MASTER, false); acl_start(scanner, ACL_RMT); _str = ""; }
#line 2337 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 78:
#line 618 "cf-parse.y" /* yacc.c:1646  */
    { f_name(scanner, R_ZONE, C_ACL, false);    acl_start(scanner, ACL_XFR); _str = "acl_"; }
#line 2343 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 79:
#line 619 "cf-parse.y" /* yacc.c:1646  */
    { f_name(scanner, R_ZONE, C_ACL, false);    acl_start(scanner, ACL_NTF); _str = "acl_"; }
#line 2349 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 80:
#line 620 "cf-parse.y" /* yacc.c:1646  */
    { f_name(scanner, R_ZONE, C_NOTIFY, false); acl_start(scanner, ACL_RMT); _str = ""; }
#line 2355 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 81:
#line 621 "cf-parse.y" /* yacc.c:1646  */
    { f_name(scanner, R_ZONE, C_ACL, false);    acl_start(scanner, ACL_UPD); _str = "acl_"; }
#line 2361 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 83:
#line 625 "cf-parse.y" /* yacc.c:1646  */
    { acl_next(scanner, (yyvsp[0].tok).t); free((yyvsp[0].tok).t); }
#line 2367 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 84:
#line 626 "cf-parse.y" /* yacc.c:1646  */
    { acl_next(scanner, (yyvsp[0].tok).t + 1); }
#line 2373 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 85:
#line 627 "cf-parse.y" /* yacc.c:1646  */
    { acl_next(scanner, (yyvsp[0].tok).t); }
#line 2379 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 86:
#line 628 "cf-parse.y" /* yacc.c:1646  */
    { acl_next(scanner, (yyvsp[0].tok).t); }
#line 2385 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 87:
#line 629 "cf-parse.y" /* yacc.c:1646  */
    { acl_next(scanner, (yyvsp[0].tok).t); }
#line 2391 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 90:
#line 634 "cf-parse.y" /* yacc.c:1646  */
    { acl_end(scanner); }
#line 2397 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 95:
#line 646 "cf-parse.y" /* yacc.c:1646  */
    { f_id(scanner, R_ZONE, C_DOMAIN, (yyvsp[0].tok).t); free((yyvsp[0].tok).t); }
#line 2403 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 96:
#line 647 "cf-parse.y" /* yacc.c:1646  */
    { f_id(scanner, R_ZONE, C_DOMAIN, (yyvsp[0].tok).t); }
#line 2409 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 97:
#line 648 "cf-parse.y" /* yacc.c:1646  */
    { f_id(scanner, R_ZONE, C_DOMAIN, (yyvsp[0].tok).t + 1); }
#line 2415 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 98:
#line 649 "cf-parse.y" /* yacc.c:1646  */
    { f_id(scanner, R_ZONE, C_DOMAIN, (yyvsp[0].tok).t); }
#line 2421 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 99:
#line 650 "cf-parse.y" /* yacc.c:1646  */
    { f_id(scanner, R_ZONE, C_DOMAIN, (yyvsp[0].tok).t); }
#line 2427 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 100:
#line 651 "cf-parse.y" /* yacc.c:1646  */
    { f_id(scanner, R_ZONE, C_DOMAIN, (yyvsp[0].tok).t); }
#line 2433 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 101:
#line 652 "cf-parse.y" /* yacc.c:1646  */
    {
   	f_name(scanner, R_ZONE, C_DOMAIN, true);
   	f_val(scanner, R_ZONE, false, "%i/%s", (yyvsp[-2].tok).i, (yyvsp[0].tok).t);
   	f_val(scanner, R_ZONE, false, "\n");
   	free((yyvsp[0].tok).t);
   }
#line 2444 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 102:
#line 658 "cf-parse.y" /* yacc.c:1646  */
    { f_id(scanner, R_ZONE, C_DOMAIN, (yyvsp[0].tok).t); free((yyvsp[0].tok).t); }
#line 2450 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 105:
#line 664 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner, R_ZONE, C_FILE,             (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2456 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 106:
#line 665 "cf-parse.y" /* yacc.c:1646  */
    { f_bool(scanner,  R_ZONE, C_DISABLE_ANY,      (yyvsp[-1].tok).i); }
#line 2462 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 107:
#line 666 "cf-parse.y" /* yacc.c:1646  */
    { f_bool(scanner,  R_ZONE, C_IXFR_DIFF,        (yyvsp[-1].tok).i); }
#line 2468 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 108:
#line 667 "cf-parse.y" /* yacc.c:1646  */
    { f_bool(scanner,  R_ZONE, C_SEM_CHECKS,       (yyvsp[-1].tok).i); }
#line 2474 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 109:
#line 668 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE, C_MAX_JOURNAL_SIZE, (yyvsp[-1].tok).l); }
#line 2480 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 110:
#line 669 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE, C_MAX_JOURNAL_SIZE, (yyvsp[-1].tok).i); }
#line 2486 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 111:
#line 670 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE, C_ZONEFILE_SYNC,    (yyvsp[-1].tok).i); }
#line 2492 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 112:
#line 671 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE, C_ZONEFILE_SYNC,    (yyvsp[-1].tok).i); }
#line 2498 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 113:
#line 672 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner, R_ZONE, C_STORAGE,          (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2504 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 114:
#line 673 "cf-parse.y" /* yacc.c:1646  */
    { f_bool(scanner,  R_ZONE, C_DNSSEC_SIGNING,   (yyvsp[-1].tok).i); }
#line 2510 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 115:
#line 674 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner, R_ZONE, C_KASP_DB,          (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2516 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 116:
#line 675 "cf-parse.y" /* yacc.c:1646  */
    { f_str(scanner,   R_ZONE, C_SERIAL_POLICY,    (yyvsp[-1].tok).t); }
#line 2522 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 117:
#line 676 "cf-parse.y" /* yacc.c:1646  */
    { /* Not used. */ }
#line 2528 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 118:
#line 677 "cf-parse.y" /* yacc.c:1646  */
    { /* Not used. */ }
#line 2534 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 119:
#line 678 "cf-parse.y" /* yacc.c:1646  */
    { /* Not used. */ }
#line 2540 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 120:
#line 679 "cf-parse.y" /* yacc.c:1646  */
    { /* Not used. */ }
#line 2546 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 121:
#line 680 "cf-parse.y" /* yacc.c:1646  */
    {
   	if (cf_get_extra(scanner)->run == S_FIRST) {
   		cf_warning(scanner, "query module is not supported by knot1to2");
   	}
   }
#line 2556 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 126:
#line 696 "cf-parse.y" /* yacc.c:1646  */
    {
   	f_section(scanner, R_ZONE, S_ZONE); _acl_run = R_ZONE;
   	if (f_section(scanner, R_ZONE_TPL, S_TPL)) {
   		f_id(scanner, R_ZONE_TPL, C_ID, "default");
   	}
   }
#line 2567 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 128:
#line 703 "cf-parse.y" /* yacc.c:1646  */
    { f_bool(scanner,  R_ZONE_TPL, C_DISABLE_ANY,      (yyvsp[-1].tok).i); }
#line 2573 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 129:
#line 704 "cf-parse.y" /* yacc.c:1646  */
    { f_bool(scanner,  R_ZONE_TPL, C_IXFR_DIFF,        (yyvsp[-1].tok).i); }
#line 2579 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 130:
#line 705 "cf-parse.y" /* yacc.c:1646  */
    { f_bool(scanner,  R_ZONE_TPL, C_SEM_CHECKS,       (yyvsp[-1].tok).i); }
#line 2585 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 131:
#line 706 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE_TPL, C_MAX_JOURNAL_SIZE, (yyvsp[-1].tok).l); }
#line 2591 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 132:
#line 707 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE_TPL, C_MAX_JOURNAL_SIZE, (yyvsp[-1].tok).i); }
#line 2597 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 133:
#line 708 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE_TPL, C_ZONEFILE_SYNC,    (yyvsp[-1].tok).i); }
#line 2603 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 134:
#line 709 "cf-parse.y" /* yacc.c:1646  */
    { f_int(scanner,   R_ZONE_TPL, C_ZONEFILE_SYNC,    (yyvsp[-1].tok).i); }
#line 2609 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 135:
#line 710 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner, R_ZONE_TPL, C_STORAGE,          (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2615 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 136:
#line 711 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner, R_ZONE_TPL, C_TIMER_DB,         (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2621 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 137:
#line 712 "cf-parse.y" /* yacc.c:1646  */
    { f_bool(scanner,  R_ZONE_TPL, C_DNSSEC_SIGNING,   (yyvsp[-1].tok).i); }
#line 2627 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 138:
#line 713 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner, R_ZONE_TPL, C_KASP_DB,          (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2633 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 139:
#line 714 "cf-parse.y" /* yacc.c:1646  */
    { f_str(scanner,   R_ZONE_TPL, C_SERIAL_POLICY,    (yyvsp[-1].tok).t); }
#line 2639 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 140:
#line 715 "cf-parse.y" /* yacc.c:1646  */
    { /* Not used. */ }
#line 2645 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 141:
#line 716 "cf-parse.y" /* yacc.c:1646  */
    { /* Not used. */ }
#line 2651 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 142:
#line 717 "cf-parse.y" /* yacc.c:1646  */
    { /* Not used. */ }
#line 2657 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 143:
#line 718 "cf-parse.y" /* yacc.c:1646  */
    { /* Not used. */ }
#line 2663 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 144:
#line 719 "cf-parse.y" /* yacc.c:1646  */
    {
   	if (cf_get_extra(scanner)->run == S_FIRST) {
   		cf_warning(scanner, "query module is not supported by knot1to2");
   	}
   }
#line 2673 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 147:
#line 728 "cf-parse.y" /* yacc.c:1646  */
    { if (_str == NULL) _str = (yyvsp[-1].tok).t; }
#line 2679 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 148:
#line 729 "cf-parse.y" /* yacc.c:1646  */
    { if (_str == NULL) _str = (yyvsp[-1].tok).t; }
#line 2685 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 150:
#line 733 "cf-parse.y" /* yacc.c:1646  */
    { f_name(scanner, R_LOG, (yyvsp[0].tok).t, false); _str = NULL; }
#line 2691 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 151:
#line 734 "cf-parse.y" /* yacc.c:1646  */
    { f_val(scanner, R_LOG, false, "%s\n", _str); }
#line 2697 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 152:
#line 738 "cf-parse.y" /* yacc.c:1646  */
    { f_id(scanner, R_LOG, C_TARGET, (yyvsp[0].tok).t); }
#line 2703 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 153:
#line 742 "cf-parse.y" /* yacc.c:1646  */
    {
   	f_name(scanner, R_LOG, C_TARGET, true);
   	f_val(scanner, R_LOG, true, "%s", (yyvsp[0].tok).t); free((yyvsp[0].tok).t);
   	f_val(scanner, R_LOG, false, "\n");
   }
#line 2713 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 157:
#line 755 "cf-parse.y" /* yacc.c:1646  */
    { f_section(scanner, R_LOG, S_LOG); }
#line 2719 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 160:
#line 764 "cf-parse.y" /* yacc.c:1646  */
    { f_name(scanner, R_CTL, C_ACL, false); acl_start(scanner, ACL_CTL); _str = "acl_"; }
#line 2725 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 161:
#line 768 "cf-parse.y" /* yacc.c:1646  */
    { f_section(scanner, R_CTL, S_CTL); _acl_run = R_CTL; }
#line 2731 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 162:
#line 769 "cf-parse.y" /* yacc.c:1646  */
    { f_name(scanner, R_CTL, C_LISTEN, false); _addr = NULL, _port = -1; }
#line 2737 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 163:
#line 770 "cf-parse.y" /* yacc.c:1646  */
    {
   	if (_addr == NULL) {
   		cf_error(scanner, "control.listen address not defined");
   	} else if (_port == -1) {
   		f_val(scanner, R_CTL, false, "%s\n", _addr);
   	} else {
   		f_val(scanner, R_CTL, false, "%s@%i\n", _addr, _port);
   	}
   	free(_addr);
   }
#line 2752 "cf-parse.tab.c" /* yacc.c:1646  */
    break;

  case 164:
#line 780 "cf-parse.y" /* yacc.c:1646  */
    { f_quote(scanner, R_CTL, C_LISTEN, (yyvsp[-1].tok).t); free((yyvsp[-1].tok).t); }
#line 2758 "cf-parse.tab.c" /* yacc.c:1646  */
    break;


#line 2762 "cf-parse.tab.c" /* yacc.c:1646  */
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
#line 786 "cf-parse.y" /* yacc.c:1906  */

