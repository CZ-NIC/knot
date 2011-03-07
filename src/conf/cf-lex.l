/*!
 * \file cf-lex.l
 *
 * \author Ondrej Sury <ondrej.sury@nic.cz>
 *
 * \brief Server configuration structures and API.
 *
 * IP address conversions from BIRD, (c) 1998--2000 Martin Mares <mj@ucw.cz>
 */
%{

#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <arpa/inet.h>

#include "conf/conf.h"
#include "other/log.h"
#include "libknot_la-cf-parse.h" /* Automake generated header. */

/* Imported symbols. */
#define yylex cf_lex
extern void cf_error(const char *msg);
extern int (*cf_read_hook)(char *buf, size_t nbytes);

#define YY_INPUT(buf,result,max) result = cf_read_hook(buf, max);
#define YY_NO_UNPUT

%}

%option noyywrap
%option noinput
%option nounput
%option noreject
%option yylineno

ALPHA [a-zA-Z_]
DIGIT [0-9]
HEXA  [0-9a-fA-F]
ALNUM [a-zA-Z_0-9]
BLANK [ \t\n]

%%
\#.*\n               /* Ignore comments */;
{BLANK}+             /* Ignore whitespace */;
[@{};,]              { return yytext[0]; }
system               return SYSTEM;
identity             return IDENTITY;
version              return VERSION;
storage              return STORAGE;
key                  return KEY;

zones                return ZONES;
file                 return FILENAME;

interfaces           return INTERFACES;
address              return ADDRESS;
port                 return PORT;

log                  return LOG;
any                  { cf_lval.i = LOG_ANY; return LOG_SRC; }
server               { cf_lval.i = LOG_SERVER; return LOG_SRC; }
answering            { cf_lval.i = LOG_ANSWER; return LOG_SRC; }
zone                 { cf_lval.i = LOG_ZONE; return LOG_SRC; }
stdout               { cf_lval.i = LOGT_STDOUT; return LOG_DEST; }
stderr               { cf_lval.i = LOGT_STDERR; return LOG_DEST; }
syslog               { cf_lval.i = LOGT_SYSLOG; return LOG_DEST; }
all                  { cf_lval.i = LOG_UPTO(LOG_DEBUG); return LOG_LEVEL; }
debug                { cf_lval.i = LOG_MASK(LOG_DEBUG); return LOG_LEVEL; }
info                 { cf_lval.i = LOG_MASK(LOG_INFO); return LOG_LEVEL; }
notice               { cf_lval.i = LOG_MASK(LOG_NOTICE); return LOG_LEVEL; }
warning              { cf_lval.i = LOG_MASK(LOG_WARNING); return LOG_LEVEL; }
error                { cf_lval.i = LOG_MASK(LOG_ERR); return LOG_LEVEL; }

{DIGIT}+ {
  cf_lval.i = atoi(yytext);
  return NUM;
}

{DIGIT}+\.{DIGIT}+\.{DIGIT}+\.{DIGIT}+ {
  unsigned char buf[sizeof(struct in_addr)];
  if (inet_pton(AF_INET, yytext, buf)) {
	  cf_lval.t = strdup(yytext);
	  return IPA;
  }
  cf_error("Invalid IP address.");
}

({HEXA}*::|({HEXA}*:){3,})({HEXA}*|{DIGIT}+\.{DIGIT}+\.{DIGIT}+\.{DIGIT}+) {
#ifdef DISABLE_IPV6
unsigned char buf[sizeof(struct in6_addr)];
if (inet_pton(AF_INET6, yytext, buf)) {
        cf_lval.t = strdup(yytext);
        return IPA6;
}
cf_error("Invalid IPv6 address.");
#else
  unsigned char buf[sizeof(struct in6_addr)];
  if (inet_pton(AF_INET6, yytext, buf)) {
	  cf_lval.t = strdup(yytext);
	  return IPA6;
  }
  cf_error("Invalid IPv6 address.");
#endif
}

gss-tsig        { cf_lval.alg = GSS_TSIG;    return TSIG_ALGO_NAME; }
hmac-md5        { cf_lval.alg = HMAC_MD5;    return TSIG_ALGO_NAME; }
hmac-sha1       { cf_lval.alg = HMAC_SHA1;   return TSIG_ALGO_NAME; }
hmac-sha224     { cf_lval.alg = HMAC_SHA224; return TSIG_ALGO_NAME; }
hmac-sha256     { cf_lval.alg = HMAC_SHA256; return TSIG_ALGO_NAME; }
hmac-sha384     { cf_lval.alg = HMAC_SHA384; return TSIG_ALGO_NAME; }
hmac-sha512     { cf_lval.alg = HMAC_SHA512; return TSIG_ALGO_NAME; }

["][^"\n]*["] {
  yytext[yyleng-1] = 0;
  cf_lval.t = strdup(yytext + 1);
  return TEXT;
}

["][^"\n]*\n    cf_error("Unterminated string.");

[a-zA-Z0-9\.]+ {
  cf_lval.t = strdup(yytext);
  return TEXT /* Last resort, alphanumeric word. */;
}

<<EOF>> return END;

%%

