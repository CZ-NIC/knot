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

#include "common/sockaddr.h"
#include "knot/conf/conf.h"
#include "knot/other/log.h"
#include "libknotd_la-cf-parse.h" /* Automake generated header. */

/* Imported symbols. */
#define lval (yylval->tok)
extern void cf_error(void *scanner, const char *msg);
extern int (*cf_read_hook)(char *buf, size_t nbytes);
void switch_input(const char *str, void *scanner)
{
	yy_scan_string(str, scanner);
}

//#define YY_INPUT(buf,result,max) result = cf_read_hook(buf, max);
#define YY_NO_UNPUT

%}

%option reentrant
%option bison-bridge
%option noyywrap
%option noinput
%option nounput
%option noreject
%option yylineno
%option prefix = "cf_"
%option outfile = "lex.yy.c"

ALPHA [a-zA-Z_]
DIGIT [0-9]
HEXA  [0-9a-fA-F]
ALNUM [a-zA-Z_0-9]
BLANK [ \t\n]

%%
\#.*\n          /* Ignore comments */;
{BLANK}+        /* Ignore whitespace */;
:		/* Optional : in assignments. */;
[\!\$\%\^\&\*\(\)\/\+\-\@\{\}\;\,] { return yytext[0]; }
system          { lval.t = yytext;  return SYSTEM; }
identity        { lval.t = yytext; return IDENTITY; }
version         { lval.t = yytext; return VERSION; }
storage         { lval.t = yytext; return STORAGE; }
key             { lval.t = yytext; return KEY; }
keys            { lval.t = yytext; return KEYS; }
remotes         { lval.t = yytext; return REMOTES; }

zones           { lval.t = yytext; return ZONES; }
file            { lval.t = yytext; return FILENAME; }
semantic-checks { lval.t = yytext; return SEMANTIC_CHECKS; }
notify-retries  { lval.t = yytext; return NOTIFY_RETRIES; }
notify-timeout  { lval.t = yytext; return NOTIFY_TIMEOUT; }
zonefile-sync   { lval.t = yytext; return DBSYNC_TIMEOUT; }
ixfr-fslimit    { lval.t = yytext; return IXFR_FSLIMIT; }
xfr-in          { lval.t = yytext; return XFR_IN; }
xfr-out         { lval.t = yytext; return XFR_OUT; }
notify-in       { lval.t = yytext; return NOTIFY_IN; }
notify-out      { lval.t = yytext; return NOTIFY_OUT; }
workers         { lval.t = yytext; return WORKERS; }

interfaces      { lval.t = yytext; return INTERFACES; }
address         { lval.t = yytext; return ADDRESS; }
port            { lval.t = yytext; return PORT; }

log             { lval.t = yytext; return LOG; }

any { lval.t = yytext; lval.i = LOG_ANY; return LOG_SRC; }
server { lval.t = yytext; lval.i = LOG_SERVER; return LOG_SRC; }
answering { lval.t = yytext; lval.i = LOG_ANSWER; return LOG_SRC; }
zone { lval.t = yytext; lval.i = LOG_ZONE; return LOG_SRC; }
stdout { lval.t = yytext; lval.i = LOGT_STDOUT; return LOG_DEST; }
stderr { lval.t = yytext; lval.i = LOGT_STDERR; return LOG_DEST; }
syslog { lval.t = yytext; lval.i = LOGT_SYSLOG; return LOG_DEST; }
all { lval.t = yytext; lval.i = LOG_UPTO(LOG_DEBUG); return LOG_LEVEL; }
debug { lval.t = yytext; lval.i = LOG_MASK(LOG_DEBUG); return LOG_LEVEL; }
info { lval.t = yytext; lval.i = LOG_MASK(LOG_INFO); return LOG_LEVEL; }
notice { lval.t = yytext; lval.i = LOG_MASK(LOG_NOTICE); return LOG_LEVEL; }
warning { lval.t = yytext; lval.i = LOG_MASK(LOG_WARNING); return LOG_LEVEL; }
error { lval.t = yytext; lval.i = LOG_MASK(LOG_ERR); return LOG_LEVEL; }

on|off {
  lval.t = yytext;
  lval.i = 0;
  if (strcmp(yytext, "on") == 0) {
    lval.i = 1;
  }
  return BOOL;
}

{DIGIT}+[smhd] {
  size_t mpos = strlen(yytext) - 1;
  char multiplier = yytext[mpos];
  yytext[mpos] = '\0';
  lval.i = atoi(yytext);
  if (lval.i < 1) {
	  cf_error(yyscanner, "interval must be a positive integer");
	  return END;
  }

  /* Handle multiplier. */
  switch(multiplier) {
  case 'm': lval.i *= 60; break; /* minutes */
  case 'h': lval.i *= 60*60; break; /* hours */
  case 'd': lval.i *= 24*60*60; break; /* days */
  case 's': /* seconds */
  default: break;
  }

  return INTERVAL;
}

{DIGIT}+[kMG] {
  size_t mpos = strlen(yytext) - 1;
  char multiplier = yytext[mpos];
  yytext[mpos] = '\0';
  lval.i = atol(yytext);
  if (lval.i < 1) {
	  cf_error(yyscanner, "size must be a positive integer");
	  return END;
  }

  /* Handle multiplier. */
  switch(multiplier) {
  case 'k': lval.l = lval.i * 1024; break; /* kB */
  case 'M': lval.l = lval.i * 1024*1024; break; /* MB */
  case 'G': lval.l = lval.i * 1024*1024*1024; break; /* GB */
  default: break;
  }

  return SIZE;
}

{DIGIT}+ {
  lval.i = atol(yytext);
  return NUM;
}

{DIGIT}+\.{DIGIT}+\.{DIGIT}+\.{DIGIT}+ {
  unsigned char buf[sizeof(struct in_addr)];
  if (inet_pton(AF_INET, yytext, buf)) {
	  lval.t = strdup(yytext);
	  return IPA;
  }
  cf_error(yyscanner, "Invalid IP address.");
}

\[({HEXA}*::|({HEXA}*:){3,})({HEXA}*|{DIGIT}+\.{DIGIT}+\.{DIGIT}+\.{DIGIT}+)\] {
#ifdef DISABLE_IPV6
  lval.t = strdup(yytext);
  cf_error(yyscanner, "IPv6 address support not compiled.");
  return TEXT;
#else
  unsigned char buf[sizeof(struct in6_addr)];
  yytext[strlen(yytext)-1] = '\0';
  if (inet_pton(AF_INET6, yytext+1, buf)) {
	  lval.t = strdup(yytext+1);
	  return IPA6;
  }
  cf_error(yyscanner, "Invalid IPv6 address.");
#endif
  }

({HEXA}*::|({HEXA}*:){3,})({HEXA}*|{DIGIT}+\.{DIGIT}+\.{DIGIT}+\.{DIGIT}+) {
#ifdef DISABLE_IPV6
	lval.t = strdup(yytext);
	cf_error(yyscanner, "IPv6 address support not compiled.");
	return TEXT;
#else
  unsigned char buf[sizeof(struct in6_addr)];
  if (inet_pton(AF_INET6, yytext, buf)) {
	  lval.t = strdup(yytext);
	  return IPA6;
  }
  cf_error(yyscanner, "Invalid IPv6 address.");
#endif
}

gss-tsig        { lval.alg = KNOT_TSIG_ALG_GSS_TSIG;    return TSIG_ALGO_NAME; }
hmac-md5        { lval.alg = KNOT_TSIG_ALG_HMAC_MD5;    return TSIG_ALGO_NAME; }
hmac-sha1       { lval.alg = KNOT_TSIG_ALG_HMAC_SHA1;   return TSIG_ALGO_NAME; }
hmac-sha224     { lval.alg = KNOT_TSIG_ALG_HMAC_SHA224; return TSIG_ALGO_NAME; }
hmac-sha256     { lval.alg = KNOT_TSIG_ALG_HMAC_SHA256; return TSIG_ALGO_NAME; }
hmac-sha384     { lval.alg = KNOT_TSIG_ALG_HMAC_SHA384; return TSIG_ALGO_NAME; }
hmac-sha512     { lval.alg = KNOT_TSIG_ALG_HMAC_SHA512; return TSIG_ALGO_NAME; }

["][^"\n]*["] {
  yytext[yyleng-1] = 0;
  lval.t = strdup(yytext + 1);
  return TEXT;
}

["][^"\n]*\n    cf_error(yyscanner, "Unterminated string.");

[a-zA-Z0-9\.\-\_]+ {
  lval.t = strdup(yytext);
  return TEXT /* Last resort, alphanumeric word. */;
}

<<EOF>> return END;

%%

