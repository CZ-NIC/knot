/*!
 * \file cf-lex.l
 *
 * \author Ondrej Sury <ondrej.sury@nic.cz>
 *
 * \brief Server configuration structures and API.
 *
 * \addtogroup config
 * \{
 *
 * IP address conversions from BIRD, (c) 1998--2000 Martin Mares <mj@ucw.cz>
 */
%{

#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <arpa/inet.h>

#include "conf/conf.h"
#include "cf-parse.h"
//int (*cf_read_hook)(unsigned char *buf, unsigned int max);
extern void yyerror(const char *str); // cf-parse.y

//#define YY_INPUT(buf,result,max) result = cf_read_hook(buf, max);
//#define YY_NO_UNPUT
//#define YY_FATAL_ERROR(msg) yyerror(msg)
/*%token <alg> TSIG_ALGO_NAME*/

%}

%option noyywrap
%option noinput
%option nounput
%option noreject

ALPHA [a-zA-Z_]
DIGIT [0-9]
HEXA  [0-9a-fA-F]
ALNUM [a-zA-Z_0-9]
BLANK [ \t\n]

%%

\#.*\n          /* Ignore comments */;
{BLANK}+        /* Ignore whitespace */;
[{};]           { return yytext[0]; }
system          return SYSTEM;
identity        return IDENTITY;
version         return VERSION;
log             return LOG;
interfaces      return INTERFACES;
address         return ADDRESS;
port            return PORT;
algorithm       return ALGORITHM;
secret          return SECRET;
servers         return SERVERS;
keys            return KEYS;
key             return KEY;
interface       return INTERFACE;
zones           return ZONES;
storage         return STORAGE;

{DIGIT}+ {
  yylval.i = atoi(yytext);
  return NUM;
}

{DIGIT}+\.{DIGIT}+\.{DIGIT}+\.{DIGIT}+ {
  unsigned char buf[sizeof(struct in_addr)];
  if (inet_pton(AF_INET, yytext, buf))
	  return IPA;
  yyerror("Invalid IP address.");
}

({HEXA}*::|({HEXA}*:){3,})({HEXA}*|{DIGIT}+\.{DIGIT}+\.{DIGIT}+\.{DIGIT}+) {
  unsigned char buf[sizeof(struct in6_addr)];
  if (inet_pton(AF_INET6, yytext, buf))
	  return IPA;
  yyerror("Invalid IPv6 address.");
}

gss-tsig        { yylval.alg = GSS_TSIG;    return TSIG_ALGO_NAME; }
hmac-md5        { yylval.alg = HMAC_MD5;    return TSIG_ALGO_NAME; }
hmac-sha1       { yylval.alg = HMAC_SHA1;   return TSIG_ALGO_NAME; }
hmac-sha224     { yylval.alg = HMAC_SHA224; return TSIG_ALGO_NAME; }
hmac-sha256     { yylval.alg = HMAC_SHA256; return TSIG_ALGO_NAME; }
hamc-sha384     { yylval.alg = HMAC_SHA384; return TSIG_ALGO_NAME; }
hmac-sha512     { yylval.alg = HMAC_SHA512; return TSIG_ALGO_NAME; }

["][^"\n]*["] {
  yytext[yyleng-1] = 0;
  yylval.t = strdup(yytext + 1);
  return TEXT;
}

["][^"\n]*\n    yyerror("Unterminated string.");

{ALNUM}+ {
  yylval.t = strdup(yytext);
  return TEXT /* Last resort, alphanumeric word. */;
}

[a-zA-Z0-9\.]+  {
  yylval.t = strdup(yytext);
  return ZONE;
}

<<EOF>> return END;

%%

