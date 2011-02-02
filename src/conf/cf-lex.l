%{

#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>

#include "conf/conf.h"
#include "cf-parse.h"
int (*cf_read_hook)(unsigned char *buf, unsigned int max);

#define YY_INPUT(buf,result,max) result = cf_read_hook(buf, max);
#define YY_NO_UNPUT
//#define YY_FATAL_ERROR(msg) cf_error(msg)

%}

%option noyywrap
%option noinput
%option nounput
%option noreject

ALPHA [a-zA-Z_]
DIGIT [0-9]
XIGIT [0-9a-fA-F]
ALNUM [a-zA-Z_0-9]
WHITE [ \t]

%%

\#\#.*\n        ; // Ignore comments
