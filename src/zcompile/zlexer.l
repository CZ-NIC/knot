%{
/*!
 * \file zlexer.l
 *
 * \author minor modifications by Jan Kadlec <jan.kadlec@nic.cz>,
 *         most of the code by NLnet Labs
 *         Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *
 * \brief lexical analyzer for (DNS) zone files.
 *
 * \addtogroup zoneparser
 * @{
 */

/*
 * Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *
 * This software is open source.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

//#include "common.h"

#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <assert.h>

#include "zcompile/zcompile.h"
#include "libknot/dname.h"
#include "zcompile/parser-descriptor.h"
#include "zparser.h"

#define YY_NO_INPUT

/* Utils */
extern void zc_error(const char *fmt, ...);
extern void zc_warning(const char *fmt, ...);

void strip_string(char *str)
{
	char *start = str;
	char *end = str + strlen(str) - 1;

	while (isspace(*start))
		++start;
	if (start > end) {
		/* Completely blank. */
		str[0] = '\0';
	} else {
		while (isspace(*end))
			--end;
		*++end = '\0';

		if (str != start)
			memmove(str, start, end - start + 1);
	}
}

int hexdigit_to_int(char ch)
{
	switch (ch) {
	case '0': return 0;
	case '1': return 1;
	case '2': return 2;
	case '3': return 3;
	case '4': return 4;
	case '5': return 5;
	case '6': return 6;
	case '7': return 7;
	case '8': return 8;
	case '9': return 9;
	case 'a': case 'A': return 10;
	case 'b': case 'B': return 11;
	case 'c': case 'C': return 12;
	case 'd': case 'D': return 13;
	case 'e': case 'E': return 14;
	case 'f': case 'F': return 15;
	default:
		abort();
	}
}

extern uint32_t strtottl(const char *nptr, const char **endptr);

#define YY_NO_UNPUT
#define MAXINCLUDES 10

#define scanner yyscanner
extern int zp_lex(YYSTYPE *lvalp, void *scanner);

#if 0
#define LEXOUT(s)  printf s /* used ONLY when debugging */
#else
#define LEXOUT(s)
#endif

enum lexer_state {
	EXPECT_OWNER,
	PARSING_OWNER,
	PARSING_TTL_CLASS_TYPE,
	PARSING_RDATA
};

static YY_BUFFER_STATE include_stack[MAXINCLUDES];
static zparser_type zparser_stack[MAXINCLUDES];
static int include_stack_ptr = 0;

static void pop_parser_state(void *scanner);
static void push_parser_state(FILE *input, void *scanner);
static int parse_token(void *scanner, int token, char *in_str,
                       enum lexer_state *lexer_state);


/*!< \todo does not compile */
#ifndef yy_set_bol // compat definition, for flex 2.4.6
#define yy_set_bol(at_bol) \
{ \
	if (!yy_current_buffer ) \
		yy_current_buffer = yy_create_buffer( yyin, YY_BUF_SIZE ); \
	yy_current_buffer->yy_ch_buf[0] = ((at_bol)?'\n':' '); \
}
#endif

%}

%option nounput
%option reentrant bison-bridge
%option prefix = "zp_"
%option outfile = "lex.yy.c"

SPACE   [ \t]
LETTER  [a-zA-Z]
NEWLINE [\n\r]
ZONESTR [^ \t\n\r();.\"\$]
DOLLAR  \$
COMMENT ;
DOT     \.
BIT     [^\]\n]|\\.
ANY     [^\"\n\\]|\\.

%x	incl bitlabel quotedstring

%%
	static int paren_open = 0;
	static enum lexer_state lexer_state = EXPECT_OWNER;

{SPACE}*{COMMENT}.*	/* ignore */
^{DOLLAR}TTL            { lexer_state = PARSING_RDATA; return DOLLAR_TTL; }
^{DOLLAR}ORIGIN         { lexer_state = PARSING_RDATA; return DOLLAR_ORIGIN; }

 /*
  * Handle $INCLUDE directives.  See
  * http://dinosaur.compilertools.net/flex/flex_12.html#SEC12.
  */
^{DOLLAR}INCLUDE        {
	BEGIN(incl);
}
<incl>\n 		|
<incl><<EOF>>		{
	int error_occurred = parser->error_occurred;
	BEGIN(INITIAL);
	zc_error("missing file name in $INCLUDE directive");
	yy_set_bol(1); /* Set beginning of line, so "^" rules match.  */
	++parser->line;
	parser->error_occurred = error_occurred;
}
<incl>.+ 		{
	char *tmp;
	/*! \todo pointer to origin. */
	void *origin = parser->origin;
	/* domain_type *origin = parser->origin; */
	int error_occurred = parser->error_occurred;

	BEGIN(INITIAL);
	if (include_stack_ptr >= MAXINCLUDES ) {
		zc_error("includes nested too deeply, skipped (>%d)",
			 MAXINCLUDES);
	} else {
		FILE *input;

		/* Remove trailing comment.  */
		tmp = strrchr(yytext, ';');
		if (tmp) {
			*tmp = '\0';
		}
		strip_string(yytext);

		/* Parse origin for include file.  */
		tmp = strrchr(yytext, ' ');
		if (!tmp) {
			tmp = strrchr(yytext, '\t');
		}
		if (tmp) {
			/* split the original yytext */
			*tmp = '\0';
			strip_string(yytext);

			/*! \todo knot_dname_new_from_wire() (dname.h)
			 *        which knot_node to pass as node?
			 */
			knot_dname_t *dname;
			dname = knot_dname_new_from_wire((uint8_t*)tmp + 1,
							   strlen(tmp + 1),
							   NULL);
			if (!dname) {
				zc_error("incorrect include origin '%s'",
					 tmp + 1);
			} else {
				/*! \todo insert to zonedb. */
				/* origin = domain_table_insert(
					parser->db->domains, dname); */
			}
		}

		if (strlen(yytext) == 0) {
			zc_error("missing file name in $INCLUDE directive");
		} else if (!(input = fopen(yytext, "r"))) {
			char ebuf[256];
			zc_error("cannot open include file '%s': %s",
				 yytext, strerror_r(errno, ebuf, sizeof(ebuf)));
		} else {
			/* Initialize parser for include file.  */
			char *filename = strdup(yytext);
			push_parser_state(input, scanner); /* Destroys yytext.  */
			parser->filename = filename;
			parser->line = 1;
			parser->origin = origin;
			lexer_state = EXPECT_OWNER;
		}
	}

	parser->error_occurred = error_occurred;
}
<INITIAL><<EOF>>	{
	yy_set_bol(1); /* Set beginning of line, so "^" rules match.  */
	if (include_stack_ptr == 0) {
	// from: http://stackoverflow.com/questions/1756275/bison-end-of-file
		static int once = 0;
		once++;
		if (once > 1) {
			yyterminate();
		} else {
			return NL;
		}
	} else {
		fclose(yyin);
		pop_parser_state(scanner);
	}
}
^{DOLLAR}{LETTER}+	{ zc_warning("Unknown directive: %s", yytext); }
{DOT}	{
	LEXOUT((". "));
	return parse_token(scanner, '.', yytext, &lexer_state);
}
@	{
	LEXOUT(("@ "));
	return parse_token(scanner, '@', yytext, &lexer_state);
}
\\#	{
	LEXOUT(("\\# "));
	return parse_token(scanner, URR, yytext, &lexer_state);
}
{NEWLINE}	{
	++parser->line;
	if (!paren_open) {
		lexer_state = EXPECT_OWNER;
		LEXOUT(("NL\n"));
		return NL;
	} else {
		LEXOUT(("SP "));
		return SP;
	}
}
\(	{
	if (paren_open) {
		zc_error("nested parentheses");
		yyterminate();
	}
	LEXOUT(("( "));
	paren_open = 1;
	return SP;
}
\)	{
	if (!paren_open) {
		zc_error("closing parentheses without opening parentheses");
		yyterminate();
	}
	LEXOUT((") "));
	paren_open = 0;
	return SP;
}
{SPACE}+	{
	if (!paren_open && lexer_state == EXPECT_OWNER) {
		lexer_state = PARSING_TTL_CLASS_TYPE;
		LEXOUT(("PREV "));
		return PREV;
	}
	if (lexer_state == PARSING_OWNER) {
		lexer_state = PARSING_TTL_CLASS_TYPE;
	}
	LEXOUT(("SP "));
	return SP;
}

	/* Bitlabels.  Strip leading and ending brackets.  */
\\\[			{ BEGIN(bitlabel); }
<bitlabel><<EOF>>	{
	zc_error("EOF inside bitlabel");
	BEGIN(INITIAL);
}
<bitlabel>{BIT}*	{ yymore(); }
<bitlabel>\n		{ ++parser->line; yymore(); }
<bitlabel>\]		{
	BEGIN(INITIAL);
	yytext[yyleng - 1] = '\0';
	return parse_token(scanner, BITLAB, yytext, &lexer_state);
}

	/* Quoted strings.  Strip leading and ending quotes.  */
\"			{ BEGIN(quotedstring); LEXOUT(("\" ")); }
<quotedstring><<EOF>> 	{
	zc_error("EOF inside quoted string");
	BEGIN(INITIAL);
}
<quotedstring>{ANY}*	{ LEXOUT(("STR ")); yymore(); }
<quotedstring>\n 	{ ++parser->line; yymore(); }
<quotedstring>\" {
	LEXOUT(("\" "));
	BEGIN(INITIAL);
	yytext[yyleng - 1] = '\0';
	return parse_token(scanner, STR, yytext, &lexer_state);
}

({ZONESTR}|\\.|\\\n)+ {
	/* Any allowed word.  */
	return parse_token(scanner, STR, yytext, &lexer_state);
}
. {
	zc_error("unknown character '%c' (\\%03d) seen - is this a zonefile?",
		 (int) yytext[0], (int) yytext[0]);
}
%%

/*
 * Analyze "word" to see if it matches an RR type, possibly by using
 * the "TYPExxx" notation.  If it matches, the corresponding token is
 * returned and the TYPE parameter is set to the RR type value.
 */
static int
rrtype_to_token(const char *word, uint16_t *type)
{
	uint16_t t = parser_rrtype_from_string(word);
	if (t != 0) {
		parser_rrtype_descriptor_t *entry = 0;
		entry = parser_rrtype_descriptor_by_type(t);
		*type = t;

		/*! \todo entry should return associated token.
			  see nsd/dns.c */
		return entry->token;
	}

	return 0;
}


/*
 * Remove \DDD constructs from the input. See RFC 1035, section 5.1.
 */
static size_t
zoctet(char *text)
{
	/*
	 * s follows the string, p lags behind and rebuilds the new
	 * string
	 */
	char *s;
	char *p;

	for (s = p = text; *s; ++s, ++p) {
		assert(p <= s);
		if (s[0] != '\\') {
			/* Ordinary character.  */
			*p = *s;
		} else if (isdigit((int)s[1]) && isdigit((int)s[2]) &&  isdigit((int)s[3])) {
			/* \DDD escape.  */
			int val = (hexdigit_to_int(s[1]) * 100 +
				   hexdigit_to_int(s[2]) * 10 +
				   hexdigit_to_int(s[3]));
			if (0 <= val && val <= 255) {
				s += 3;
				*p = val;
			} else {
				zc_warning("text escape \\DDD overflow");
				*p = *++s;
			}
		} else if (s[1] != '\0') {
			/* \X where X is any character, keep X.  */
			*p = *++s;
		} else {
			/* Trailing backslash, ignore it.  */
			zc_warning("trailing backslash ignored");
			--p;
		}
	}
	*p = '\0';
	return p - text;
}

static int parse_token(void *scanner, int token, char *in_str,
                       enum lexer_state *lexer_state)
{
	size_t len = 0;
	char *str = NULL;

	struct yyguts_t *yyg = (struct yyguts_t *)scanner;

	if (*lexer_state == EXPECT_OWNER) {
		*lexer_state = PARSING_OWNER;
	} else if (*lexer_state == PARSING_TTL_CLASS_TYPE) {
		const char *t;
		int token;
		uint16_t rrclass;

		/* type */
		token = rrtype_to_token(in_str, &yylval->type);
		if (token != 0) {
			*lexer_state = PARSING_RDATA;
			LEXOUT(("%d[%s] ", token, in_str));
			return token;
		}

		/* class */
		rrclass = parser_rrclass_from_string(in_str);
		if (rrclass != 0) {
			yylval->rclass = rrclass;
			LEXOUT(("CLASS "));
			return T_RRCLASS;
		}

		/* ttl */
		yylval->ttl = strtottl(in_str, &t);
		if (*t == '\0') {
			LEXOUT(("TTL "));
			return T_TTL;
		}
	}

	str = strdup(yytext);
	if (str == NULL) {
		/* Out of memory */
		ERR_ALLOC_FAILED;
		return NO_MEM;
	}
	len = zoctet(str);

	yylval->data.str = str;
	assert(yylval->data.str != NULL);
	yylval->data.len = len;

	if (strcmp(yytext, ".") == 0) {
		free(str);
		yylval->data.str=".";
	} else if (strcmp(str, "@") == 0) {
		free(str);
		yylval->data.str="@";
	} else if (strcmp(str, "\\#") == 0) {
		free(str);
		yylval->data.str="\\#";
	}

	LEXOUT(("%d[%s] ", token, in_str));
	return token;
}

/*
 * Saves the file specific variables on the include stack.
 */
static void push_parser_state(FILE *input, void *scanner)
{
	struct yyguts_t *yyg = (struct yyguts_t *)scanner;
	zparser_stack[include_stack_ptr].filename = parser->filename;
	zparser_stack[include_stack_ptr].line = parser->line;
	zparser_stack[include_stack_ptr].origin = parser->origin;
	include_stack[include_stack_ptr] = YY_CURRENT_BUFFER;
	yy_switch_to_buffer(yy_create_buffer(input, YY_BUF_SIZE, scanner),
	                    scanner);
	++include_stack_ptr;
}

/*
 * Restores the file specific variables from the include stack.
 */
void pop_parser_state(void *scanner)
{
	struct yyguts_t *yyg = (struct yyguts_t *)scanner;
	--include_stack_ptr;
	parser->filename = zparser_stack[include_stack_ptr].filename;
	parser->line = zparser_stack[include_stack_ptr].line;
	parser->origin = zparser_stack[include_stack_ptr].origin;
	yy_delete_buffer(YY_CURRENT_BUFFER, scanner);
	yy_switch_to_buffer(include_stack[include_stack_ptr], scanner);
}
