/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "contrib/json.h"

#define MAX_DEPTH 8

enum {
	BLOCK_INVALID = 0,
	BLOCK_OBJECT,
	BLOCK_LIST,
};

/*! One indented block of JSON. */
struct block {
	/*! Block type. */
	int type;
	/*! Number of elements written. */
	int count;
};

struct jsonw {
	/*! Output file stream. */
	FILE *out;
	/*! Indentaiton string. */
	const char *indent;
	/*! List to be used as a stack of blocks in progress. */
	struct block stack[MAX_DEPTH];
	/*! Index pointing to the top of the stack. */
	int top;
	/*! Newline needed indication. */
	bool wrap;
};

static const char *DEFAULT_INDENT = "\t";

static void start_block(jsonw_t *w, int type)
{
	assert(w->top > 0);

	struct block b = {
		.type = type,
		.count = 0,
	};

	w->top -= 1;
	w->stack[w->top] = b;
}

static struct block *cur_block(jsonw_t *w)
{
	if (w && w->top < MAX_DEPTH) {
		return &w->stack[w->top];
	}
	return NULL;
}

/*! Insert new line and indent for the next write. */
static void wrap(jsonw_t *w)
{
	if (!w->wrap) {
		w->wrap = true;
		return;
	}

	fputc('\n', w->out);
	int level = MAX_DEPTH - w->top;
	for (int i = 0; i < level; i++) {
		fprintf(w->out, "%s", w->indent);
	}
}

static void end_block(jsonw_t *w)
{
	assert(w->top < MAX_DEPTH);

	w->top += 1;
}

static void escaped_print(jsonw_t *w, const char *str)
{
	fputc('"', w->out);
	for (const char *pos = str; *pos != '\0'; pos++) {
		char c = *pos;
		if (c == '\\' || c == '\"') {
			fputc('\\', w->out);
		}
		fputc(c, w->out);
	}
	fputc('"', w->out);
}

static void align_key(jsonw_t *w, const char *key)
{
	struct block *top = cur_block(w);
	if (top && top->count++) {
		fputc(',', w->out);
	}

	wrap(w);

	if (key && key[0]) {
		escaped_print(w, key);
		fprintf(w->out, ": ");
	}
}

jsonw_t *jsonw_new(FILE *out, const char *indent)
{
	assert(out);

	jsonw_t *w = calloc(1, sizeof(*w));
	if (w == NULL) {
		return w;
	}

	w->out = out;
	w->indent = indent ? indent : DEFAULT_INDENT;
	w->top = MAX_DEPTH;

	return w;
}

void jsonw_free(jsonw_t **w)
{
	if (w == NULL) {
		return;
	}

	wrap(*w);

	free(*w);
	*w = NULL;
}

void jsonw_object(jsonw_t *w, const char *key)
{
	assert(w);

	align_key(w, key);
	fprintf(w->out, "{");
	start_block(w, BLOCK_OBJECT);
}

void jsonw_list(jsonw_t *w, const char *key)
{
	assert(w);

	align_key(w, key);
	fprintf(w->out, "[");
	start_block(w, BLOCK_LIST);
}

void jsonw_str(jsonw_t *w, const char *key, const char *value)
{
	assert(w);

	align_key(w, key);
	escaped_print(w, value);
}

void jsonw_ulong(jsonw_t *w, const char *key, unsigned long value)
{
	assert(w);

	align_key(w, key);
	fprintf(w->out, "%lu", value);
}

void jsonw_int(jsonw_t *w, const char *key, int value)
{
	assert(w);

	align_key(w, key);
	fprintf(w->out, "%d", value);
}


void jsonw_bool(jsonw_t *w, const char *key, bool value)
{
	assert(w);

	align_key(w, key);
	fprintf(w->out, "%s", value ? "true" : "false");
}

void jsonw_end(jsonw_t *w)
{
	assert(w);

	struct block *top = cur_block(w);
	if (top == NULL) {
		return;
	}

	end_block(w);
	wrap(w);

	switch (top->type) {
	case BLOCK_OBJECT:
		fprintf(w->out, "}");
		break;
	case BLOCK_LIST:
		fprintf(w->out, "]");
		break;
	}
}
