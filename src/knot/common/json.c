/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/common/json.h"

jsonw_t *jsonw_new(FILE *out, const char *indent)
{
	if (!out) {
		return NULL;
	}

	jsonw_t *w = calloc(1, sizeof(*w));
	if (!w) {
		return NULL;
	}

	w->out = out;
	w->indent = indent;

	w->top = MAX_DEPTH;

	return w;
}

void jsonw_free(jsonw_t *w)
{
	if (!w) {
		return;
	}

	free(w);
	w = NULL;
}

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

static void end_block(jsonw_t *w)
{
	assert(w->top < MAX_DEPTH);

	w->top += 1;
}

static struct block *cur_block(jsonw_t *w)
{
	if (!w) {
		return NULL;
	}
	if (w->top >= MAX_DEPTH) {
		return NULL;
	}

	assert(w->top < MAX_DEPTH);

	return &w->stack[w->top];
}

/*! Insert new line and indent for the next write. */
static void wrap(jsonw_t *w)
{
	fputc('\n', w->out);

	int level = MAX_DEPTH - w->top;
	for (int i = 0; i < level; i++) {
		fprintf(w->out, "%s", w->indent);
	}
}

/*! Align for the write of a next value. */
static void align(jsonw_t *w)
{
	if (w->top == MAX_DEPTH) {
		return;
	}

	struct block *top = cur_block(w);

	switch (top->type) {
	case BLOCK_OBJECT:
		if (top->count == 0) {
			wrap(w);
		} else if (top->count % 2 == 0) {
			fputc(',', w->out);
			wrap(w);
		} else {
			fprintf(w->out, ": ");
		}
		break;
	case BLOCK_LIST:
		if (top->count > 0) {
			fputc(',', w->out);
		}
		wrap(w);
		break;
	}

	top->count += 1;
}

void jsonw_object(jsonw_t *w)
{
	align(w);

	fprintf(w->out, "{");
	start_block(w, BLOCK_OBJECT);
}

void jsonw_list(jsonw_t *w)
{
	align(w);

	fprintf(w->out, "[");
	start_block(w, BLOCK_LIST);
}

void jsonw_end(jsonw_t *w)
{
	struct block *top = cur_block(w);
	int type = top->type;
	end_block(w);

	wrap(w);

	switch (type) {
	case BLOCK_OBJECT:
		fputc('}', w->out);
		break;
	case BLOCK_LIST:
		fputc(']', w->out);
		break;
	}

	// extra new line for the last block
	if (w->top == MAX_DEPTH) {
		fputc('\n', w->out);
	}
}

void jsonw_str(jsonw_t *w, const char *value)
{
	align(w);

	fputc('"', w->out);
	for (const char *pos = value; *pos != '\0'; pos++) {
		char c = *pos;
		if (c == '\\' || c == '\"') {
			fputc('\\', w->out);
		}
		fputc(c, w->out);
	}
	fputc('"', w->out);
}

void jsonw_int(jsonw_t *w, int value)
{
	align(w);

	fprintf(w->out, "%d", value);
}


void jsonw_ulong(jsonw_t *w, unsigned long value)
{
	align(w);

	fprintf(w->out, "%lu", value);
}

void jsonw_bool(jsonw_t *w, bool value)
{
	align(w);

	fprintf(w->out, "%s", value ? "true" : "false");
}

static void jsonw2_wrap(jsonw_t *w)
{	
	fputc('\n', w->out);

	int level = MAX_DEPTH - w->top;
	for (int i = 0; i < level; i++) {
		fprintf(w->out, "%s", w->indent);
	}
}

static void jsonw2_end_block(jsonw_t *w)
{
	if (!w) {
		return;
	}

	assert(w->top < MAX_DEPTH);

	w->top += 1;
}

void jsonw2_str(jsonw_t *w, const char *name, const char *value)
{
	if (!w) {
		return;
	}

	struct block *top = cur_block(w);
	if (top) {
		if (top->count) {
			fputc(',', w->out);
		}
		top->count++;
	}
	
	jsonw2_wrap(w);

	if (name && strlen(name)) {
		fprintf(w->out, "\"%s\": \"%s\"", name, value);
	} else {
		fprintf(w->out, "\"%s\"", value);
	}
}


void jsonw2_ulong(jsonw_t *w, const char *name, unsigned long value)
{
	if (!w) {
		return;
	}

	struct block *top = cur_block(w);
	if (top) {
		if (top->count) {
			fputc(',', w->out);
		}
		top->count++;
	}
	
	jsonw2_wrap(w);

	if (name && strlen(name)) {
		fprintf(w->out, "\"%s\": %lu", name, value);
	} else {
		fprintf(w->out, "%lu", value);
	}
}


void jsonw2_object(jsonw_t *w, const char *name)
{
	if (!w) {
		return;
	}

	struct block *top = cur_block(w);
	if (top) {
		if (top->count) {
			fputc(',', w->out);
		}
		top->count++;
	}
	
	jsonw2_wrap(w);

	if (name && strlen(name)) {
		fprintf(w->out, "\"%s\": {", name);
	} else {
		fprintf(w->out, "{");
	}
	
	start_block(w, BLOCK_OBJECT);
}

void jsonw2_list(jsonw_t *w, const char *name)
{
	if (!w) {
		return;
	}

	struct block *top = cur_block(w);
	if (top->count) {
		fputc(',', w->out);
	}
	top->count++;
	
	jsonw2_wrap(w);

	if (name && strlen(name)) {
		fprintf(w->out, "\"%s\": [", name);
	} else {
		fprintf(w->out, "[");
	}
	
	start_block(w, BLOCK_LIST);
}


void jsonw2_end(jsonw_t *w)
{
	if (!w) {
		return;
	}

	struct block *top = cur_block(w);
	if (!top) {
		return;
	}

	jsonw2_end_block(w);
	jsonw2_wrap(w);

	switch (top->type) {
	case BLOCK_OBJECT:
		fprintf(w->out, "}");
		break;
	case BLOCK_LIST:
		fprintf(w->out, "]");
		break;
	}

}
