/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

static const char *DEFAULT_INDENT = "\t";

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
	w->indent = indent ? indent : DEFAULT_INDENT;
	w->top = MAX_DEPTH;

	return w;
}

void jsonw_free(jsonw_t *w)
{
	free(w);
	w = NULL;
}

static void jsonw_start(jsonw_t *w, int type)
{
	assert(w->top > 0);

	jsonw_block_t b = {
		.type = type,
		.count = 0,
	};

	w->top -= 1;
	w->stack[w->top] = b;
}

static jsonw_block_t *jsonw_cur_block(jsonw_t *w)
{
	if (w && w->top < MAX_DEPTH) {
		return &w->stack[w->top];
	}

	return NULL;
}

static size_t jsonw_wrap(jsonw_t *w)
{	
	fputc('\n', w->out);
	size_t written = 1;

	const int level = MAX_DEPTH - w->top;
	for (int i = 0; i < level; i++) {
		written += fprintf(w->out, "%s", w->indent);
	}
	return written;
}

static void jsonw_end_block(jsonw_t *w)
{
	if (!w) {
		return;
	}

	assert(w->top < MAX_DEPTH);

	w->top += 1;
}

static int jsonw_any_prep(jsonw_t *w, const char *name)
{
	if (!w) {
		return 0;
	}

	int written = 0;

	jsonw_block_t *top = jsonw_cur_block(w);
	if (top) {
		if (top->count) {
			fputc(',', w->out);
			written++;
		}
		top->count++;
	}
	
	written += jsonw_wrap(w);

	if (name && strlen(name)) {
		written += fprintf(w->out, "\"%s\": ", name);
	}
	
	return written;
}

void jsonw_str(jsonw_t *w, const char *name, const char *value)
{
	if (jsonw_any_prep(w, name)) {
		fprintf(w->out, "\"%s\"", value);
	}
}


void jsonw_ulong(jsonw_t *w, const char *name, unsigned long value)
{
	if (jsonw_any_prep(w, name)) {
		fprintf(w->out, "%lu", value);
	}
}


void jsonw_object(jsonw_t *w, const char *name)
{
	if (jsonw_any_prep(w, name)) {
		fprintf(w->out, "{");
		jsonw_start(w, BLOCK_OBJECT);
	}
}

void jsonw_list(jsonw_t *w, const char *name)
{
	if (jsonw_any_prep(w, name)) {
		fprintf(w->out, "[");
		jsonw_start(w, BLOCK_LIST);
	}
}


void jsonw_end(jsonw_t *w)
{
	if (!w) {
		return;
	}

	jsonw_block_t *top = jsonw_cur_block(w);
	if (!top) {
		return;
	}

	jsonw_end_block(w);
	jsonw_wrap(w);

	switch (top->type) {
	case BLOCK_OBJECT:
		fprintf(w->out, "}");
		break;
	case BLOCK_LIST:
		fprintf(w->out, "]");
		break;
	}

}
