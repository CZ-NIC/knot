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

#pragma once


#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#define MAX_DEPTH 8
/*!
 * Simple pretty JSON writer.
 */

enum {
	BLOCK_INVALID = 0,
	BLOCK_OBJECT,
	BLOCK_LIST,
};

/*! One indented block of JSON. */
struct block {
	//! Block type.
	int type;

	//! Number of elements written.
	int count;
};

typedef struct jsonw {
	//! Output file stream.
	FILE *out;
	//! Indentaiton string.
	const char *indent;

	//! List to be used as a stack of blocks in progress.
	struct block stack[MAX_DEPTH];
	//! Index pointing to the top of the stack.
	int top;
} jsonw_t;

/*!
 * Create new JSON writer.
 *
 * @param out     Output file stream.
 * @param indent  Indentation string.
 *
 * @return JSON writer or NULL for allocation error.
 */
jsonw_t *jsonw_new(FILE *out, const char *indent);

/*!
 * Free JSON writer created with jsonw_new.
 */
void jsonw_free(jsonw_t *w);

/*!
 * Start writing a new object.
 *
 * The following writes will represent key and value pairs respectively until
 * jsonw_end is called.
 */
void jsonw_object(jsonw_t *w);

/*!
 * Start writing a new list.
 *
 * The following writes will represent values until jsonw_end is called.
 */
void jsonw_list(jsonw_t *w);

/*!
 * Terminate in-progress object or list.
 */
void jsonw_end(jsonw_t *w);

/*!
 * Write string as JSON. The string will be escaped properly.
 */
void jsonw_str(jsonw_t *w, const char *value);

/*!
 * Write integer as JSON.
 */
void jsonw_int(jsonw_t *w, int value);

/*!
 * Write integer as JSON.
 */
void jsonw_ulong(jsonw_t *w, unsigned long value);

/*!
 * Write boolean value as JSON.
 */
void jsonw_bool(jsonw_t *w, bool value);
