/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

/*!
 * Simple pretty JSON writer.
 */
struct jsonw;
typedef struct jsonw jsonw_t;

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
void jsonw_free(jsonw_t **w);

/*!
 * Write null value as JSON.
 */
void jsonw_null(jsonw_t *w, const char *key);

/*!
 * Start writing a new object.
 *
 * The following writes will represent key and value pairs respectively until
 * jsonw_end is called.
 */
void jsonw_object(jsonw_t *w, const char *key);

/*!
 * Start writing a new list.
 *
 * The following writes will represent values until jsonw_end is called.
 */
void jsonw_list(jsonw_t *w, const char *key);

/*!
 * Write string as JSON. The string will be escaped properly.
 */
void jsonw_str(jsonw_t *w, const char *key, const char *value);

/*!
 * Write string with specified length as JSON. The string will be escaped properly, including \0.
 */
void jsonw_str_len(jsonw_t *w, const char *key, const uint8_t *value, size_t len, bool quote);

/*!
 * Write unsigned long value as JSON.
 */
void jsonw_ulong(jsonw_t *w, const char *key, unsigned long value);

/*!
 * Write integer as JSON.
 */
void jsonw_int(jsonw_t *w, const char *key, int value);

/*!
 * Write double as JSON.
 */
void jsonw_double(jsonw_t *w, const char *key, double value);

/*!
 * Write boolean value as JSON.
 */
void jsonw_bool(jsonw_t *w, const char *key, bool value);

/*!
 * Write binary data encoded to HEX as JSON.
 */
void jsonw_hex(jsonw_t *w, const char *key, const uint8_t *data, size_t len);

/*!
 * Terminate in-progress object or list.
 */
void jsonw_end(jsonw_t *w);
