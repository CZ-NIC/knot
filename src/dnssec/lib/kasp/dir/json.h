/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <jansson.h>

// Compatibility with Jansson 2.3, json_array_foreach exists since 2.7
#ifndef json_array_foreach
#define json_array_foreach(array, index, value) \
	for(index = 0; \
		index < json_array_size(array) && (value = json_array_get(array, index)); \
		index++)
#endif

static inline void json_decref_ptr(json_t **json_ptr)
{
	json_decref(*json_ptr);
}

#define _json_cleanup_ _cleanup_(json_decref_ptr)

/*! Options for JSON reading. */
#define JSON_LOAD_OPTIONS JSON_REJECT_DUPLICATES

/*! Options for JSON writing. */
#define JSON_DUMP_OPTIONS JSON_INDENT(2)|JSON_PRESERVE_ORDER

int decode_ignore(const json_t *value, void *result);

int decode_keyid(const json_t *value, void *result);
int encode_keyid(const void *value, json_t **result);

int decode_uint8(const json_t *value, void *result);
int encode_uint8(const void *value, json_t **result);

int decode_uint16(const json_t *value, void *result);
int encode_uint16(const void *value, json_t **result);

int decode_uint32(const json_t *value, void *result);
int encode_uint32(const void *value, json_t **result);

int decode_binary(const json_t *value, void *result);
int encode_binary(const void *value, json_t **result);

int decode_bool(const json_t *value, void *result);
int encode_bool(const void *value, json_t **result);

int decode_time(const json_t *value, void *result);
int encode_time(const void *value, json_t **result);

int decode_string(const json_t *value, void *result);
int encode_string(const void *value, json_t **result);

/*!
 * Object attribute serialization parameters.
 */
struct encode_attr {
	const char *name;
	size_t offset;
	int (*encode)(const void *value, json_t **result);
	int (*decode)(const json_t *value, void *result);
};

typedef struct encode_attr encode_attr_t;

int encode_object(const encode_attr_t attrs[], const void *object, json_t **encoded);
int decode_object(const encode_attr_t attrs[], const json_t *encoded, void *object);
