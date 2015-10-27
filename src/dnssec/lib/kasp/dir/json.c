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

#include <jansson.h>
#include <string.h>
#include <time.h>

#include "error.h"
#include "kasp/dir/json.h"
#include "key.h"
#include "keyid.h"
#include "shared.h"
#include "strtonum.h"
#include "timestamp.h"

int decode_ignore(_unused_ const json_t *value, _unused_ void *result)
{
	return DNSSEC_EOK;
}

/*!
 * Decode key ID from JSON.
 */
int decode_keyid(const json_t *value, void *result)
{
	char **keyid_ptr = result;

	if (!json_is_string(value)) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	const char *value_str = json_string_value(value);
	if (!dnssec_keyid_is_valid(value_str)) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	char *keyid = dnssec_keyid_copy(value_str);
	if (!keyid) {
		return DNSSEC_ENOMEM;
	}

	*keyid_ptr = keyid;

	return DNSSEC_EOK;
}

/*!
 * Encode key ID to JSON.
 */
int encode_keyid(const void *value, json_t **result)
{
	char * const *id_ptr = value;
	json_t *encoded = json_string(*id_ptr);
	if (!encoded) {
		return DNSSEC_ENOMEM;
	}

	*result = encoded;

	return DNSSEC_EOK;
}

/*!
 * Decode bounded interger value from JSON.
 */
static int decode_int(const json_int_t min, const json_int_t max,
		      const json_t *value, json_int_t *result)
{
	if (!json_is_integer(value)) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	json_int_t number = json_integer_value(value);
	if (number < min || number > max) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	*result = number;

	return DNSSEC_EOK;
}

/*!
 * Encode bounded integer value to JSON.
 */
static int encode_int(const json_int_t min, const json_int_t max,
		      const json_int_t value, json_t **result)
{
	if (value < min || max < value) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	json_t *encoded = json_integer(value);
	if (!encoded) {
		return DNSSEC_ENOMEM;
	}

	*result = encoded;

	return DNSSEC_EOK;
}

/*!
 * Decode unsigned 8-bit integer from JSON.
 */
int decode_uint8(const json_t *value, void *result)
{
	json_int_t decoded;
	int r = decode_int(0, UINT8_MAX, value, &decoded);
	if (r != DNSSEC_EOK) {
		return r;
	}

	uint8_t *uint8_ptr = result;
	*uint8_ptr = decoded;

	return DNSSEC_EOK;
}

/*!
 * Encode unsigned 8-bit integer to JSON.
 */
int encode_uint8(const void *value, json_t **result)
{
	return encode_int(0, UINT8_MAX, *((uint8_t *)value), result);
}

/*!
 * Decode unsigned 16-bit integer from JSON.
 */
int decode_uint16(const json_t *value, void *result)
{
	json_int_t decoded;
	int r = decode_int(0, UINT16_MAX, value, &decoded);
	if (r != DNSSEC_EOK) {
		return r;
	}

	uint16_t *uint16_ptr = result;
	*uint16_ptr = decoded;

	return DNSSEC_EOK;
}

/*!
 * Encode unsigned 16-bit integer to JSON.
 */
int encode_uint16(const void *value, json_t **result)
{
	return encode_int(0, UINT16_MAX, *((uint16_t *)value), result);
}

/*!
 * Decode unsigned 32-bit integer from JSON.
 */
int decode_uint32(const json_t *value, void *result)
{
	json_int_t decoded;
	int r = decode_int(0, UINT32_MAX, value, &decoded);
	if (r != DNSSEC_EOK) {
		return r;
	}

	uint32_t *uint32_ptr = result;
	*uint32_ptr = decoded;

	return DNSSEC_EOK;
}

/*!
 * Encode unsigned 32-bit integer to JSON.
 */
int encode_uint32(const void *value, json_t **result)
{
	return encode_int(0, UINT32_MAX, *((uint32_t *)value), result);
}

/*!
 * Decode binary data storead as Base64 in JSON.
 */
int decode_binary(const json_t *value, void *result)
{
	dnssec_binary_t *binary_ptr = result;

	if (!json_is_string(value)) {
		return DNSSEC_MALFORMED_DATA;
	}

	const char *base64_str = json_string_value(value);
	dnssec_binary_t base64 = {
		.data = (uint8_t *)base64_str,
		.size = strlen(base64_str)
	};

	return dnssec_binary_from_base64(&base64, binary_ptr);
}

/*!
 * Encode binary data as Base64 to JSON.
 */
int encode_binary(const void *value, json_t **result)
{
	const dnssec_binary_t *binary_ptr = value;

	_cleanup_binary_ dnssec_binary_t base64 = { 0 };
	int r = dnssec_binary_to_base64(binary_ptr, &base64);
	if (r != DNSSEC_EOK) {
		return r;
	}

#if JANSSON_VERSION_HEX >= 0x020500
	json_t *encoded = json_pack("s#", base64.data, (int)base64.size);
#else
	char tmp[base64.size + 1];
	memcpy(tmp, base64.data, base64.size);
	tmp[base64.size] = '\0';
	json_t *encoded = json_pack("s", tmp);
#endif
	if (!encoded) {
		return DNSSEC_ENOMEM;
	}

	*result = encoded;

	return DNSSEC_EOK;
}

/*!
 * Decode boolean value from JSON.
 */
int decode_bool(const json_t *value, void *result)
{
	bool *bool_ptr = result;

	if (!json_is_boolean(value)) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	*bool_ptr = json_is_true(value);

	return DNSSEC_EOK;
}

/*!
 * Encode boolean value to JSON.
 */
int encode_bool(const void *value, json_t **result)
{
	const bool *bool_ptr = value;

	*result = *bool_ptr ? json_true() : json_false();

	return DNSSEC_EOK;
}

/*!
 * Decode time value from JSON.
 */
int decode_time(const json_t *value, void *result)
{
	time_t *time_ptr = result;

	if (!json_is_string(value)) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	const char *time_str = json_string_value(value);
	if (!timestamp_read(time_str, time_ptr)) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	return DNSSEC_EOK;
}

/*!
 * Encode time value to JSON.
 */
int encode_time(const void *value, json_t **result)
{
	const time_t *time_ptr = value;

	if (*time_ptr == 0) {
		// unset
		return DNSSEC_EOK;
	}

	char buffer[128] = { 0 };
	if (!timestamp_write(buffer, sizeof(buffer), *time_ptr)) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	json_t *encoded = json_string(buffer);
	if (!encoded) {
		return DNSSEC_ENOMEM;
	}

	*result = encoded;

	return DNSSEC_EOK;
}

/*!
 * Encode object according to attributes description.
 */
int encode_object(const encode_attr_t attrs[], const void *object, json_t **encoded_ptr)
{
	assert(attrs);
	assert(object);
	assert(encoded_ptr);

	json_t *encoded = json_object();
	if (!encoded) {
		return DNSSEC_ENOMEM;
	}

	for (const encode_attr_t *attr = attrs; attr->name != NULL; attr++) {
		const void *src = object + attr->offset;
		json_t *value = NULL;
		int r = attr->encode(src, &value);
		if (r != DNSSEC_EOK) {
			json_decref(encoded);
			return r;
		}

		if (value == NULL) {
			// missing value (valid)
			continue;
		}

		if (json_object_set_new(encoded, attr->name, value) != 0) {
			json_decref(value);
			json_decref(encoded);
			return DNSSEC_ENOMEM;
		}
	}

	*encoded_ptr = encoded;
	return DNSSEC_EOK;
}

/*!
 * Decode object according to attributes description.
 */
int decode_object(const encode_attr_t attrs[], const json_t *encoded, void *object)
{
	assert(attrs);
	assert(encoded);
	assert(object);

	if (!json_is_object(encoded)) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	for (const encode_attr_t *attr = attrs; attr->name != NULL; attr++) {
		json_t *value = json_object_get(encoded, attr->name);
		if (!value || json_is_null(value)) {
			continue;
		}

		void *dst = object + attr->offset;
		int r = attr->decode(value, dst);
		if (r != DNSSEC_EOK) {
			return r;
		}
	}

	return DNSSEC_EOK;
}
