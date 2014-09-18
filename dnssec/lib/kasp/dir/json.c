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
#include "key.h"
#include "shared.h"
#include "strtonum.h"

// ISO 8610
#define TIME_FORMAT "%Y-%m-%dT%H:%M:%S%z"

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
 * Decode unsigned 8-bit integer from JSON.
 *
 * \todo Could understand an algorithm name instead of just a number.
 */
int decode_uint8(const json_t *value, void *result)
{
	uint8_t *byte_ptr = result;

	if (!json_is_integer(value)) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	json_int_t number = json_integer_value(value);
	if (number < 0 || number > UINT8_MAX) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	*byte_ptr = number;

	return DNSSEC_EOK;
}

/*!
 * Encode unsigned 8-bit integer to JSON.
 */
int encode_uint8(const void *value, json_t **result)
{
	const uint8_t *byte_ptr = value;

	json_t *encoded = json_integer(*byte_ptr);
	if (!encoded) {
		return DNSSEC_ENOMEM;
	}

	*result = encoded;

	return DNSSEC_EOK;
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

	//! \todo replace json_pack with json_stringn (not in Jansson 2.6 yet)
	json_t *encoded = json_pack("s#", base64.data, base64.size);
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
	struct tm tm = { 0 };
	char *end = strptime(time_str, TIME_FORMAT, &tm);
	if (end == NULL || *end != '\0') {
		return DNSSEC_CONFIG_MALFORMED;
	}

	*time_ptr = timegm(&tm);

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

	struct tm tm = { 0 };
	if (!gmtime_r(time_ptr, &tm)) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	char buffer[128] = { 0 };
	int written = strftime(buffer, sizeof(buffer), TIME_FORMAT, &tm);
	if (written == 0) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	json_t *encoded = json_string(buffer);
	if (!encoded) {
		return DNSSEC_ENOMEM;
	}

	*result = encoded;

	return DNSSEC_EOK;
}
