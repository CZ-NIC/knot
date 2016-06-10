/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <ctype.h>
#include <string.h>

#include "dnssec/binary.h"
#include "dnssec/error.h"
#include "shared/shared.h"
#include "shared/strtonum.h"
#include "utils/keymgr/legacy/privkey.h"

/* -- private key params conversion ---------------------------------------- */

/*!
 * Private key attribute conversion.
 */
typedef struct param_t {
	char *name;
	size_t offset;
	int (*parse_cb)(char *string, void *data);
	void (*free_cb)(void *data);
} param_t;

static int parse_algorithm(char *string, void *_algorithm);
static int parse_binary(char *string, void *_binary);
static int parse_time(char *string, void *_time);

static void binary_free(void *_binary)
{
	dnssec_binary_t *binary = _binary;
	dnssec_binary_free(binary);
}

/*!
 * Know attributes in private key file.
 */
const param_t PRIVKEY_CONVERSION_TABLE[] = {
	#define o(field) offsetof(legacy_privkey_t, field)
	{ "Algorithm",       o(algorithm),        parse_algorithm, NULL },
	{ "Modulus",         o(modulus),          parse_binary,    binary_free },
	{ "PublicExponent",  o(public_exponent),  parse_binary,    binary_free },
	{ "PrivateExponent", o(private_exponent), parse_binary,    binary_free },
	{ "Prime1",          o(prime_one),        parse_binary,    binary_free },
	{ "Prime2",          o(prime_two),        parse_binary,    binary_free },
	{ "Exponent1",       o(exponent_one),     parse_binary,    binary_free },
	{ "Exponent2",       o(exponent_two),     parse_binary,    binary_free },
	{ "Coefficient",     o(coefficient),      parse_binary,    binary_free },
	{ "Prime(p)",        o(prime),            parse_binary,    binary_free },
	{ "Subprime(q)",     o(subprime),         parse_binary,    binary_free },
	{ "Base(g)",         o(base),             parse_binary,    binary_free },
	{ "Private_value(x)",o(private_value),    parse_binary,    binary_free },
	{ "Public_value(y)", o(public_value),     parse_binary,    binary_free },
	{ "PrivateKey",      o(private_key),      parse_binary,    binary_free },
	{ "Created",         o(time_created),     parse_time,      NULL },
	{ "Publish",         o(time_publish),     parse_time,      NULL },
	{ "Activate",        o(time_activate),    parse_time,      NULL },
	{ "Revoke",          o(time_revoke),      parse_time,      NULL },
	{ "Inactive",        o(time_inactive),    parse_time,      NULL },
	{ "Delete",          o(time_delete),      parse_time,      NULL },
	{ NULL }
	#undef o
};

/* -- attribute parsing ---------------------------------------------------- */

/*!
 * Parse key algorithm field.
 *
 * Example: 7 (NSEC3RSASHA1)
 *
 * Only the numeric value is decoded, the rest of the value is ignored.
 */
static int parse_algorithm(char *string, void *_algorithm)
{
	char *end = string;
	while (*end != '\0' && !isspace((int)*end)) {
		end += 1;
	}
	*end = '\0';

	uint8_t *algorithm = _algorithm;
	int r = str_to_u8(string, algorithm);

	return (r == DNSSEC_EOK ? DNSSEC_EOK : DNSSEC_INVALID_KEY_ALGORITHM);
}

/*!
 * Parse binary data encoded in Base64.
 *
 * Example: AQAB
 */
static int parse_binary(char *string, void *_binary)
{
	dnssec_binary_t base64 = {
		.data = (uint8_t *)string,
		.size = strlen(string)
	};

	dnssec_binary_t *binary = _binary;
	return dnssec_binary_from_base64(&base64, binary);
}

#define LEGACY_DATE_FORMAT "%Y%m%d%H%M%S"

/*!
 * Parse timestamp in a format in \ref LEGACY_DATE_FORMAT.
 *
 * Example: 20140415151855
 */
static int parse_time(char *string, void *_time)
{
	struct tm tm = { 0 };

	char *end = strptime(string, LEGACY_DATE_FORMAT, &tm);
	if (end == NULL || *end != '\0') {
		return DNSSEC_MALFORMED_DATA;
	}

	time_t *time = _time;
	*time = timegm(&tm);

	return DNSSEC_EOK;
}

/* -- key parsing ---------------------------------------------------------- */

/*!
 * Strip string value of left and right whitespaces.
 *
 * \param[in,out] value   Start of the string.
 * \param[in,out] length  Length of the string.
 *
 */
static void strip(char **value, size_t *length)
{
	// strip from left
	while (*length > 0 && isspace((int)**value)) {
		*value += 1;
		*length -= 1;
	}
	// strip from right
	while (*length > 0 && isspace((int)(*value)[*length - 1])) {
		*length -= 1;
	}
}

/*!
 * Parse one line of the private key file.
 */
static int parse_line(legacy_privkey_t *params, char *line, size_t length)
{
	assert(params);
	assert(line);

	char *separator = memchr(line, ':', length);
	if (!separator) {
		return DNSSEC_MALFORMED_DATA;
	}

	char *key = line;
	size_t key_length = separator - key;
	strip(&key, &key_length);

	char *value = separator + 1;
	size_t value_length = (line + length) - value;
	strip(&value, &value_length);

	if (key_length == 0 || value_length == 0) {
		return DNSSEC_MALFORMED_DATA;
	}

	key[key_length] = '\0';
	value[value_length] = '\0';

	for (const param_t *p = PRIVKEY_CONVERSION_TABLE; p->name != NULL; p++) {
		size_t name_length = strlen(p->name);
		if (name_length != key_length) {
			continue;
		}

		if (strcasecmp(p->name, key) != 0) {
			continue;
		}

		return p->parse_cb(value, (void *)params + p->offset);
	}

	// ignore unknown attributes

	return DNSSEC_EOK;
}

int legacy_privkey_parse(const char *filename, legacy_privkey_t *params_ptr)
{
	_cleanup_fclose_ FILE *file = fopen(filename, "r");
	if (!file) {
		return DNSSEC_NOT_FOUND;
	}

	legacy_privkey_t params = { 0 };

	_cleanup_free_ char *line = NULL;
	size_t size = 0;
	ssize_t read = 0;
	while ((read = getline(&line, &size, file)) != -1) {
		int r = parse_line(&params, line, read);
		if (r != DNSSEC_EOK) {
			legacy_privkey_free(&params);
			return r;
		}
	}

	*params_ptr = params;

	return DNSSEC_EOK;
}

/* -- freeing -------------------------------------------------------------- */

/*!
 * Free private key parameters.
 */
void legacy_privkey_free(legacy_privkey_t *params)
{
	if (!params) {
		return;
	}

	for (const param_t *p = PRIVKEY_CONVERSION_TABLE; p->name != NULL; p++) {
		if (p->free_cb) {
			p->free_cb((void *)params + p->offset);
		}
	}

	clear_struct(params);
}
