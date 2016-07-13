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

#include "dnssec/key.h"
#include "dnssec/tsig.h"
#include "shared/print.h"
#include "utils/keymgr/cmdparse/value.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

static void error_missing_option(const parameter_t *p)
{
	error("Missing value for option '%s'.", p->name);
}

static void error_invalid_value(const parameter_t *p, const char *value)
{
	error("Invalid value '%s' for option '%s'.", value, p->name);
}

int value_flag(int argc, char *argv[], const parameter_t *p, void *data)
{
	assert(p);
	assert(data);

	bool *flag = data + p->offset;
	*flag = true;

	return 0;
}

int value_bool(int argc, char *argv[], const parameter_t *p, void *data)
{
	assert(p);
	assert(data);

	if (argc < 1) {
		error_missing_option(p);
		return -1;
	}

	bool *value = data + p->offset;
	char *input = argv[0];

	struct value_name {
		char *value;
		bool flag;
	};

	static const struct value_name VALUE_NAMES[] = {
		{ "true", true }, { "false", false },
		{ "yes",  true }, { "no",    false },
		{ "on",   true }, { "off",   false },
		{ "t",    true }, { "f",     false },
		{ "y",    true }, { "n",     false },
		{ NULL }
	};

	for (const struct value_name *v = VALUE_NAMES; v->value; v++) {
		if (strcasecmp(v->value, input) == 0) {
			*value = v->flag;
			return 1;
		}
	}

	error_invalid_value(p, input);
	return -1;
}

int value_string(int argc, char *argv[], const parameter_t *p, void *data)
{
	assert(p);
	assert(data);

	if (argc < 1) {
		error_missing_option(p);
		return -1;
	}

	char *copy = strdup(argv[0]);
	if (!copy) {
		error("Allocation failed for '%s'.", p->name);
		return -1;
	}

	char **string = data + p->offset;
	free(*string);
	*string = copy;

	return 1;
}

int value_static_string(int argc, char *argv[], const parameter_t *p, void *data)
{
	assert(p);
	assert(data);

	if (argc < 1) {
		error_missing_option(p);
		return -1;
	}

	char **string = data + p->offset;
	*string = argv[0];

	return 1;
}

/*!
 * Skip non-alphanumerc characters and convert to lower case.
 */
static void simplify_algorithm_name(char *name)
{
	size_t len = strlen(name);

	int ri, wi;
	for (ri = 0, wi = 0; ri < len; ri++) {
		int c = name[ri];
		if (isalnum(c)) {
			name[wi] = tolower(c);
			wi += 1;
		}
	}

	name[wi] = '\0';
}

int value_algorithm(int argc, char *argv[], const parameter_t *p, void *data)
{
	assert(p);
	assert(data);

	if (argc < 1) {
		error_missing_option(p);
		return -1;
	}

	dnssec_key_algorithm_t *algorithm = data + p->offset;
	char *input = argv[0];

	// numeric value

	errno = 0;
	char *end = NULL;
	long value = strtol(input, &end, 10);
	if (*end == '\0' && errno == 0) {
		if (value <= 0 || UINT8_MAX < value) {
			error("Invalid algorithm number.");
			return -1;
		}

		*algorithm = value;
		return 1;
	}

	// name (IANA mnemonics, simplified)

	struct lookup {
		const char *name;
		dnssec_key_algorithm_t algorithm;
	};

	static const struct lookup mnemonics[] = {
		{ "dsa",              DNSSEC_KEY_ALGORITHM_DSA_SHA1  },
		{ "rsasha1",          DNSSEC_KEY_ALGORITHM_RSA_SHA1  },
		{ "dsansec3sha1",     DNSSEC_KEY_ALGORITHM_DSA_SHA1_NSEC3  },
		{ "rsasha1nsec3sha1", DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3  },
		{ "rsasha256",        DNSSEC_KEY_ALGORITHM_RSA_SHA256  },
		{ "rsasha512",        DNSSEC_KEY_ALGORITHM_RSA_SHA512  },
		{ "ecdsap256sha256",  DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256 },
		{ "ecdsap384sha384",  DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384 },
		{ NULL }
	};

	simplify_algorithm_name(input);
	for (const struct lookup *m = mnemonics; m->name; m++) {
		if (strcmp(input, m->name) == 0) {
			*algorithm = m->algorithm;
			return 1;
		}
	}

	error("Invalid value for '%s'. Use number or IANA mnemonic.", p->name);

	return -1;
}

int value_tsig_algorithm(int argc, char *argv[], const parameter_t *p, void *data)
{
	assert(p);
	assert(data);

	if (argc < 1) {
		error_missing_option(p);
		return -1;
	}

	dnssec_tsig_algorithm_t *algorithm = data + p->offset;
	char *input = argv[0];

	dnssec_tsig_algorithm_t match = dnssec_tsig_algorithm_from_name(input);
	if (match == DNSSEC_TSIG_UNKNOWN) {
		error("Invalid value for '%s'.", p->name);
		return -1;
	}

	*algorithm = match;
	return 1;
}

int value_key_size(int argc, char *argv[], const parameter_t *p, void *data)
{
	assert(p);
	assert(data);

	if (argc < 1) {
		error_missing_option(p);
		return -1;
	}

	uint16_t *key_size = data + p->offset;
	char *input = argv[0];

	errno = 0;
	char *end = NULL;
	unsigned long value = strtoul(input, &end, 10);
	if (*end != '\0' || errno != 0 || value > UINT16_MAX) {
		error("Invalid key size.");
		return -1;
	}

	*key_size = value;

	return 1;
}

static int value_uint(int argc, char *argv[], const parameter_t *p,
		      uintmax_t max, uintmax_t *value_ptr)
{
	assert(p);
	assert(value_ptr);

	if (argc < 1) {
		error_missing_option(p);
		return -1;
	}

	char *input = argv[0];

	errno = 0;
	char *end = NULL;
	uintmax_t value = strtoumax(input, &end, 10);
	if (*end != '\0' || errno != 0) {
		error_invalid_value(p, input);
		return -1;
	}

	if (value > max) {
		error_invalid_value(p, input);
		return -1;
	}

	*value_ptr = value;

	return 1;
}

#define VALUE_UINT(argc, argv, p, data, type, max) ({ \
	uintmax_t value = 0; \
	int r = value_uint((argc), (argv), (p), (max), &value); \
	if (r >= 0) { \
		assert(value <= (max)); \
		*(type *)((data) + (p)->offset) = value; \
	} \
	r; \
})

int value_uint8(int argc, char *argv[], const parameter_t *p, void *data)
{
	return VALUE_UINT(argc, argv, p, data, uint8_t, UINT8_MAX);
}

int value_uint16(int argc, char *argv[], const parameter_t *p, void *data)
{
	return VALUE_UINT(argc, argv, p, data, uint16_t, UINT16_MAX);
}

int value_uint32(int argc, char *argv[], const parameter_t *p, void *data)
{
	return VALUE_UINT(argc, argv, p, data, uint32_t, UINT32_MAX);
}

static const time_t TIME_PARSE_ERROR = -1;
static const time_t TIME_PARSE_SKIP = -2;

/*!
 * Get time multiplier for offset suffix.
 */
static time_t time_offset_suffix(const char *search)
{
	struct lookup {
		char *suffix;
		time_t value;
	};

	static const struct lookup suffixes[] = {
		{ "mi", 60 },
		{ "h",  60 * 60 },
		{ "d",  60 * 60 * 24 },
		{ "w",  60 * 60 * 24 * 7 },
		{ "mo", 60 * 60 * 24 * 30 },
		{ "y",  60 * 60 * 24 * 365 },
		{ NULL }
	};

	for (const struct lookup *s = suffixes; s->suffix; s++) {
		if (strcasecmp(search, s->suffix) == 0) {
			return s->value;
		}
	}

	return 0;
}

/*!
 * Parse time specified as (+|-)<value>[<suffix>].
 *
 * suffix can be y, mo, w, d, h, mi
 */
static time_t parse_time_offset(const char *input)
{
	if (input[0] != '+' && input[0] != '-') {
		return TIME_PARSE_SKIP;
	}

	char *suffix = NULL;
	errno = 0;
	long long offset = strtoll(input, &suffix, 10);
	if (errno == ERANGE) {
		return TIME_PARSE_ERROR;
	}

	if (*suffix != '\0') {
		time_t multiplier = time_offset_suffix(suffix);
		if (multiplier == 0) {
			return TIME_PARSE_ERROR;
		}

		offset *= multiplier;
	}

	time_t result = time(NULL) + offset;
	if (result < 0) {
		return TIME_PARSE_ERROR;
	}

	return result;
}

/*!
 * Parse BIND-like format (i.e., YYYYMMDD or YYYYMMDDHHMMSS).
 */
static time_t parse_time_bind(const char *input)
{
	const char *format = NULL;

	switch (strlen(input)) {
	case 8:
		format = "%Y%m%d";
		break;
	case 14:
		format = "%Y%m%d%H%M%S";
		break;
	default:
		return TIME_PARSE_SKIP;
	}

	struct tm tm = { 0 };
	char *end = strptime(input, format, &tm);
	if (end == NULL || *end != '\0') {
		return TIME_PARSE_ERROR;
	}

	time_t result = mktime(&tm);
	if (result < 0) {
		return TIME_PARSE_ERROR;
	}

	return result;
}

/*!
 * Parse time as a number of seconds since epoch.
 */
static time_t parse_time_epoch(const char *input)
{
	char *end = NULL;
	errno = 0;
	long long time = strtoll(input, &end, 10);
	if (errno == ERANGE || *end != '\0' || time < 0) {
		return TIME_PARSE_ERROR;
	}

	return time;
}

int value_time(int argc, char *argv[], const parameter_t *p, void *data)
{
	assert(p);
	assert(data);

	if (argc < 1) {
		error_missing_option(p);
		return -1;
	}

	time_t *result = data + p->offset;
	char *input = argv[0];

	typedef time_t (*parser_cb)(const char *input);
	static const parser_cb parsers[] = {
		parse_time_bind,
		parse_time_offset,
		parse_time_epoch,
		NULL
	};

	time_t time = TIME_PARSE_SKIP;
	for (const parser_cb *cb = parsers; *cb && time == TIME_PARSE_SKIP; cb++) {
		time = (*cb)(input);
	}

	if (time < 0) {
		error("Cannot parse time for '%s'.", p->name);
		return -1;
	}

	*result = time;

	return 1;
}
