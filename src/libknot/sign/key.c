/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "binary.h"
#include "common.h"
#include "common/getline_wrap.h"
#include "dname.h"
#include "sign/key.h"
#include "tsig.h"

/*!
 * \brief Acts like strndup, except it adds a suffix to duplicated string.
 */
static char *strndup_with_suffix(const char *base, int length, char *suffix)
{
	int result_length = length + strlen(suffix) + 1;
	char *result = (char *)malloc(result_length);
	if (!result)
		return NULL;

	snprintf(result, result_length, "%.*s%s", length, base, suffix);

	return result;
}

/*!
 * \brief Reads RR in the public key file and retrieves a key name.
 *
 * \note Currently we guess the key name from filename.
 * \note Expected input file name: K{name}.+{algorithm}.+{random}.public
 *
 * \todo #2360 read key name from RR record in .key file
 */
static char *get_key_name_from_public_key(const char *filename)
{
	assert(filename);

	char *begin = strrchr(filename, '/');
	if (!begin)
		begin = (char *)filename;
	else
		begin += 1;

	if (*begin == 'K')
		begin += 1;

	char *end = strstr(begin, ".+");
	if (!end)
		return NULL;

	return strndup(begin, end - begin);
}

/*!
 * \brief Extract private and public key file names from input filename.
 *
 * If the input file name has an empty extension (ends with a dot),
 * extension 'private', or extension 'public', the appropriate filenames are
 * derived from the previous part of the string. Otherwise, just append the
 * extensions.
 */
static int get_key_filenames(const char *input, char **public, char **private)
{
	assert(input);
	assert(public);
	assert(private);

	char *name_end = strrchr(input, '.');
	size_t base_length;

	if (name_end && (*(name_end + 1) == '\0' ||
			 strcmp(name_end, ".public") == 0 ||
			 strcmp(name_end, ".private") == 0)
	) {
		base_length = name_end - input;
	} else {
		base_length = strlen(input);
	}

	*public = strndup_with_suffix(input, base_length, ".public");
	if (!*public) {
		return KNOT_ENOMEM;
	}

	*private = strndup_with_suffix(input, base_length, ".private");
	if (!*private) {
		free(*public);
		*public = NULL;
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

/*!
 * \brief Handle storing of string type key parameter.
 */
static int key_param_string(const void *save_to, char *value)
{
	char **parameter = (char **)save_to;

	if (*parameter)
		free(*parameter);
	*parameter = strdup(value);

	return *parameter ? KNOT_EOK : KNOT_ENOMEM;
}

/*!
 * \brief Handle storing of algorithm type key parameter.
 */
static int key_param_int(const void *save_to, char *value)
{
	int *parameter = (int *)save_to;

	char *value_end;
	int numeric_value = strtol(value, &value_end, 10);

	if (value == value_end || (*value_end != '\0' && !isspace(*value_end)))
		return KNOT_EINVAL;

	*parameter = numeric_value;
	return KNOT_EOK;
}

/*!
 * \brief Describes private key parameter used in key_parameters.
 */
struct key_parameter {
	char *name;
	size_t offset;
	int (*handler)(const void *, char *);
};

#define key_offset(field) offsetof(knot_key_params_t, field)

/*!
 * \brief Table of know attributes in private key file.
 */
static const struct key_parameter key_parameters[] = {
	{ "Algorithm",       key_offset(algorithm),        key_param_int },
	{ "Key",             key_offset(secret),           key_param_string },
	{ "Modulus",         key_offset(modulus),          key_param_string },
	{ "PublicExponent",  key_offset(public_exponent),  key_param_string },
	{ "PrivateExponent", key_offset(private_exponent), key_param_string },
	{ "Prime1",          key_offset(prime_one),        key_param_string },
	{ "Prime2",          key_offset(prime_two),        key_param_string },
	{ "Exponent1",       key_offset(exponent_one),     key_param_string },
	{ "Exponent2",       key_offset(exponent_two),     key_param_string },
	{ "Coefficient",     key_offset(coefficient),      key_param_string },
	{ NULL }
};

/*!
 * \brief Parse one line of key file.
 *
 * \param key_params Key parameters to write the result into.
 * \param line       Input line pointer.
 * \param length     Input line length.
 */
static int parse_keyfile_line(knot_key_params_t *key_params,
                              char *line, size_t length)
{
	// discard line termination
	if (line[length - 1] == '\n') {
		line[length - 1] = '\0';
		length -= 1;
	}

	// extract attribute name
	char *separator = memchr(line, ':', length);
	if (!separator)
		return KNOT_EOK;

	// find matching attribute
	size_t name_length = separator - line;
	for (int i = 0; key_parameters[i].name != NULL; i++) {
		const struct key_parameter *current = &key_parameters[i];
		if (memcmp(current->name, line, name_length) != 0)
			continue;

		assert(current->handler);

		char *value = separator + 1;
		while (isspace(*value))
			value++;

		void *save_to = (void *)key_params + current->offset;
		return current->handler(save_to, value);
	}

	// attribute not supported or not required
	return KNOT_EOK;
}

/*!
 * \brief Reads the key file and extracts key parameters.
 */
int knot_load_key_params(const char *filename, knot_key_params_t *key_params)
{
	assert(filename);
	assert(key_params);

	int result;
	char *public_key = NULL;
	char *private_key = NULL;
	char *key_name = NULL;

	result = get_key_filenames(filename, &public_key, &private_key);
	if (result != KNOT_EOK) {
		return result;
	}

	key_name = get_key_name_from_public_key(public_key);
	if (!key_name) {
		free(public_key);
		free(private_key);
		return KNOT_ERROR; //!< \todo better error code
	}

	FILE *fp = fopen(private_key, "r");
	if (!fp) {
		free(public_key);
		free(private_key);
		free(key_name);
		return KNOT_ERROR; //!< \todo better error code
	}

	key_params->name = key_name;

	char *buffer = NULL;
	size_t read = 0;
	while ((buffer = getline_wrap(fp, &read)) != NULL && read > 0) {
		result = parse_keyfile_line(key_params, buffer, read);
		free(buffer);
		if (result != KNOT_EOK)
			break;
	}

	fclose(fp);
	free(public_key);
	free(private_key);

	return result;
}

static void free_string_if_set(char *string)
{
	if (string)
		free(string);
}

int knot_free_key_params(knot_key_params_t *key_params)
{
	assert(key_params);

	free_string_if_set(key_params->name);
	free_string_if_set(key_params->secret);
	free_string_if_set(key_params->modulus);
	free_string_if_set(key_params->public_exponent);
	free_string_if_set(key_params->private_exponent);
	free_string_if_set(key_params->prime_one);
	free_string_if_set(key_params->prime_two);
	free_string_if_set(key_params->exponent_one);
	free_string_if_set(key_params->exponent_two);
	free_string_if_set(key_params->coefficient);

	memset(key_params, '\0', sizeof(knot_key_params_t));

	return KNOT_EOK;
}

knot_key_type_t knot_get_key_type(const knot_key_params_t *key_params)
{
	assert(key_params);

	if (key_params->secret) {
		return KNOT_KEY_TSIG;
	}

	//! \todo DNSSEC key recognition

	//! \todo TKEY key recognition

	return KNOT_KEY_UNKNOWN;
}

int knot_tsig_create_key(const char *name, int algorithm,
                         const char *b64secret, knot_tsig_key_t *key)
{
	if (!name || !b64secret || !key)
		return KNOT_EINVAL;

	knot_dname_t *dname = knot_dname_new_from_nonfqdn_str(name,
	                                                      strlen(name),
							      NULL);
	if (!dname)
		return KNOT_ENOMEM;

	knot_binary_t secret;
	int result = knot_binary_from_base64(b64secret, &secret);

	if (result != KNOT_EOK) {
		knot_dname_free(&dname);
		return result;
	}

	key->name = dname;
	key->secret = secret;
	key->algorithm = algorithm;

	return KNOT_EOK;
}

int knot_tsig_key_from_params(const knot_key_params_t *params,
                              knot_tsig_key_t *key)
{
	if (!params)
		return KNOT_EINVAL;

	return knot_tsig_create_key(params->name, params->algorithm,
	                            params->secret, key);
}

int knot_tsig_key_free(knot_tsig_key_t *key)
{
	if (!key)
		return KNOT_EINVAL;

	knot_binary_free(&key->secret);
	memset(key, '\0', sizeof(knot_tsig_key_t));

	return KNOT_EOK;
}
