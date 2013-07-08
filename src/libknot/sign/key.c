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

#include <config.h>
#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "binary.h"
#include "common.h"
#include "common/getline.h"
#include "dname.h"
#include "sign/key.h"
#include "sign/sig0.h"
#include "tsig.h"
#include "zscanner/scanner.h"

/*!
 * \brief Calculates keytag for RSA/MD5 algorithm.
 */
static uint16_t keytag_rsa_md5(const uint8_t *rdata, uint16_t rdata_len)
{
	uint16_t ac = 0;
	if (rdata_len > 4) {
		memmove(&ac, rdata + rdata_len - 3, 2);
	}

	ac = ntohs(ac);
	return ac;
}

/*!
 * \brief Calculates keytag from key wire.
 */
uint16_t knot_keytag(const uint8_t *rdata, uint16_t rdata_len)
{
	uint32_t ac = 0; /* assumed to be 32 bits or larger */

	if (rdata[3] == 1) {
		// different algorithm for RSA/MD5 (historical reasons)
		return keytag_rsa_md5(rdata, rdata_len);
	} else {
		for(int i = 0; i < rdata_len; i++) {
			ac += (i & 1) ? rdata[i] : rdata[i] << 8;
		}

		ac += (ac >> 16) & 0xFFFF;
		return (uint16_t)ac & 0xFFFF;
	}
}

/*!
 * \brief Acts like strndup, except it adds a suffix to duplicated string.
 */
static char *strndup_with_suffix(const char *base, int length, char *suffix)
{
	int result_length = length + strlen(suffix) + 1;
	char *result = (char *)malloc(result_length);
	if (!result)
		return NULL;

	int ret = snprintf(result, result_length, "%.*s%s", length, base, suffix);
	if (ret < 0 || ret >= result_length) {
		free(result);
		return NULL;
	}

	return result;
}

static void key_scan_noop(const scanner_t *s)
{
	UNUSED(s);
}

/*!
 * \brief Reads RR in the public key file and retrieves basic key information.
 */
static int get_key_info_from_public_key(const char *filename,
                                        knot_dname_t **name,
                                        uint16_t *keytag)
{
	if (!filename || !name || !keytag)
		return KNOT_EINVAL;

	FILE *keyfile = fopen(filename, "r");
	if (!keyfile)
		return KNOT_KEY_EPUBLIC_KEY_OPEN;

	scanner_t *scanner = scanner_create(filename);
	if (!scanner) {
		fclose(keyfile);
		return KNOT_ENOMEM;
	}

	scanner->process_record = key_scan_noop;
	scanner->process_error = key_scan_noop;
	scanner->default_ttl = 0;
	scanner->default_class = KNOT_CLASS_IN;
	scanner->zone_origin[0] = '\0';
	scanner->zone_origin_length = 1;

	char *buffer = NULL;
	size_t buffer_size;
	ssize_t read = knot_getline(&buffer, &buffer_size, keyfile);

	fclose(keyfile);

	if (read == -1) {
		scanner_free(scanner);
		return KNOT_KEY_EPUBLIC_KEY_INVALID;
	}

	if (scanner_process(buffer, buffer + read, true, scanner) != 0) {
		free(buffer);
		scanner_free(scanner);
		return KNOT_KEY_EPUBLIC_KEY_INVALID;
	}

	free(buffer);

	knot_dname_t *owner = knot_dname_new_from_wire(scanner->r_owner,
	                                               scanner->r_owner_length,
	                                               NULL);
	if (!owner) {
		scanner_free(scanner);
		return KNOT_ENOMEM;
	}

	*name = owner;
	*keytag = knot_keytag(scanner->r_data, scanner->r_data_length);

	scanner_free(scanner);

	return KNOT_EOK;
}

/*!
 * \brief Extract private and public key file names from input filename.
 *
 * If the input file name has an empty extension (ends with a dot),
 * extension 'private', or extension 'key', the appropriate filenames are
 * derived from the previous part of the string. Otherwise, just append the
 * extensions.
 */
static int get_key_filenames(const char *input, char **pubname, char **privname)
{
	assert(input);
	assert(pubname);
	assert(privname);

	char *name_end = strrchr(input, '.');
	size_t base_length;

	if (name_end && (*(name_end + 1) == '\0' ||
	                 strcmp(name_end, ".key") == 0 ||
	                 strcmp(name_end, ".private") == 0)
	) {
		base_length = name_end - input;
	} else {
		base_length = strlen(input);
	}

	*pubname = strndup_with_suffix(input, base_length, ".key");
	if (!*pubname) {
		return KNOT_ENOMEM;
	}

	*privname = strndup_with_suffix(input, base_length, ".private");
	if (!*privname) {
		free(*pubname);
		*pubname = NULL;
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

	if (value == value_end ||
	    (*value_end != '\0' && !isspace((unsigned char)(*value_end))))
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
 *
 * \todo Save some space, save base64 encoded strings as binary data.
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
	{ "Prime(p)",        key_offset(prime),            key_param_string },
	{ "Subprime(q)",     key_offset(subprime),         key_param_string },
	{ "Generator(g)",    key_offset(generator),        key_param_string },
	{ "Base(g)",         key_offset(base),             key_param_string },
	{ "Private_value(x)",key_offset(private_value),    key_param_string },
	{ "Public_value(y)", key_offset(public_value),     key_param_string },
	{ "PrivateKey",      key_offset(private_key),      key_param_string },
	{ NULL }
};

/*!
 * \brief Parse one line of key file.
 *
 * \param key_params  Key parameters to write the result into.
 * \param line        Input line pointer.
 * \param length      Input line length.
 */
static int parse_keyfile_line(knot_key_params_t *key_params,
                              char *line, size_t length)
{
	// discard line termination
	if (length > 0 && line[length - 1] == '\n') {
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
		while (isspace((unsigned char)(*value)))
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

	result = get_key_filenames(filename, &public_key, &private_key);
	if (result != KNOT_EOK) {
		return result;
	}

	knot_dname_t *name;
	uint16_t keytag;
	result = get_key_info_from_public_key(public_key, &name, &keytag);
	if (result != KNOT_EOK) {
		free(public_key);
		free(private_key);
		return result;
	}

	FILE *fp = fopen(private_key, "r");
	if (!fp) {
		free(public_key);
		free(private_key);
		knot_dname_release(name);
		return KNOT_KEY_EPRIVATE_KEY_OPEN;
	}

	key_params->name = name;
	key_params->keytag = keytag;

	char *buffer = NULL;
	size_t buffer_size = 0;
	ssize_t read;
	while((read = knot_getline(&buffer, &buffer_size, fp)) > 0) {
		if (buffer[read - 1] == '\n') {
			read -= 1;
			buffer[read] = '\0';
		}
		result = parse_keyfile_line(key_params, buffer, read);
		if (result != KNOT_EOK)
			break;
	}
	free(buffer);

	fclose(fp);
	free(public_key);
	free(private_key);

	return result;
}

static int copy_string_if_set(const char *src, char **dst)
{
	if (src != NULL) {
		*dst = strdup(src);

		if (*dst == NULL) {
			return -1;
		}
	} else {
		*dst = NULL;
	}

	return 0;
}

int knot_copy_key_params(const knot_key_params_t *src, knot_key_params_t *dst)
{
	if (src == NULL || dst == NULL) {
		return KNOT_EINVAL;
	}

	int ret = 0;

	if (src->name != NULL) {
		dst->name = knot_dname_deep_copy(src->name);
		if (dst->name == NULL) {
			ret += -1;
		}
	}

	dst->algorithm = src->algorithm;
	dst->keytag = src->keytag;

	ret += copy_string_if_set(src->secret, &dst->secret);

	ret += copy_string_if_set(src->modulus, &dst->modulus);
	ret += copy_string_if_set(src->public_exponent, &dst->public_exponent);
	ret += copy_string_if_set(src->private_exponent, &dst->private_exponent);
	ret += copy_string_if_set(src->prime_one, &dst->prime_one);
	ret += copy_string_if_set(src->prime_two, &dst->prime_two);
	ret += copy_string_if_set(src->exponent_one, &dst->exponent_one);
	ret += copy_string_if_set(src->exponent_two, &dst->exponent_two);
	ret += copy_string_if_set(src->coefficient, &dst->coefficient);

	ret += copy_string_if_set(src->prime, &dst->prime);
	ret += copy_string_if_set(src->generator, &dst->generator);
	ret += copy_string_if_set(src->subprime, &dst->subprime);
	ret += copy_string_if_set(src->base, &dst->base);
	ret += copy_string_if_set(src->private_value, &dst->private_value);
	ret += copy_string_if_set(src->public_value, &dst->public_value);

	ret += copy_string_if_set(src->private_key, &dst->private_key);

	if (ret < 0) {
		knot_free_key_params(dst);
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

/*!
 * \brief Frees the key parameters.
 */
int knot_free_key_params(knot_key_params_t *key_params)
{
	assert(key_params);

	if (key_params->name)
		knot_dname_release(key_params->name);

	free(key_params->secret);

	free(key_params->modulus);
	free(key_params->public_exponent);
	free(key_params->private_exponent);
	free(key_params->prime_one);
	free(key_params->prime_two);
	free(key_params->exponent_one);
	free(key_params->exponent_two);
	free(key_params->coefficient);

	free(key_params->prime);
	free(key_params->generator);
	free(key_params->subprime);
	free(key_params->base);
	free(key_params->private_value);
	free(key_params->public_value);

	free(key_params->private_key);

	memset(key_params, '\0', sizeof(knot_key_params_t));

	return KNOT_EOK;
}

/*!
 * \brief Get the type of the key.
 */
knot_key_type_t knot_get_key_type(const knot_key_params_t *key_params)
{
	assert(key_params);

	if (key_params->secret) {
		return KNOT_KEY_TSIG;
	}

	if (key_params->modulus || key_params->prime || key_params->private_key) {
		return KNOT_KEY_DNSSEC;
	}

	//! \todo TKEY key recognition

	return KNOT_KEY_UNKNOWN;
}

/*!
 * \brief Creates TSIG key from function arguments.
 *
 * \param name       Key name (aka owner name).
 * \param algorithm  Algorithm number.
 * \param b64secret  Shared secret encoded in Base64.
 * \param key        Output TSIG key.
 *
 * \return Error code, KNOT_EOK when succeeded.
 */
static int knot_tsig_create_key_from_args(knot_dname_t *name, int algorithm,
                                          const char *b64secret,
                                          knot_tsig_key_t *key)
{
	if (!name || !b64secret || !key)
		return KNOT_EINVAL;

	knot_binary_t secret;
	int result = knot_binary_from_base64(b64secret, &secret);

	if (result != KNOT_EOK)
		return result;

	knot_dname_retain(name);

	key->name = name;
	key->secret = secret;
	key->algorithm = algorithm;

	return KNOT_EOK;
}

/*!
 * \brief Creates TSIG key.
 */
int knot_tsig_create_key(const char *name, int algorithm,
                         const char *b64secret, knot_tsig_key_t *key)
{
	knot_dname_t *dname;
	dname = knot_dname_new_from_nonfqdn_str(name, strlen(name), NULL);
	if (!dname)
		return KNOT_ENOMEM;

	int res;
	res = knot_tsig_create_key_from_args(dname, algorithm, b64secret, key);

	knot_dname_release(dname);

	return res;
}


/*!
 * \brief Creates TSIG key from key parameters.
 */
int knot_tsig_key_from_params(const knot_key_params_t *params,
                              knot_tsig_key_t *key)
{
	if (!params)
		return KNOT_EINVAL;

	return knot_tsig_create_key_from_args(params->name, params->algorithm,
					      params->secret, key);
}

/*!
 * \brief Frees TSIG key.
 */
int knot_tsig_key_free(knot_tsig_key_t *key)
{
	if (!key)
		return KNOT_EINVAL;

	knot_dname_release(key->name);

	knot_binary_free(&key->secret);
	memset(key, '\0', sizeof(knot_tsig_key_t));

	return KNOT_EOK;
}
