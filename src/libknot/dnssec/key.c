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
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libknot/descriptor.h"
#include "common/getline.h"
#include "libknot/binary.h"
#include "libknot/common.h"
#include "libknot/dname.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/sig0.h"
#include "libknot/rrtype/tsig.h"
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
	if (!rdata || rdata_len < 4) {
		return 0;
	}

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
	if (!result) {
		return NULL;
	}

	int ret = snprintf(result, result_length, "%.*s%s", length, base, suffix);
	if (ret < 0 || ret >= result_length) {
		free(result);
		return NULL;
	}

	return result;
}

static void key_scan_set_done(zs_scanner_t *s)
{
	*((bool *)s->data) = true;
}

/*!
 * \brief Reads RR in the public key file and retrieves basic key information.
 */
static int get_key_info_from_public_key(const char *filename,
                                        knot_dname_t **name,
                                        knot_binary_t *rdata)
{
	if (!filename || !name || !rdata) {
		return KNOT_EINVAL;
	}

	FILE *keyfile = fopen(filename, "r");
	if (!keyfile) {
		return KNOT_KEY_EPUBLIC_KEY_OPEN;
	}

	bool scan_done = false;

	zs_scanner_t *scanner = zs_scanner_create(".", KNOT_CLASS_IN, 0,
	                                          key_scan_set_done,
	                                          key_scan_set_done,
	                                          (void *)&scan_done);
	if (!scanner) {
		fclose(keyfile);
		return KNOT_ENOMEM;
	}

	bool last_block = false;
	char *buffer = NULL;
	size_t buffer_size;
	ssize_t read;
	int result = 0;

	while (!scan_done && !last_block && result == 0) {
		read = knot_getline(&buffer, &buffer_size, keyfile);
		if (read <= 0) {
			last_block = true;
			read = 0;
		}
		result = zs_scanner_parse(scanner, buffer, buffer + read,
		                          last_block);
	}

	free(buffer);
	fclose(keyfile);

	if (scanner->r_type != KNOT_RRTYPE_DNSKEY &&
	    scanner->r_type != KNOT_RRTYPE_KEY &&
        scanner->r_type != KNOT_RRTYPE_NSEC5KEY) {
		zs_scanner_free(scanner);
		return KNOT_KEY_EPUBLIC_KEY_INVALID;
	}

	knot_dname_t *owner = knot_dname_copy(scanner->r_owner, NULL);
	if (!owner) {
		zs_scanner_free(scanner);
		return KNOT_ENOMEM;
	}
	knot_dname_to_lower(owner);

	knot_binary_t rdata_bin = { 0 };
	result = knot_binary_from_string(scanner->r_data, scanner->r_data_length,
	                                 &rdata_bin);
	if (result != KNOT_EOK) {
		zs_scanner_free(scanner);
		knot_dname_free(&owner, NULL);
		return result;
	}

	*name = owner;
	*rdata = rdata_bin;

	zs_scanner_free(scanner);

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
 * \brief Handle storing of base64 encoded data key parameter.
 */
static int key_param_base64(const void *save_to, char *value)
{
	knot_binary_t *parameter = (knot_binary_t *)save_to;
	knot_binary_free(parameter);

	return knot_binary_from_base64(value, parameter);
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
	    (*value_end != '\0' && !isspace((unsigned char)(*value_end)))) {
		return KNOT_EINVAL;
	}

	*parameter = numeric_value;
	return KNOT_EOK;
}

/*!
 * \brief Handle storing of key lifetime parameter.
 */
static int key_param_time(const void *save_to, char *value)
{
	time_t *parameter = (time_t *)save_to;

	struct tm parsed = { 0 };

	if (!strptime(value, "%Y%m%d%H%M%S", &parsed)) {
		return KNOT_EINVAL;
	}

	*parameter = timegm(&parsed);
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
	{ "Key",             key_offset(secret),           key_param_base64 },
	{ "Modulus",         key_offset(modulus),          key_param_base64 },
	{ "PublicExponent",  key_offset(public_exponent),  key_param_base64 },
	{ "PrivateExponent", key_offset(private_exponent), key_param_base64 },
	{ "Prime1",          key_offset(prime_one),        key_param_base64 },
	{ "Prime2",          key_offset(prime_two),        key_param_base64 },
	{ "Exponent1",       key_offset(exponent_one),     key_param_base64 },
	{ "Exponent2",       key_offset(exponent_two),     key_param_base64 },
	{ "Coefficient",     key_offset(coefficient),      key_param_base64 },
	{ "Prime(p)",        key_offset(prime),            key_param_base64 },
	{ "Subprime(q)",     key_offset(subprime),         key_param_base64 },
	{ "Base(g)",         key_offset(base),             key_param_base64 },
	{ "Private_value(x)",key_offset(private_value),    key_param_base64 },
	{ "Public_value(y)", key_offset(public_value),     key_param_base64 },
	{ "PrivateKey",      key_offset(private_key),      key_param_base64 },
	{ "GostAsn1",        key_offset(private_key),      key_param_base64 },
	{ "Publish",         key_offset(time_publish),     key_param_time },
	{ "Activate",        key_offset(time_activate),    key_param_time },
	{ "Inactive",        key_offset(time_inactive),    key_param_time },
	{ "Delete",          key_offset(time_delete),      key_param_time },
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
	if (!separator) {
		return KNOT_EOK;
	}

	// find matching attribute
	size_t name_length = separator - line;
	for (int i = 0; key_parameters[i].name != NULL; i++) {
		const struct key_parameter *current = &key_parameters[i];

		if (strlen(current->name) != name_length ||
		    memcmp(current->name, line, name_length) != 0
		) {
			continue;
		}

		assert(current->handler);

		char *value = separator + 1;
		while (isspace((unsigned char)(*value))) {
			value++;
		}

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
	if (!filename || !key_params) {
		return KNOT_EINVAL;
	}

	int result;
	char *public_key = NULL;
	char *private_key = NULL;

	result = get_key_filenames(filename, &public_key, &private_key);
	if (result != KNOT_EOK) {
		return result;
	}

	knot_dname_t *name = NULL;
	knot_binary_t rdata = { 0 };
	result = get_key_info_from_public_key(public_key, &name, &rdata);
	if (result != KNOT_EOK) {
		free(public_key);
		free(private_key);
		return result;
	}

	FILE *fp = fopen(private_key, "r");
	if (!fp) {
		free(public_key);
		free(private_key);
		knot_dname_free(&name, NULL);
		return KNOT_KEY_EPRIVATE_KEY_OPEN;
	}

    //dipapadop: Hack -> test whether NSEC5 key from filename
    if (strstr(filename,"nsec5")==NULL) {
        key_params->nsec5 = 0;
    }
    else {
        key_params->nsec5 = 1;
    }
    
	key_params->name = name;
	key_params->rdata = rdata;
	key_params->keytag = knot_keytag(rdata.data, rdata.size);
	key_params->flags = knot_wire_read_u16(rdata.data);

	char *buffer = NULL;
	size_t buffer_size = 0;
	ssize_t read;
	while((read = knot_getline(&buffer, &buffer_size, fp)) > 0) {
		if (buffer[read - 1] == '\n') {
			read -= 1;
			buffer[read] = '\0';
		}
		result = parse_keyfile_line(key_params, buffer, read);
		if (result != KNOT_EOK) {
			break;
		}
	}
	free(buffer);

	fclose(fp);
	free(public_key);
	free(private_key);

	return result;
}

int knot_copy_key_params(const knot_key_params_t *src, knot_key_params_t *dst)
{
	if (src == NULL || dst == NULL) {
		return KNOT_EINVAL;
	}

	int ret = 0;

	if (src->name != NULL) {
		dst->name = knot_dname_copy(src->name, NULL);
		if (dst->name == NULL) {
			ret += -1;
		}
	}

	dst->algorithm = src->algorithm;
	dst->keytag = src->keytag;
    dst->nsec5 = src->nsec5;

	ret += knot_binary_dup(&src->secret, &dst->secret);

	ret += knot_binary_dup(&src->modulus, &dst->modulus);
	ret += knot_binary_dup(&src->public_exponent, &dst->public_exponent);
	ret += knot_binary_dup(&src->private_exponent, &dst->private_exponent);
	ret += knot_binary_dup(&src->prime_one, &dst->prime_one);
	ret += knot_binary_dup(&src->prime_two, &dst->prime_two);
	ret += knot_binary_dup(&src->exponent_one, &dst->exponent_one);
	ret += knot_binary_dup(&src->exponent_two, &dst->exponent_two);
	ret += knot_binary_dup(&src->coefficient, &dst->coefficient);

	ret += knot_binary_dup(&src->prime, &dst->prime);
	ret += knot_binary_dup(&src->subprime, &dst->subprime);
	ret += knot_binary_dup(&src->base, &dst->base);
	ret += knot_binary_dup(&src->private_value, &dst->private_value);
	ret += knot_binary_dup(&src->public_value, &dst->public_value);

	ret += knot_binary_dup(&src->private_key, &dst->private_key);

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
	if (!key_params) {
		return KNOT_EINVAL;
	}

	knot_dname_free(&key_params->name, NULL);
	knot_binary_free(&key_params->rdata);

	knot_binary_free(&key_params->secret);

	knot_binary_free(&key_params->modulus);
	knot_binary_free(&key_params->public_exponent);
	knot_binary_free(&key_params->private_exponent);
	knot_binary_free(&key_params->prime_one);
	knot_binary_free(&key_params->prime_two);
	knot_binary_free(&key_params->exponent_one);
	knot_binary_free(&key_params->exponent_two);
	knot_binary_free(&key_params->coefficient);

	knot_binary_free(&key_params->prime);
	knot_binary_free(&key_params->subprime);
	knot_binary_free(&key_params->base);
	knot_binary_free(&key_params->private_value);
	knot_binary_free(&key_params->public_value);

	knot_binary_free(&key_params->private_key);

	memset(key_params, '\0', sizeof(knot_key_params_t));

	return KNOT_EOK;
}

/*!
 * \brief Get the type of the key.
 */
knot_key_type_t knot_get_key_type(const knot_key_params_t *key_params)
{
	if (!key_params) {
		return KNOT_EINVAL;
	}

	if (key_params->secret.size > 0) {
		return KNOT_KEY_TSIG;
	}
    //dipapado: NSEC5 looks like a DNSKEY for us
	if (key_params->modulus.size > 0 ||
	    key_params->prime.size > 0 ||
	    key_params->private_key.size > 0
	) {
        if (key_params->nsec5 >0)
        { return KNOT_KEY_NSEC5; }
        else
        { return KNOT_KEY_DNSSEC; }
	}

	//! \todo TKEY key recognition

	return KNOT_KEY_UNKNOWN;
}

/*!
 * \brief Creates TSIG key.
 */
int knot_tsig_create_key(const char *name, int algorithm,
                         const char *b64secret, knot_tsig_key_t *key)
{
	if (!name || !b64secret || !key) {
		return KNOT_EINVAL;
	}

	knot_dname_t *dname;
	dname = knot_dname_from_str_alloc(name);
	if (!dname) {
		return KNOT_ENOMEM;
	}

	knot_binary_t secret;
	int result = knot_binary_from_base64(b64secret, &secret);
	if (result != KNOT_EOK) {
		knot_dname_free(&dname, NULL);
		return result;
	}

	key->name = dname;
	key->algorithm = algorithm;
	key->secret = secret;

	return KNOT_EOK;
}

/*!
 * \brief Creates TSIG key from key parameters.
 */
int knot_tsig_key_from_params(const knot_key_params_t *params,
                              knot_tsig_key_t *key)
{
	if (!params || !params->name || params->secret.size == 0) {
		return KNOT_EINVAL;
	}

	int result = knot_binary_dup(&params->secret, &key->secret);
	if (result != KNOT_EOK) {
		return result;
	}

	key->name = knot_dname_copy(params->name, NULL);

	key->algorithm = params->algorithm;

	return KNOT_EOK;
}

/*!
 * \brief Frees TSIG key.
 */
int knot_tsig_key_free(knot_tsig_key_t *key)
{
	if (!key) {
		return KNOT_EINVAL;
	}

	knot_dname_free(&key->name, NULL);
	knot_binary_free(&key->secret);
	memset(key, '\0', sizeof(knot_tsig_key_t));

	return KNOT_EOK;
}
