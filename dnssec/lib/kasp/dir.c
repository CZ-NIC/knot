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
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "dname.h"
#include "error.h"
#include "kasp.h"
#include "kasp/internal.h"
#include "kasp/keyset.h"
#include "kasp/zone.h"
#include "key.h"
#include "path.h"
#include "shared.h"
#include "strtonum.h"

// ISO 8610
#define TIME_FORMAT "%Y-%m-%dT%H:%M:%S%z"

#define DNSKEY_KSK_FLAGS 257
#define DNSKEY_ZSK_FLAGS 256

#define JSON_LOAD_OPTIONS JSON_REJECT_DUPLICATES
#define JSON_DUMP_OPTIONS JSON_INDENT(2)|JSON_PRESERVE_ORDER

static void json_decref_ptr(json_t **json_ptr)
{
	json_decref(*json_ptr);
}

#define _json_cleanup_ _cleanup_(json_decref_ptr)

/* -- variable types decoding ---------------------------------------------- */

/*!
 * Decode key ID from JSON.
 */
static int decode_keyid(const json_t *value, void *result)
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

static int encode_keyid(const void *value, json_t **result)
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
 * Decode algorithm from JSON.
 *
 * \todo Could understand an algorithm name instead of just a number.
 */
static int decode_uint8(const json_t *value, void *result)
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

static int encode_uint8(const void *value, json_t **result)
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
 * Decode binary data storead as base64 in JSON.
 */
static int decode_binary(const json_t *value, void *result)
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

static int encode_binary(const void *value, json_t **result)
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
static int decode_bool(const json_t *value, void *result)
{
	bool *bool_ptr = result;

	if (!json_is_boolean(value)) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	*bool_ptr = json_is_true(value);

	return DNSSEC_EOK;
}

static int encode_bool(const void *value, json_t **result)
{
	const bool *bool_ptr = value;

	*result = *bool_ptr ? json_true() : json_false();

	return DNSSEC_EOK;
}

/*!
 * Decode time value from JSON.
 */
static int decode_time(const json_t *value, void *result)
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

static int encode_time(const void *value, json_t **result)
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

/* -- key parameters ------------------------------------------------------- */

/*!
 * Key parameters as writting in zone config file.
 */
struct key_params {
	char *id;
	uint8_t algorithm;
	dnssec_binary_t public_key;
	bool is_ksk;
	dnssec_kasp_key_timing_t timing;
};

typedef struct key_params key_params_t;

/*!
 * Free allocated key parameters and clear the structure.
 */
static void key_params_free(key_params_t *params)
{
	assert(params);

	free(params->id);
	dnssec_binary_free(&params->public_key);

	clear_struct(params);
}

#define _cleanup_key_params_ _cleanup_(key_params_free)

/*!
 * Instruction for parsing of individual key parameters.
 */
struct key_params_field {
	const char *key;
	size_t offset;
	int (*encode_cb)(const void *value, json_t **result);
	int (*decode_cb)(const json_t *value, void *result);
};

typedef struct key_params_field key_params_field_t;

static const key_params_field_t KEY_PARAMS_FIELDS[] = {
	#define off(member) offsetof(key_params_t, member)
	{ "id",         off(id),             encode_keyid,  decode_keyid  },
	{ "algorithm",  off(algorithm),      encode_uint8,  decode_uint8  },
	{ "public_key", off(public_key),     encode_binary, decode_binary },
	{ "ksk",        off(is_ksk),         encode_bool,   decode_bool   },
	{ "publish",    off(timing.publish), encode_time,   decode_time   },
	{ "active",     off(timing.active),  encode_time,   decode_time   },
	{ "retire",     off(timing.retire),  encode_time,   decode_time   },
	{ "remove",     off(timing.remove),  encode_time,   decode_time   },
	{ 0 }
	#undef off
};

/* -- configuration loading ------------------------------------------------ */

/*!
 * Parse key parameters from JSON object.
 */
static int parse_key(json_t *key, key_params_t *params)
{
	if (!json_is_object(key)) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	const key_params_field_t *field;
	for (field = KEY_PARAMS_FIELDS; field->key != NULL; field++) {
		json_t *value = json_object_get(key, field->key);
		if (!value || json_is_null(value)) {
			continue;
		}

		void *dest = ((void *)params) + field->offset;
		int r = field->decode_cb(value, dest);
		if (r != DNSSEC_EOK) {
			return r;
		}
	}

	return DNSSEC_EOK;
}

/*!
 * Check if key parameters allow to create a key.
 */
static int key_params_check(key_params_t *params)
{
	assert(params);

	if (params->algorithm == 0) {
		return DNSSEC_INVALID_KEY_ALGORITHM;
	}

	if (params->public_key.size == 0) {
		return DNSSEC_NO_PUBLIC_KEY;
	}

	return DNSSEC_EOK;
}

/*!
 * Create DNSKEY from parameters.
 */
static int create_dnskey(const uint8_t *dname, key_params_t *params,
			 dnssec_key_t **key_ptr)
{
	assert(dname);
	assert(params);
	assert(key_ptr);

	int result = key_params_check(params);
	if (result != DNSSEC_EOK) {
		return result;
	}

	// create key

	dnssec_key_t *key = NULL;
	result = dnssec_key_new(&key);
	if (result != DNSSEC_EOK) {
		return result;
	}

	// set key parameters

	result = dnssec_key_set_dname(key, dname);
	if (result != DNSSEC_EOK) {
		dnssec_key_free(key);
		return result;
	}

	dnssec_key_set_algorithm(key, params->algorithm);

	uint16_t flags = params->is_ksk ? DNSKEY_KSK_FLAGS : DNSKEY_ZSK_FLAGS;
	dnssec_key_set_flags(key, flags);

	result = dnssec_key_set_pubkey(key, &params->public_key);
	if (result != DNSSEC_EOK) {
		dnssec_key_free(key);
		return result;
	}

	// validate key ID

	const char *key_id = dnssec_key_get_id(key);
	if (!key_id) {
		dnssec_key_free(key);
		return DNSSEC_INVALID_PUBLIC_KEY;
	}

	if (!dnssec_keyid_equal(params->id, key_id)) {
		dnssec_key_free(key);
		return DNSSEC_INVALID_KEY_ID;
	}

	*key_ptr = key;

	return DNSSEC_EOK;
}

/*!
 * Add DNSKEY into a keyset.
 */
static int keyset_add_dnskey(dnssec_kasp_keyset_t *keyset,
			     dnssec_key_t *dnskey,
			     const dnssec_kasp_key_timing_t *timing)
{
	dnssec_kasp_key_t *kasp_key = malloc(sizeof(*kasp_key));
	if (!kasp_key) {
		return DNSSEC_ENOMEM;
	}

	clear_struct(kasp_key);
	kasp_key->key = dnskey;
	kasp_key->timing = *timing;

	int result = dnssec_kasp_keyset_add(keyset, kasp_key);
	if (result != DNSSEC_EOK) {
		free(kasp_key);
	}

	return result;
}

/*!
 * Load zone keys.
 */
static int load_zone_keys(dnssec_kasp_zone_t *zone, json_t *keys)
{
	if (!keys) {
		return DNSSEC_NO_PUBLIC_KEY;
	}

	if (!json_is_array(keys)) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	int result = DNSSEC_EOK;

	dnssec_kasp_keyset_init(&zone->keys);

	int index;
	json_t *key;
	json_array_foreach(keys, index, key) {
		_cleanup_key_params_ key_params_t params = { 0 };

		result = parse_key(key, &params);
		if (result != DNSSEC_EOK) {
			break;
		}

		dnssec_key_t *dnskey = NULL;
		result = create_dnskey(zone->dname, &params, &dnskey);
		if (result != DNSSEC_EOK) {
			break;
		}

		result = keyset_add_dnskey(&zone->keys, dnskey, &params.timing);
		if (result != DNSSEC_EOK) {
			dnssec_key_free(dnskey);
			break;
		}
	}

	if (result != DNSSEC_EOK) {
		dnssec_kasp_keyset_empty(&zone->keys);
	}

	return result;
}

/*!
 * Load zone configuration.
 */
static int load_zone_config(dnssec_kasp_zone_t *zone, const char *filename)
{
	assert(zone);
	assert(filename);

	FILE *file = fopen(filename, "r");
	if (!file) {
		return DNSSEC_NOT_FOUND;
	}

	json_error_t error = { 0 };
	_json_cleanup_ json_t *config = json_loadf(file, JSON_LOAD_OPTIONS, &error);
	fclose(file);
	if (!config) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	json_t *config_keys = json_object_get(config, "keys");
	return load_zone_keys(zone, config_keys);
}

/*!
 * Convert KASP key parameters to JSON.
 */
static int export_key(const key_params_t *params, json_t **key_ptr)
{
	assert(params);
	assert(key_ptr);

	json_t *key = json_object();
	if (!key) {
		return DNSSEC_ENOMEM;
	}

	const key_params_field_t *field;
	for (field = KEY_PARAMS_FIELDS; field->key != NULL; field++) {
		const void *src = ((void *)params) + field->offset;
		json_t *encoded = NULL;
		int r = field->encode_cb(src, &encoded);
		if (r != DNSSEC_EOK) {
			json_decref(key);
			return r;
		}

		if (encoded == NULL) {
			// missing value (valid)
			continue;
		}

		if (json_object_set_new(key, field->key, encoded) != 0) {
			json_decref(encoded);
			json_decref(key);
			return DNSSEC_ENOMEM;
		}
	}

	*key_ptr = key;

	return DNSSEC_EOK;
}

/*!
 * Convert KASP key to serializable parameters.
 */
static void key_to_params(dnssec_kasp_key_t *key, key_params_t *params)
{
	assert(key);
	assert(params);

	params->id = (char *)dnssec_key_get_id(key->key);
	dnssec_key_get_pubkey(key->key, &params->public_key);
	params->algorithm = dnssec_key_get_algorithm(key->key);
	params->is_ksk = dnssec_key_get_flags(key->key) == DNSKEY_KSK_FLAGS;
	params->timing = key->timing;
}

/*!
 * Convert KASP keys to JSON array.
 */
static int export_zone_keys(dnssec_kasp_zone_t *zone, json_t **keys_ptr)
{
	json_t *keys = json_array();
	if (!keys) {
		return DNSSEC_ENOMEM;
	}

	int keys_count = dnssec_kasp_keyset_count(&zone->keys);
	for (int i = 0; i < keys_count; i++) {
		dnssec_kasp_key_t *kasp_key = dnssec_kasp_keyset_at(&zone->keys, i);
		key_params_t params = { 0 };
		key_to_params(kasp_key, &params);

		json_t *key = NULL;
		int r = export_key(&params, &key);
		if (r != DNSSEC_EOK) {
			json_decref(keys);
			return r;
		}

		if (json_array_append_new(keys, key)) {
			json_decref(key);
			json_decref(keys);
			return DNSSEC_ENOMEM;
		}
	}

	*keys_ptr = keys;

	return DNSSEC_EOK;
}

/*!
 * Save zone configuration.
 */
static int save_zone_config(dnssec_kasp_zone_t *zone, const char *filename)
{
	assert(zone);
	assert(filename);

	json_t *keys = NULL;
	int r = export_zone_keys(zone, &keys);
	if (r != DNSSEC_EOK) {
		return r;
	}

	_json_cleanup_ json_t *config = json_pack("{so}", "keys", keys);
	_cleanup_fclose_ FILE *file = fopen(filename, "r");
	if (!file) {
		return DNSSEC_NOT_FOUND;
	}

	r = json_dumpf(config, file, JSON_DUMP_OPTIONS);
	fputc('\n', file);

	return (r == 0) ? DNSSEC_EOK : DNSSEC_NOT_FOUND;
}

/*!
 * Get zone configuration file name.
 */
static char *zone_config_file(const char *dir, const char *zone_name)
{
	// replace slashes with underscores

	_cleanup_free_ char *name = strdup(zone_name);
	for (char *scan = name; *scan != '\0'; scan++) {
		if (*scan == '/') {
			*scan = '_';
		}
	}

	// build full path

	char *config = NULL;
	int result = asprintf(&config, "%s/zone_%s.json", dir, name);
	if (result == -1) {
		return NULL;
	}

	return config;
}

/* -- internal API --------------------------------------------------------- */

typedef struct kasp_dir_ctx {
	char *path;
} kasp_dir_ctx_t;

#define KASP_DIR_INIT_MODE (S_IRWXU | S_IRGRP|S_IXGRP)

static int kasp_dir_init(const char *config)
{
	assert(config);

	// existing directory is no-op

	_cleanup_close_ int fd = open(config, O_RDONLY);
	if (fd != -1) {
		struct stat stat = { 0 };
		if (fstat(fd, &stat) == -1) {
			return dnssec_errno_to_error(errno);
		}

		if (!S_ISDIR(stat.st_mode)) {
			return dnssec_errno_to_error(ENOTDIR);
		}

		// TODO: maybe check if the directory is empty?

		return DNSSEC_EOK;
	}

	// create directory

	int r = mkdir(config, KASP_DIR_INIT_MODE);
	if (r != 0) {
		return dnssec_errno_to_error(errno);
	}

	return DNSSEC_EOK;
}

static int kasp_dir_open(void **ctx_ptr, const char *config)
{
	assert(ctx_ptr);
	assert(config);

	kasp_dir_ctx_t *ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		return DNSSEC_ENOMEM;
	}

	clear_struct(ctx);
	ctx->path = path_normalize(config);
	if (!ctx->path) {
		free(ctx);
		return DNSSEC_NOT_FOUND;
	}

	*ctx_ptr = ctx;
	return DNSSEC_EOK;
}

static void kasp_dir_close(void *_ctx)
{
	assert(_ctx);

	kasp_dir_ctx_t *ctx = _ctx;

	free(ctx->path);
	free(ctx);
}

static int kasp_dir_load_zone(dnssec_kasp_zone_t *zone, void *_ctx)
{
	assert(zone);
	assert(_ctx);

	kasp_dir_ctx_t *ctx = _ctx;

	_cleanup_free_ char *config = zone_config_file(ctx->path, zone->name);
	if (!config) {
		return DNSSEC_ENOMEM;
	}

	return load_zone_config(zone, config);
}

static int kasp_dir_save_zone(dnssec_kasp_zone_t *zone, void *_ctx)
{
	assert(zone);
	assert(_ctx);

	kasp_dir_ctx_t *ctx = _ctx;

	_cleanup_free_ char *config = zone_config_file(ctx->path, zone->name);
	if (!config) {
		return DNSSEC_ENOMEM;
	}

	return save_zone_config(zone, config);
}

static const dnssec_kasp_store_functions_t KASP_DIR_FUNCTIONS = {
	.init = kasp_dir_init,
	.open = kasp_dir_open,
	.close = kasp_dir_close,
	.load_zone = kasp_dir_load_zone,
	.save_zone = kasp_dir_save_zone,
};

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_kasp_init_dir(dnssec_kasp_t **kasp_ptr)
{
	return dnssec_kasp_create(kasp_ptr, &KASP_DIR_FUNCTIONS);
}
