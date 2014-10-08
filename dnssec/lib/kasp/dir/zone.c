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

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include "binary.h"
#include "error.h"
#include "kasp.h"
#include "kasp/dir/escape.h"
#include "kasp/dir/json.h"
#include "kasp/zone.h"
#include "list.h"
#include "shared.h"

#define DNSKEY_KSK_FLAGS 257
#define DNSKEY_ZSK_FLAGS 256

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
static int keyset_add_dnskey(dnssec_list_t *keyset, dnssec_key_t *dnskey,
			     const dnssec_kasp_key_timing_t *timing)
{
	dnssec_kasp_key_t *kasp_key = malloc(sizeof(*kasp_key));
	if (!kasp_key) {
		return DNSSEC_ENOMEM;
	}

	clear_struct(kasp_key);
	kasp_key->key = dnskey;
	kasp_key->timing = *timing;

	int result = dnssec_list_append(keyset, kasp_key);
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

	zone->keys = dnssec_list_new();
	if (!zone->keys) {
		return DNSSEC_ENOMEM;
	}

	int result = DNSSEC_EOK;

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

		result = keyset_add_dnskey(zone->keys, dnskey, &params.timing);
		if (result != DNSSEC_EOK) {
			dnssec_key_free(dnskey);
			break;
		}
	}

	if (result != DNSSEC_EOK) {
		kasp_zone_keys_free(zone->keys);
		zone->keys = NULL;
	}

	return result;
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

	dnssec_list_foreach(item, zone->keys) {
		dnssec_kasp_key_t *kasp_key = dnssec_item_get(item);
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

/* -- internal API --------------------------------------------------------- */

/*!
 * Get zone configuration file name.
 */
char *zone_config_file(const char *dir, const char *zone_name)
{
	// escape zone name

	_cleanup_free_ char *zone_escaped = NULL;
	int r = escape_zone_name(zone_name, &zone_escaped);
	if (r != DNSSEC_EOK) {
		return NULL;
	}

	// build full path

	char *config = NULL;
	int result = asprintf(&config, "%s/zone_%s.json", dir, zone_escaped);
	if (result == -1) {
		return NULL;
	}

	return config;
}

/*!
 * Get a zone name from a config file name.
 */
char *zone_name_from_config_file(const char *basename)
{
	assert(basename);

	// basename components

	const char *prefix = "zone_";
	const char *suffix = ".json";

	size_t basename_len = strlen(basename);
	size_t prefix_len = strlen(prefix);
	size_t suffix_len = strlen(suffix);

	if (basename_len < prefix_len + suffix_len) {
		return NULL;
	}

	const char *basename_prefix = basename;
	const char *basename_name   = basename + prefix_len;
	const char *basename_suffix = basename + basename_len - suffix_len;

	size_t name_len = basename_len - suffix_len - prefix_len;

	// prefix and suffix match

	if (memcmp(basename_prefix, prefix, prefix_len) != 0 ||
	    memcmp(basename_suffix, suffix, suffix_len) != 0
	) {
		return NULL;
	}

	// unescape zone name

	_cleanup_free_ char *escaped = strndup(basename_name, name_len);
	if (!escaped) {
		return NULL;
	}

	char *name = NULL;
	int r = unescape_zone_name(escaped, &name);
	if (r != DNSSEC_EOK) {
		free(name);
		return NULL;
	}

	return name;
}

/*!
 * Load zone configuration.
 */
int load_zone_config(dnssec_kasp_zone_t *zone, const char *filename)
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
 * Save zone configuration.
 */
int save_zone_config(dnssec_kasp_zone_t *zone, const char *filename)
{
	assert(zone);
	assert(filename);

	json_t *keys = NULL;
	int r = export_zone_keys(zone, &keys);
	if (r != DNSSEC_EOK) {
		return r;
	}

	_json_cleanup_ json_t *config = json_pack("{so}", "keys", keys);
	_cleanup_fclose_ FILE *file = fopen(filename, "w");
	if (!file) {
		return DNSSEC_NOT_FOUND;
	}

	r = json_dumpf(config, file, JSON_DUMP_OPTIONS);
	fputc('\n', file);

	return (r == 0) ? DNSSEC_EOK : DNSSEC_NOT_FOUND;
}
