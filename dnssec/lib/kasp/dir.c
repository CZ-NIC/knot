#include <time.h>
#include <stdio.h>

#include "error.h"
#include "kasp.h"
#include "kasp/internal.h"
#include "kasp/keyset.h"
#include "kasp/zone.h"
#include "key.h"
#include "path.h"
#include "shared.h"
#include "strtonum.h"
#include "yml.h"

#define DNSKEY_KSK_FLAGS 257
#define DNSKEY_ZSK_FLAGS 256

/* -- YAML format parsing -------------------------------------------------- */

#define DATE_FORMAT "%Y-%m-%d %H:%M:%S"

/*!
 * Convert hex encoded key ID into binary key ID.
 */
static int str_to_keyid(const char *string, void *_keyid_ptr)
{
	assert(string);
	assert(_keyid_ptr);
	char **keyid_ptr = _keyid_ptr;

	if (!dnssec_keyid_is_valid(string)) {
		return DNSSEC_CONFIG_MALFORMED;
	}

	char *keyid = dnssec_keyid_copy(string);
	if (!keyid) {
		return DNSSEC_ENOMEM;
	}

	*keyid_ptr = keyid;

	return DNSSEC_EOK;
}

/*!
 * Parse algorithm string to algorithm.
 *
 * \todo Could understand an algorithm name instead of just a number.
 */
static int str_to_algorithm(const char *string, void *_algorithm)
{
	assert(string);
	assert(_algorithm);
	dnssec_key_algorithm_t *algorithm = _algorithm;

	uint8_t number = 0;
	int r = str_to_u8(string, &number);
	if (r != DNSSEC_EOK) {
		return r;
	}

	*algorithm = number;

	return DNSSEC_EOK;
}

/*!
 * Parse date to a time stamp.
 */
static int str_to_time(const char *string, void *_time)
{
	assert(string);
	assert(_time);
	time_t *time = _time;

	struct tm tm = { 0 };
	char *end = strptime(string, DATE_FORMAT, &tm);
	if (end == NULL || *end != '\0') {
		return DNSSEC_MALFORMED_DATA;
	}

	*time = timegm(&tm);

	return DNSSEC_EOK;
}

/*!
 * Parse boolean value.
 */
static int str_to_bool(const char *string, void *_enabled)
{
	assert(string);
	assert(_enabled);
	bool *enabled = _enabled;

	if (strcasecmp(string, "true") == 0) {
		*enabled = true;
	} else if (strcasecmp(string, "false") == 0) {
		*enabled = false;
	} else {
		return DNSSEC_MALFORMED_DATA;
	}

	return DNSSEC_EOK;
}

/*!
 * Parse Base 64 encoded string to binary data.
 */
static int str_to_binary(const char *string, void *_binary)
{
	assert(string);
	assert(_binary);

	dnssec_binary_t *binary = _binary;
	const dnssec_binary_t base64 = {
		.data = (uint8_t *)string,
		.size = strlen(string)
	};

	return dnssec_binary_from_base64(&base64, binary);
}

/* -- KASP key parsing ----------------------------------------------------- */

/*!
 * Key parameters as read from the KASP configuration.
 */
typedef struct {
	dnssec_key_algorithm_t algorithm;
	dnssec_binary_t public_key;
	bool is_ksk;
	char *id;
	dnssec_kasp_key_timing_t timing;
} kasp_key_params_t;

#define _cleanup_key_params_ _cleanup_(kasp_key_params_free)

/*!
 * Instruction for parsing of individual key parameters.
 */
typedef struct {
	const char *key;
	int (*parse_cb)(const char *value, void *target);
	size_t target_off;
} key_parse_line_t;

#define parse_offset(member) offsetof(kasp_key_params_t, member)

static const key_parse_line_t KEY_PARSE_LINES[] = {
	{ "algorithm",  str_to_algorithm, parse_offset(algorithm) },
	{ "public_key", str_to_binary,    parse_offset(public_key) },
	{ "ksk",        str_to_bool,      parse_offset(is_ksk) },
	{ "id",         str_to_keyid,     parse_offset(id) },
	{ "publish",    str_to_time,      parse_offset(timing.publish) },
	{ "active",     str_to_time,      parse_offset(timing.active) },
	{ "retire",     str_to_time,      parse_offset(timing.retire) },
	{ "remove",     str_to_time,      parse_offset(timing.remove) },
	{ 0 }
};

/*!
 * Parse parameters from.
 *
 * \param[in]  node    Key node in the YAML tree.
 * \param[out] params  Loaded key parameters.
 */
static int kasp_key_params_parse(yml_node_t *node, kasp_key_params_t *params)
{
	assert(params);

	for (const key_parse_line_t *line = KEY_PARSE_LINES; line->key; line++) {
		char *value_str = yml_get_string(node, line->key);
		if (!value_str) {
			continue;
		}

		void *target = ((void *)params) + line->target_off;
		int result = line->parse_cb(value_str, target);

		free(value_str);

		if (result != DNSSEC_EOK) {
			return DNSSEC_CONFIG_MALFORMED;
		}
	}

	if (params->algorithm == 0) {
		return DNSSEC_INVALID_KEY_ALGORITHM;
	}

	if (params->public_key.size == 0) {
		return DNSSEC_NO_PUBLIC_KEY;
	}

	return DNSSEC_EOK;
}

/*!
 * Free KASP key parameters.
 */
static void kasp_key_params_free(kasp_key_params_t *params)
{
	assert(params);

	free(params->id);
	dnssec_binary_free(&params->public_key);

	clear_struct(params);
}

/* -- KASP key construction ------------------------------------------------ */

static int dnssec_key_from_params(kasp_key_params_t *params, dnssec_key_t **key_ptr)
{
	assert(params);
	assert(key_ptr);

	dnssec_key_t *key = NULL;
	int result = dnssec_key_new(&key);
	if (result != DNSSEC_EOK) {
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

/* -- KASP key construction ------------------------------------------------ */

static int kasp_key_create(kasp_key_params_t *params,
			   dnssec_kasp_key_t **kasp_key_ptr)
{
	if (!params || !kasp_key_ptr) {
		return DNSSEC_EINVAL;
	}

	dnssec_key_t *key = NULL;
	int result = dnssec_key_from_params(params, &key);
	if (result != DNSSEC_EOK) {
		return result;
	}

	dnssec_kasp_key_t *kasp_key = malloc(sizeof(*kasp_key));
	if (!kasp_key) {
		dnssec_key_free(key);
		return DNSSEC_ENOMEM;
	}

	clear_struct(kasp_key);
	kasp_key->key = key;
	kasp_key->timing = params->timing;

	*kasp_key_ptr = kasp_key;

	return DNSSEC_EOK;
}

static void kasp_key_free(dnssec_kasp_key_t *kasp_key)
{
	if (!kasp_key) {
		return;
	}

	dnssec_key_free(kasp_key->key);

	free(kasp_key);
}

/* -- KASP keyset construction --------------------------------------------- */

static int load_zone_key(yml_node_t *node, void *data, _unused_ bool *interrupt)
{
	assert(node);
	assert(data);

	dnssec_kasp_zone_t *zone = data;

	// construct the key from key parameters

	_cleanup_key_params_ kasp_key_params_t params = { 0 };
	int result = kasp_key_params_parse(node, &params);
	if (result != DNSSEC_EOK) {
		return result;
	}

	dnssec_kasp_key_t *kasp_key = NULL;
	result = kasp_key_create(&params, &kasp_key);
	if (result != DNSSEC_EOK) {
		return result;
	}

	dnssec_key_set_dname(kasp_key->key, zone->dname);

	// write result

	result = dnssec_kasp_keyset_add(&zone->keys, kasp_key);
	if (result != DNSSEC_EOK) {
		kasp_key_free(kasp_key);
		return result;
	}

	return DNSSEC_EOK;
}

static int parse_zone_keys(dnssec_kasp_zone_t *zone, yml_node_t *root)
{
	assert(zone);
	assert(root);

	yml_node_t keys;
	int result = yml_traverse(root, "keys", &keys);
	if (result != DNSSEC_EOK) {
		return result;
	}

	result = yml_sequence_each(&keys, load_zone_key, zone);
	if (result != DNSSEC_EOK) {
		dnssec_kasp_keyset_empty(&zone->keys);
	}

	return result;
}

static int parse_zone_config(dnssec_kasp_zone_t *zone, const char *filename)
{
	assert(zone);
	assert(filename);

	_cleanup_yml_node_ yml_node_t root = { 0 };
	int result = yml_parse_file(filename, &root);
	if (result != DNSSEC_EOK) {
		return result;
	}

	// todo parse policy

	// todo parse repositories

	result = parse_zone_keys(zone, &root);
	if (result != DNSSEC_EOK) {
		return result;
	}

	return DNSSEC_EOK;
}

/*!
 * Load zone configuration.
 */
static int load_zone_config(const char *dir, dnssec_kasp_zone_t *zone)
{
	assert(zone);

	char *config = NULL;
	int result = asprintf(&config, "%s/zone_%s.yaml", dir, zone->name);
	if (result == -1) {
		return DNSSEC_ENOMEM;
	}

	result = parse_zone_config(zone, config);
	free(config);
	return result;
}

/* -- internal API --------------------------------------------------------- */

typedef struct kasp_dir_ctx {
	char *path;
} kasp_dir_ctx_t;

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
	if (!zone) {
		return DNSSEC_EINVAL;
	}

	assert(_ctx);
	kasp_dir_ctx_t *ctx = _ctx;

	return load_zone_config(ctx->path, zone);
}

static int kasp_dir_save_zone(dnssec_kasp_zone_t *zone, void *ctx)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static const dnssec_kasp_store_functions_t KASP_DIR_FUNCTIONS = {
	.open = kasp_dir_open,
	.close = kasp_dir_close,
	.load_zone = kasp_dir_load_zone,
	.save_zone = kasp_dir_save_zone,
};

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_kasp_open_dir(const char *path, dnssec_kasp_t **kasp_ptr)
{
	return dnssec_kasp_create(kasp_ptr, &KASP_DIR_FUNCTIONS, path);
}
