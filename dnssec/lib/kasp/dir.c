#include <time.h>

#include "dname.h"
#include "error.h"
#include "kasp.h"
#include "kasp/internal.h"
#include "path.h"
#include "shared.h"
#include "strtonum.h"
#include "yml.h"

#define DATE_FORMAT "%Y-%m-%d %H:%M:%S"

static int str_to_keyid(const char *string, void *_key_id)
{
	assert(string);
	assert(_key_id);
	dnssec_key_id_t *key_id = _key_id;

	return dnssec_key_id_from_string(string, *key_id);
}

/*!
 * Parse algorithm string to algorithm.
 *
 * \todo Understands only algorithm number, may also understand name, e.g. RSASHA256.
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

	*enabled = (strcasecmp(string, "true") == 0);

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

typedef struct {
	dnssec_key_id_t id;
	dnssec_key_algorithm_t algorithm;
	dnssec_binary_t public_key;
	bool is_ksk;
	time_t publish;
	time_t active;
	time_t retire;
	time_t remove;
} kasp_key_params_t;

typedef struct {
	const char *key;
	int (*parse_cb)(const char *value, void *target);
	size_t target_off;
} key_parse_line_t;

#define parse_offset(member) offsetof(kasp_key_params_t, member)

static const key_parse_line_t KEY_PARSE_LINES[] = {
	{ "id",         str_to_keyid,     parse_offset(id) },
	{ "algorithm",  str_to_algorithm, parse_offset(algorithm) },
	{ "public_key", str_to_binary,    parse_offset(public_key) },
	{ "ksk",        str_to_bool,      parse_offset(is_ksk) },
	{ "publish",    str_to_time,      parse_offset(publish) },
	{ "active",     str_to_time,      parse_offset(active) },
	{ "retire",     str_to_time,      parse_offset(retire) },
	{ "remove",     str_to_time,      parse_offset(remove) },
	{ 0 }
};

static int parse_zone_key(yml_node_t *node, void *data, bool *interrupt)
{
	kasp_key_params_t params = {};

	for (const key_parse_line_t *line = KEY_PARSE_LINES; line->key; line++) {
		char *value_str = yml_get_string(node, line->key);
		if (!value_str) {
			continue;
		}

		void *target = ((void *)&params) + line->target_off;
		int result = line->parse_cb(value_str, target);

		free(value_str);

		if (result != DNSSEC_EOK) {
			printf("invalid value for %s\n", line->key);
			break;
		}
	}

	printf("key pub size %zu algo %d ksk %s pub %zu act %zu ret %zu rem %zu\n",
	params.public_key.size,
	params.algorithm,
	params.is_ksk ? "true" : "false",
	params.publish,
	params.active,
	params.retire,
	params.remove
	);

	if (params.algorithm == 0 && params.public_key.size == 0) {
		return DNSSEC_ERROR;
	}

	dnssec_key_t *key = NULL;
	int r = dnssec_key_new(&key);
	assert(r == DNSSEC_EOK);

	dnssec_key_set_algorithm(key, params.algorithm);
	dnssec_key_set_flags(key, params.is_ksk ? 257 : 256);
	r = dnssec_key_set_pubkey(key, &params.public_key);
	assert(r == DNSSEC_EOK);

	uint16_t keytag = 0;
	dnssec_key_get_keytag(key, &keytag);
	printf("keytag %u\n", keytag);
	printf("\n");

	return DNSSEC_EOK;
}

static int parse_zone_keys(yml_node_t *root)
{
	yml_node_t keys;
	int result = yml_traverse(root, "keys", &keys);
	if (result != DNSSEC_EOK) {
		return result;
	}

	return yml_sequence_each(&keys, parse_zone_key, NULL);
}

int parse_zone_config(const char *filename)
{
	_cleanup_yml_node_ yml_node_t root = { 0 };
	int result = yml_parse_file(filename, &root);
	if (result != DNSSEC_EOK) {
		return result;
	}

	result = parse_zone_keys(&root);
	if (result != DNSSEC_EOK) {
		return result;
	}

	return DNSSEC_EOK;
}

char *zone_config_file(dnssec_kasp_t *kasp, const char *zone)
{
	assert(kasp);
	assert(zone);

	// <dir>/zone_<name>.yaml<\0>
	size_t len = strlen(kasp->path) + strlen(zone) + 12;
	char *path = malloc(len);
	if (!path) {
		return NULL;
	}

	int written = snprintf(path, len, "%s/zone_%s.yaml", kasp->path, zone);
	if (written + 1 != len) {
		free(path);
		return NULL;
	}

	return path;
}

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_kasp_open_dir(const char *path, dnssec_kasp_t **kasp_ptr)
{
	if (!path || !kasp_ptr) {
		return DNSSEC_EINVAL;
	}

	dnssec_kasp_t *kasp = calloc(1, sizeof(*kasp));
	if (!kasp) {
		return DNSSEC_ENOMEM;
	}

	kasp->path = path_normalize(path);
	if (!kasp->path) {
		free(kasp);
		return DNSSEC_NOT_FOUND;
	}

	*kasp_ptr = kasp;

	return DNSSEC_EOK;
}

_public_
void dnssec_kasp_close(dnssec_kasp_t *kasp)
{
	if (!kasp) {
		return;
	}

	free(kasp->path);
	free(kasp);
}

_public_
int dnssec_kasp_get_keys(dnssec_kasp_t *kasp, const char *_zone,
			 dnssec_kasp_key_t *keys, size_t *count)
{
	if (!kasp || !_zone || !keys || !count) {
		return DNSSEC_EINVAL;
	}

	_cleanup_free_ char *zone = dname_ascii_normalize(_zone);
	if (!zone) {
		return DNSSEC_EINVAL;
	}

	_cleanup_free_ char *config = zone_config_file(kasp, zone);
	if (!zone) {
		return DNSSEC_ENOMEM;
	}

	// TMP
	printf("zone [%s] config [%s]\n", zone, config);

	parse_zone_config(config);

	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}
