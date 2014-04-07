#include "dname.h"
#include "error.h"
#include "kasp.h"
#include "kasp/internal.h"
#include "path.h"
#include "shared.h"
#include "yml.h"

static int parse_zone_key(yml_node_t *key, void *data, bool *interrupt)
{
	char *id = yml_get_string(key, "id");

	fprintf(stderr, "[key] %sx\n", id);
	free(id);

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
