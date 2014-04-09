#include <stdio.h>
#include <yaml.h>

#include <dnssec/crypto.h>
#include <dnssec/error.h>
#include <dnssec/kasp.h>

static void usage(void)
{
	fprintf(stderr, "parsekey <kasp-config-dir> <zone-name>\n");
}

static void error(const char *message, int err)
{
	fprintf(stderr, "%s: %s (%d).\n", message, dnssec_strerror(err), err);
}

int main(int argc, char *argv[])
{
	if (argc != 3) {
		usage();
		return 1;
	}

	const char *kasp_dir = argv[1];
	const char *zone_name = argv[2];
	int exit_code = 1;

	dnssec_crypto_init();

	dnssec_kasp_t *kasp = NULL;
	dnssec_kasp_zone_t *zone = NULL;

	int r = dnssec_kasp_open_dir(kasp_dir, &kasp);
	if (r != DNSSEC_EOK) {
		error("dnssec_kasp_open_dir()", r);
		goto fail;
	}

	r = dnssec_kasp_get_zone(kasp, zone_name, &zone);
	if (r != DNSSEC_EOK) {
		error("dnssec_kasp_get_zone()", r);
		goto fail;
	}

	dnssec_kasp_key_t *keys = NULL;
	size_t keys_count = 0;
	r = dnssec_kasp_zone_get_keys(zone, &keys, &keys_count);
	if (r != DNSSEC_EOK) {
		error("dnssec_kasp_zone_get_keys()", r);
		goto fail;
	}

	printf("keytag  ID\n");
	for (size_t i = 0; i < keys_count; i++) {
		dnssec_key_id_t id = { 0 };
		dnssec_key_get_id(keys[i].key, id);
		char *id_str = NULL;
		dnssec_key_id_to_string(id, &id_str);

		uint16_t keytag = 0;
		dnssec_key_get_keytag(keys[i].key, &keytag);

		printf("%-6d  %s\n", keytag, id_str);
		free(id_str);
	}

	exit_code = 0;

fail:
	dnssec_kasp_free_zone(zone);
	dnssec_kasp_close(kasp);
	dnssec_crypto_cleanup();

	return exit_code;
}
