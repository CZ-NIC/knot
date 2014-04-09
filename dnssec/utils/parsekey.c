#include <stdio.h>
#include <yaml.h>

#include <dnssec/crypto.h>
#include <dnssec/error.h>
#include <dnssec/kasp.h>

static void usage(void)
{
	fprintf(stderr, "parsekey <kasp-config-dir> <zone-name>\n");
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
	int r = dnssec_kasp_open_dir(kasp_dir, &kasp);
	if (r != DNSSEC_EOK) {
		fprintf(stderr, "dnssec_kasp_open_dir(): %s\n", dnssec_strerror(r));
		goto fail;
	}

	dnssec_kasp_zone_t *zone = NULL;
	r = dnssec_kasp_get_zone(kasp, zone_name, &zone);
	if (r != DNSSEC_EOK) {
		fprintf(stderr, "dnssec_kasp_get_zone(): %s\n", dnssec_strerror(r));
		goto fail;
	}

	fprintf(stderr, "success\n");
	dnssec_kasp_free_zone(zone);

	exit_code = 0;

fail:
	dnssec_kasp_close(kasp);
	dnssec_crypto_cleanup();

	return exit_code;
}
