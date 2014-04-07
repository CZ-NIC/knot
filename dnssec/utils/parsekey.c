#include <stdio.h>
#include <yaml.h>

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

	dnssec_kasp_t *kasp = NULL;
	int r = dnssec_kasp_open_dir(kasp_dir, &kasp);
	if (r != DNSSEC_EOK) {
		return 1;
	}

	dnssec_kasp_key_t keys = {0};
	size_t count;
	r = dnssec_kasp_get_keys(kasp, zone_name, &keys, &count);
	if (r != DNSSEC_EOK) {
		dnssec_kasp_close(kasp);
		return 1;
	}

	dnssec_kasp_close(kasp);

	return 0;
}
