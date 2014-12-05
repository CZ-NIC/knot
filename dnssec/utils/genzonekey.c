#include <assert.h>
#include <stdio.h>
#include <dnssec/error.h>
#include <dnssec/kasp.h>
#include <dnssec/keystore.h>

int main(int argc, char *argv[])
{
	if (argc != 3) {
		fprintf(stderr, "usage: %s <keydir> <zone>\n", argv[0]);
		return 1;
	}

	char *kasp_path = argv[1];
	char *keystore_path = NULL;
	asprintf(&keystore_path, "%s/keys", kasp_path);
	char *zone_name = argv[2];

	int r;

	dnssec_kasp_t *kasp = NULL;
	r = dnssec_kasp_init_dir(&kasp);
	assert(r == DNSSEC_EOK);

	r = dnssec_kasp_open(kasp, kasp_path);
	assert(r == DNSSEC_EOK);

	dnssec_kasp_zone_t *zone = NULL;
	r = dnssec_kasp_zone_load(kasp, zone_name, &zone);
	assert(r == DNSSEC_EOK);

	dnssec_keystore_t *store = NULL;
	r = dnssec_keystore_init_pkcs8_dir(&store);
	assert(r == DNSSEC_EOK);

	r = dnssec_keystore_open(store, keystore_path);
	assert(r == DNSSEC_EOK);

	char *key_id = NULL;
	dnssec_keystore_generate_key(store, DNSSEC_KEY_ALGORITHM_RSA_SHA256, 512, &key_id);

	dnssec_key_t *dnskey = NULL;
	dnssec_key_new(&dnskey);
	assert(dnskey);

	r = dnssec_key_import_keystore(dnskey, store, key_id, DNSSEC_KEY_ALGORITHM_RSA_SHA256);
	assert(r == DNSSEC_EOK);

	dnssec_list_t *keys = dnssec_kasp_zone_get_keys(zone);
	assert(keys);

	dnssec_kasp_key_t *new_key = calloc(1, sizeof(*new_key));
	assert(new_key);

	new_key->key = dnskey;
	dnssec_list_append(keys, new_key);

	r = dnssec_kasp_zone_save(kasp, zone);
	assert(r == DNSSEC_EOK);

	free(key_id);
	dnssec_keystore_close(store);
	dnssec_keystore_deinit(store);
	dnssec_kasp_zone_free(zone);
	dnssec_kasp_close(kasp);
	dnssec_kasp_deinit(kasp);
	free(keystore_path);

	return 0;
}
