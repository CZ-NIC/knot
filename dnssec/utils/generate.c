#include <assert.h>
#include <stdio.h>

#include <dnssec/crypto.h>
#include <dnssec/error.h>
#include <dnssec/key.h>
#include <dnssec/keystore.h>

static void usage(void)
{
	fprintf(stderr, "usage: generate <storage-dir>\n");
}

int main(int argc, char *argv[])
{
	int exit_status = 1;
	int r = 0;

	if (argc != 2) {
		usage();
		return 1;
	}

	const char *storage_dir = argv[1];

	dnssec_crypto_init();

	dnssec_keystore_t *keystore = NULL;
	r = dnssec_keystore_create_pkcs8_dir(&keystore, storage_dir);
	if (r != DNSSEC_EOK) {
		fprintf(stderr, "Cannot open key store (%s).\n", dnssec_strerror(r));
		goto fail;
	}

	char *key_id = NULL;
	r = dnssec_keystore_generate_key(keystore, DNSSEC_KEY_ALGORITHM_RSA_SHA256, 2048, &key_id);
	if (r != DNSSEC_EOK) {
		fprintf(stderr, "Cannot generate key (%s).\n", dnssec_strerror(r));
		goto fail;
	}

	fprintf(stderr, "Generated key id: %s\n", key_id);
	free(key_id);

	exit_status = 0;

fail:
	dnssec_keystore_close(keystore);
	dnssec_crypto_cleanup();

	return exit_status;
}
