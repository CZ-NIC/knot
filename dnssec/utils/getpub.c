#include <assert.h>
#include <dnssec/crypto.h>
#include <dnssec/error.h>
#include <dnssec/key.h>
#include <stdio.h>
#include <stdlib.h>
#include <nettle/base64.h>

#include "shared.h"
#include "strtonum.h"

static size_t file_size(FILE *file)
{
	assert(file);

	int r = fseek(file, 0, SEEK_END);
	if (r != 0) {
		return 0;
	}

	size_t size = ftell(file);

	r = fseek(file, 0, SEEK_SET);
	if (r != 0) {
		return 0;
	}

	return size;
}

static int load_pem(const char *filename, dnssec_binary_t *data)
{
	_cleanup_fclose_ FILE *file = fopen(filename, "r");
	if (file == NULL) {
		return DNSSEC_NOT_FOUND;
	}

	size_t size = file_size(file);
	if (size == 0) {
		return DNSSEC_MALFORMED_DATA;
	}

	int r = dnssec_binary_alloc(data, size);
	if (r != DNSSEC_EOK) {
		return r;
	}

	fread(data->data, data->size, 1, file);

	return DNSSEC_EOK;
}

static void liberr(const char *message, int code)
{
	fprintf(stderr, "%s: %s.\n", message, dnssec_strerror(code));
}

int main(int argc, char *argv[])
{
	if (argc != 3) {
		fprintf(stderr, "%s: <private.pem> <algorithm-number>\n", argv[0]);
		return 1;
	}

	const char *keyname = argv[1];
	uint8_t algorithm = 0;
	if (str_to_u8(argv[2], &algorithm) != DNSSEC_EOK) {
		fprintf(stderr, "Invalid alogrithm number.\n");
		return 1;
	}

	int exit_code = 1;
	dnssec_key_t *key = NULL;
	dnssec_binary_t pem = { 0 };

	dnssec_crypto_init();

	int r;

	r = load_pem(keyname, &pem);
	if (r != DNSSEC_EOK) {
		liberr("Unable to read the key", r);
		goto failed;
	}

	r = dnssec_key_new(&key);
	if (r != DNSSEC_EOK) {
		liberr("Unable to allocate key", r);
		goto failed;
	}

	r = dnssec_key_set_algorithm(key, algorithm);
	if (r != DNSSEC_EOK) {
		liberr("Unable to set algorithm", r);
		goto failed;
	}

	r = dnssec_key_load_pkcs8(key, &pem);
	if (r != DNSSEC_EOK) {
		liberr("Unable to set the private key", r);
		goto failed;
	}

	dnssec_binary_t pubkey = { 0 };
	r = dnssec_key_get_pubkey(key, &pubkey);
	if (r != DNSSEC_EOK) {
		liberr("Unable to get public key", r);
		goto failed;
	}

	size_t buffer_size = BASE64_ENCODE_RAW_LENGTH(pubkey.size);
	uint8_t *buffer = malloc(buffer_size);
	assert(buffer);

	nettle_base64_encode_raw(buffer, (unsigned long)pubkey.size, pubkey.data);

	fwrite(buffer, buffer_size, 1, stdout);
	printf("\n");

	exit_code = 0;
failed:
	dnssec_binary_free(&pem);
	dnssec_key_free(key);
	dnssec_crypto_cleanup();

	return exit_code;
}
