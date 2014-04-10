#include <string.h>
#include <tap/basic.h>
#include <stdbool.h>

#include "binary.h"
#include "crypto.h"
#include "error.h"
#include "key.h"
#include "keystore.h"

/* -- mock key store ------------------------------------------------------- */

static void *test_handle = (void *)0x42;

static bool test_open_called = false;
static int test_open(void **handle_ptr, const char *config)
{
	test_open_called = (handle_ptr != NULL && strcmp(config, "hello") == 0);
	if (handle_ptr != NULL) {
		*handle_ptr = test_handle;
	}

	return DNSSEC_EOK;
}

static bool test_close_called = false;
static int test_close(void *handle)
{
	test_close_called = handle == test_handle;

	return DNSSEC_EOK;
}

static bool test_read_called = false;
static char *test_read_id = NULL;
static int test_read(void *handle, const char *id, dnssec_binary_t *pem)
{
	test_read_called = (handle == test_handle && id && pem);
	test_read_id = dnssec_keyid_copy(id);

	return DNSSEC_EOK;
}

static bool test_write_called = false;
static char *test_write_id = NULL;
static dnssec_binary_t test_write_binary = { 0 };
static int test_write(void *handle, const char *id, const dnssec_binary_t *pem)
{
	test_write_called = (handle == test_handle && id &&
			     pem && pem->size > 0 && pem->data);

	test_write_id = dnssec_keyid_copy(id);
	test_write_binary = *pem;

	return DNSSEC_EOK;
}

static const dnssec_keystore_pkcs8_functions_t custom_store = {
	.open = test_open,
	.close = test_close,
	.read = test_read,
	.write = test_write,
};

/* -- test plan ------------------------------------------------------------ */

int main(void)
{
	plan_lazy();

	dnssec_crypto_init();

	int r = 0;

	dnssec_keystore_t *store = NULL;
	r = dnssec_keystore_create_pkcs8_custom(&store, &custom_store, "hello");
	ok(r == DNSSEC_EOK, "dnssec_keystore_create_pkcs8_custom()");

	char *gen_id = NULL;
	r = dnssec_keystore_generate_key(store, DNSSEC_KEY_ALGORITHM_RSA_SHA256, 512, &gen_id);
	ok(r == DNSSEC_EOK, "dnssec_keystore_generate_key()");

	r = dnssec_keystore_close(store);
	ok(r == DNSSEC_EOK, "dnssec_keystore_close()");

	ok(test_open_called, "test_open() called");
	ok(test_read_called, "test_read() called");
	ok(test_read_id && 0, "test_read() with correct key id");
	ok(test_write_called, "test_write() called");
	ok(strcmp(test_write_id, gen_id) == 0, "test_write() with correct key id");
	ok(test_close_called, "test_close() called");

	free(gen_id);
	free(test_read_id);
	free(test_write_id);

	dnssec_crypto_cleanup();

	return 0;
}
