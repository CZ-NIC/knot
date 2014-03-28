#include <string.h>
#include <tap/basic.h>
#include <stdbool.h>

#include "binary.h"
#include "error.h"
#include "key.h"
#include "keystore.h"

/* -- mock key store ------------------------------------------------------- */

static void *test_ptr = (void *)0x42;
static dnssec_key_id_t test_id = { 0xde, 0xad, 0xc0, 0xde };
static dnssec_binary_t test_binary = { .size = 2, .data = (uint8_t []) { 0xca, 0xfe } };

static bool test_open_ok = false;
static int test_open(void **handle_ptr, const char *config)
{
	test_open_ok = (handle_ptr != NULL && strcmp(config, "hello") == 0);
	if (handle_ptr != NULL) {
		*handle_ptr = test_ptr;
	}

	return DNSSEC_EOK;
}

static bool test_close_ok = false;
static int test_close(void *handle)
{
	test_close_ok = handle == test_ptr;

	return DNSSEC_EOK;
}

static bool test_read_ok = false;
static int test_read(void *handle, const dnssec_key_id_t id, dnssec_binary_t *pem)
{
	test_read_ok = (handle == test_ptr && id &&
			dnssec_key_id_cmp(id, test_id) == 0
			&& pem == &test_binary);

	return DNSSEC_EOK;
}

static bool test_write_ok = false;
static int test_write(void *handle, const dnssec_key_id_t id, const dnssec_binary_t *pem)
{
	test_write_ok = (handle == test_ptr &&
			 id && dnssec_key_id_cmp(id, test_id) == 0 &&
			 pem == &test_binary);

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

	int r = 0;

	dnssec_keystore_t *store = NULL;
	r = dnssec_keystore_create_pkcs8_custom(&store, &custom_store, "hello");
	ok(r == DNSSEC_EOK, "dnssec_keystore_create_pkcs8_custom()");

	r = dnssec_keystore_close(store);
	ok(r == DNSSEC_EOK, "keystore_close()");

	ok(test_open_ok, "test_open() called and correct params");
	ok(test_read_ok, "test_read() called and correct params");
	ok(test_write_ok, "test_write() called and correct params");
	ok(test_close_ok, "test_close() called and correct params");

	return 0;
}
