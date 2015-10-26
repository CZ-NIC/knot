/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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

static bool test_handle_new_ok = false;
static int test_handle_new(void **handle_ptr)
{
	if (handle_ptr) {
		*handle_ptr = test_handle;
		test_handle_new_ok = true;
	}

	return DNSSEC_EOK;
}

static bool test_handle_free_ok = false;
static int test_handle_free(void *handle)
{
	test_handle_free_ok = (handle == test_handle);

	return DNSSEC_EOK;
}

static bool test_init_ok = false;
static int test_init(void *handle, const char *config)
{
	test_init_ok = (handle == test_handle && config && strcmp(config, "init config") == 0);

	return DNSSEC_EOK;
}

static bool test_open_ok = false;
static int test_open(void *handle, const char *config)
{
	test_open_ok = (handle == test_handle && config && strcmp(config, "open config") == 0);

	return DNSSEC_EOK;
}

static bool test_close_ok = false;
static int test_close(void *handle)
{
	test_close_ok = (handle == test_handle);

	return DNSSEC_EOK;
}

static bool test_write_ok = false;
static char *test_write_id = NULL;
static dnssec_binary_t test_write_pem = { 0 };
static int test_write(void *handle, const char *id, const dnssec_binary_t *pem)
{
	if (handle == test_handle && id && pem) {
		test_write_ok = true;
		test_write_id = dnssec_keyid_copy(id);
		dnssec_binary_dup(pem, &test_write_pem);
	}

	return DNSSEC_EOK;
}

static bool test_read_ok = false;
static char *test_read_id = NULL;
static int test_read(void *handle, const char *id, dnssec_binary_t *pem)
{
	if (handle == test_handle && id && pem) {
		test_read_ok = true;
		test_read_id = dnssec_keyid_copy(id);
		dnssec_binary_dup(&test_write_pem, pem);
	}

	return DNSSEC_EOK;
}

static bool test_list_ok = false;
static int test_list(void *handle, dnssec_list_t **list_ptr)
{
	if (handle == test_handle && list_ptr) {
		test_list_ok = true;
	}

	*list_ptr = dnssec_list_new();

	return DNSSEC_EOK;
}

static bool test_remove_ok = false;
static char *test_remove_id = NULL;
static int test_remove(void *handle, const char *id)
{
	test_remove_ok = (handle == test_handle && id);
	test_remove_id = dnssec_keyid_copy(id);

	return DNSSEC_EOK;
}

static const dnssec_keystore_pkcs8_functions_t test_store = {
	.handle_new  = test_handle_new,
	.handle_free = test_handle_free,
	.init        = test_init,
	.open        = test_open,
	.close       = test_close,
	.read        = test_read,
	.write       = test_write,
	.list        = test_list,
	.remove      = test_remove,
};

/* -- test plan ------------------------------------------------------------ */

int main(void)
{
	plan_lazy();

	dnssec_crypto_init();

	int r = 0;

	// create/init/open

	dnssec_keystore_t *store = NULL;
	r = dnssec_keystore_init_pkcs8_custom(&store, &test_store);
	ok(r == DNSSEC_EOK, "dnssec_keystore_init_pkcs8_custom()");
	ok(test_handle_new_ok, "test_handle_new_ok() called");

	r = dnssec_keystore_init(store, "init config");
	ok(r == DNSSEC_EOK, "dnssec_keystore_init()");
	ok(test_init_ok, "test_init() called");

	r = dnssec_keystore_open(store, "open config");
	ok(r == DNSSEC_EOK && test_open_ok, "dnssec_keystore_open()");
	ok(test_open_ok, "test_open() called");

	// write

	char *gen_id = NULL;
	r = dnssec_keystore_generate_key(store, DNSSEC_KEY_ALGORITHM_RSA_SHA256, 512, &gen_id);
	ok(r == DNSSEC_EOK, "dnssec_keystore_generate_key()");
	ok(test_write_ok, "test_write() called");
	is_string(gen_id, test_write_id, "test_write() correct key ID");

	// read

	dnssec_key_t *key = NULL;
	dnssec_key_new(&key);
	dnssec_key_set_algorithm(key, DNSSEC_KEY_ALGORITHM_RSA_SHA256);
	r = dnssec_key_import_keystore(key, store, gen_id);
	ok(r == DNSSEC_EOK, "dnssec_key_import_keystore()");
	ok(test_read_ok, "test_read() called");
	is_string(gen_id, test_read_id, "test_read() correct key ID");
	dnssec_key_free(key);

	// remove

	r = dnssec_keystore_remove_key(store, gen_id);
	ok(r == DNSSEC_EOK, "dnssec_keystore_remove_key()");
	ok(test_remove_ok, "test_remove() called");
	is_string(gen_id, test_remove_id, "test_remove() correct key ID");

	// close

	r = dnssec_keystore_close(store);
	ok(r == DNSSEC_EOK, "dnssec_keystore_clse()");
	ok(test_close_ok, "test_close() called");

	// list

	dnssec_list_t *list = NULL;
	r = dnssec_keystore_list_keys(store, &list);
	ok(r == DNSSEC_EOK, "dnssec_keystore_list_keys()");
	ok(test_list_ok, "test_list() called");
	ok(list && dnssec_list_size(list) == 0, "dnssec_list() correct output");
	dnssec_list_free(list);

	// cleanup

	dnssec_keystore_deinit(store);
	ok(test_handle_free_ok, "test_handle_free() called");

	dnssec_crypto_cleanup();

	free(gen_id);
	free(test_write_id);
	dnssec_binary_free(&test_write_pem);
	free(test_read_id);
	free(test_remove_id);

	return 0;
}
