/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <tap/basic.h>
#include <tap/files.h>

#include "libknot/dnssec/error.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/keystore.h"

int main(void)
{
	plan_lazy();

	char *dir = test_tmpdir();
	if (!dir) {
		return 1;
	}

	// create context

	dnssec_keystore_t *store = NULL;
	int r = dnssec_keystore_init_pkcs8(&store);
	ok(r == DNSSEC_EOK, "dnssec_keystore_init_pkcs8()");

	r = dnssec_keystore_init(store, dir);
	ok(r == DNSSEC_EOK, "init");

	r = dnssec_keystore_open(store, dir);
	ok(r == DNSSEC_EOK, "open");

	// writing new content

	char *id_A = NULL;
	r = dnssec_keystore_generate(store, DNSSEC_KEY_ALGORITHM_RSA_SHA256,
	                             1024, NULL, &id_A);
	ok(r == DNSSEC_EOK, "generate A");

	char *id_B = NULL;
	r = dnssec_keystore_generate(store, DNSSEC_KEY_ALGORITHM_RSA_SHA256,
	                             1024, NULL, &id_B);
	ok(r == DNSSEC_EOK, "generate B");

	// reading existing content

	dnssec_key_t *key = NULL;
	dnssec_key_new(&key);
	dnssec_key_set_algorithm(key, DNSSEC_KEY_ALGORITHM_RSA_SHA256);
	r = dnssec_keystore_get_private(store, id_A, key);
	ok(r == DNSSEC_EOK, "read A");
	dnssec_key_free(key);

	dnssec_key_new(&key);
	dnssec_key_set_algorithm(key, DNSSEC_KEY_ALGORITHM_RSA_SHA256);
	r = dnssec_keystore_get_private(store, id_B, key);
	ok(r == DNSSEC_EOK, "read B");
	dnssec_key_free(key);

	// content removal

	r = dnssec_keystore_remove(store, id_A);
	ok(r == DNSSEC_EOK, "remove A");

	dnssec_key_new(&key);
	dnssec_key_set_algorithm(key, DNSSEC_KEY_ALGORITHM_RSA_SHA256);
	r = dnssec_keystore_get_private(store, id_A, key);
	ok(r == DNSSEC_ENOENT, "read removed");
	dnssec_key_free(key);

	// cleanup

	free(id_A);
	free(id_B);

	r = dnssec_keystore_close(store);
	ok(r == DNSSEC_EOK, "close");

	r = dnssec_keystore_deinit(store);
	ok(r == DNSSEC_EOK, "deinit");

	test_rm_rf(dir);
	free(dir);

	return 0;
}
