/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <tap/basic.h>

#include "error.h"
#include "key.h"
#include "keystore.h"

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
	r = dnssec_keystore_generate_key(store, DNSSEC_KEY_ALGORITHM_RSA_SHA256,
	                                 1024, &id_A);
	ok(r == DNSSEC_EOK, "generate A");

	char *id_B = NULL;
	r = dnssec_keystore_generate_key(store, DNSSEC_KEY_ALGORITHM_RSA_SHA256,
	                                 1024, &id_B);
	ok(r == DNSSEC_EOK, "generate B");

	// reading existing content

	dnssec_key_t *key = NULL;
	dnssec_key_new(&key);
	dnssec_key_set_algorithm(key, DNSSEC_KEY_ALGORITHM_RSA_SHA256);
	r = dnssec_key_import_keystore(key, store, id_A);
	ok(r == DNSSEC_EOK, "read A");
	dnssec_key_free(key);

	dnssec_key_new(&key);
	dnssec_key_set_algorithm(key, DNSSEC_KEY_ALGORITHM_RSA_SHA256);
	r = dnssec_key_import_keystore(key, store, id_B);
	ok(r == DNSSEC_EOK, "read B");
	dnssec_key_free(key);

	// content removal

	r = dnssec_keystore_remove_key(store, id_A);
	ok(r == DNSSEC_EOK, "remove A");

	dnssec_key_new(&key);
	dnssec_key_set_algorithm(key, DNSSEC_KEY_ALGORITHM_RSA_SHA256);
	r = dnssec_key_import_keystore(key, store, id_A);
	ok(r == DNSSEC_ENOENT, "read removed");

	// cleanup

	r = dnssec_keystore_close(store);
	ok(r == DNSSEC_EOK, "close");

	r = dnssec_keystore_deinit(store);
	ok(r == DNSSEC_EOK, "deinit");

	test_tmpdir_free(dir);

	return 0;
}
