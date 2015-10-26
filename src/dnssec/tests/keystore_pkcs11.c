/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>

#include "dnssec/crypto.h"
#include "dnssec/error.h"
#include "dnssec/keystore.h"

int main(int argc, char *argv[])
{
	plan_lazy();

	dnssec_crypto_init();

	dnssec_keystore_t *store = NULL;
	int r = dnssec_keystore_init_pkcs11(&store);
	if (r == DNSSEC_NOT_IMPLEMENTED_ERROR) {
		skip_all("not supported");
		dnssec_crypto_cleanup();
		return 0;
	}

	ok(r == DNSSEC_EOK && store, "dnssec_keystore_init_pkcs11");

	r = dnssec_keystore_open(store, "pkcs11:token=dns-keys;pin-value=1234 /usr/lib64/pkcs11/libsofthsm2.so");
	ok(r == DNSSEC_EOK, "dnssec_keystore_open");

	char *id = NULL;
	r = dnssec_keystore_generate_key(store, DNSSEC_KEY_ALGORITHM_RSA_SHA256, 2048, &id);
	ok(r == DNSSEC_EOK && id, "generate_key");

	diag("key id %s", id);
	free(id);

	dnssec_keystore_deinit(store);

	dnssec_crypto_cleanup();

	return 0;
}
