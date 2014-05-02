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
