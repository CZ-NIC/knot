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

#include <stdio.h>
#include <stdlib.h>

#include "dnssec/crypto.h"
#include "dnssec/error.h"
#include "dnssec/key.h"

#include "shared.h"

#include "legacy/legacy.h"

int main(int argc, char *argv[])
{
	dnssec_crypto_init();
	atexit(dnssec_crypto_cleanup);

	if (argc != 2) {
		fprintf(stderr, "import <name>\n");
		return 1;
	}

	int r = legacy_key_import(argv[1]);
	if (r != DNSSEC_EOK) {
		fprintf(stderr, "Key import error: %s\n", dnssec_strerror(r));
		return 1;
	}

	return 0;


//	if (legacy_pubkey_parse(filename_bind) != 0) {
//		fprintf(stderr, "Unable to parse legacy key.\n");
//	}

//	dnssec_key_t *key = load_public_key(filename_dnskey);
//	if (!key) {
//		fprintf(stderr, "Unable to parse public key.\n");
//	}

//	dnssec_key_free(key);
	return 0;
}
