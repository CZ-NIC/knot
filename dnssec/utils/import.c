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
