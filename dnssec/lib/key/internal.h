#pragma once

#include <gnutls/abstract.h>
#include <stdint.h>

#include "key.h"
#include "keyid.h"
#include "dname.h"

/*!
 * DNSSEC key.
 */
struct dnssec_key {
	uint8_t *dname;
	dnssec_binary_t rdata;

	char id[DNSSEC_KEYID_SIZE + 1];
	uint16_t keytag;

	gnutls_pubkey_t public_key;
	gnutls_privkey_t private_key;
	unsigned bits;
};

void key_update_identifiers(dnssec_key_t *key);
