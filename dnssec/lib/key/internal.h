#pragma once

#include <gnutls/abstract.h>

#include "key.h"

struct dnssec_key {
	dnssec_key_id_t id;
	uint16_t keytag;

	dnssec_binary_t rdata;

	gnutls_pubkey_t public_key;
	gnutls_privkey_t private_key;
};
