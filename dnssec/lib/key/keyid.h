#pragma once

#include <gnutls/abstract.h>

#include "key.h"

/*!
 * Get ID from GnuTLS public key and convert it into library format.
 */
void gnutls_pubkey_to_key_id(gnutls_pubkey_t key, dnssec_key_id_t id);

/*!
 * Get ID from GnuTLS X.509 private key and convert it into library format.
 */
void gnutls_x509_privkey_to_key_id(gnutls_x509_privkey_t key, dnssec_key_id_t id);
