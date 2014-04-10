#pragma once

#include <gnutls/abstract.h>
#include "binary.h"

/*!
 * Get ID from GnuTLS public key and convert it into library format.
 */
char *gnutls_pubkey_hex_key_id(gnutls_pubkey_t key);

/*!
 * Get ID from GnuTLS X.509 private key and convert it into library format.
 */
char *gnutls_x509_privkey_hex_key_id(gnutls_x509_privkey_t key);
