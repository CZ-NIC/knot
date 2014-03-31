#pragma once

#include <gnutls/abstract.h>

#include "binary.h"
#include "key.h"

/*!
 * Create GnuTLS public key from private key.
 *
 * \param[in]  privkey  Private key.
 * \param[out] pubkey   Created public key.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int pubkey_from_privkey(gnutls_privkey_t privkey, gnutls_pubkey_t *pubkey);
