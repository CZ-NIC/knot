#pragma once

#include <gnutls/abstract.h>

#include "binary.h"
#include "key.h"

/*!
 * Create GnuTLS private key from PKCS #8 in PEM.
 *
 * \param[in]  data    Unencrypted PEM.
 * \param[out] key     Resulting key.
 * \param[out] key_id  Key id of the created key.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int privkey_from_pem(const dnssec_binary_t *data, gnutls_privkey_t *key,
		     dnssec_key_id_t key_id);

/*!
 * Create GnuTLS public key from private key.
 *
 * \param[in]  privkey  Private key.
 * \param[out] pubkey   Created public key.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int pubkey_from_privkey(gnutls_privkey_t privkey, gnutls_pubkey_t *pubkey);
