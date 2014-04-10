#pragma once

#include <gnutls/abstract.h>

#include "binary.h"

/*!
 * Create GnuTLS private key from unencrypted PEM data.
 *
 * \param[in]  data  PEM binary data.
 * \param[out] key   Resulting private key.
 * \param[out] id    Key ID.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int pem_to_privkey(const dnssec_binary_t *data, gnutls_privkey_t *key,
		   char **id);

/*!
 * Generate a private key.
 *
 * \param[in]  algorithm  Algorithm to be used.
 * \param[in]  bits       Size of the key to be generated.
 * \param[out] pem        Generated key in unencrypted PEM format.
 * \param[out] id         Key ID of the generated key.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int pem_generate(gnutls_pk_algorithm_t algorithm, unsigned bits,
		 dnssec_binary_t *pem, char **id);
