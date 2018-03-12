/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include <gnutls/gnutls.h>

#include "binary.h"

/*!
 * Create GnuTLS X.509 private key from unencrypted PEM data.
 *
 * \param[in]  pem  PEM binary data.
 * \param[out] key  Resulting private key.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int pem_x509(const dnssec_binary_t *pem, gnutls_x509_privkey_t *key);

/*!
 * Create GnuTLS private key from unencrypted PEM data.
 *
 * \param[in]  pem  PEM binary data.
 * \param[out] key  Resulting private key.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int pem_privkey(const dnssec_binary_t *pem, gnutls_privkey_t *key);

/*!
 * Generate a private key and export it in the PEM format.
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

/*!
 * Export GnuTLS X.509 private key to PEM binary.
 *
 * \param[in]  key  Key to be exported.
 * \param[out] pem  Generated key in unencrypted PEM format.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int pem_from_x509(gnutls_x509_privkey_t key, dnssec_binary_t *pem);

/*!
 * Get key ID of a private key in PEM format.
 *
 * \param[in]  pem  Key in unencrypted PEM format.
 * \param[out] id   ID of the key.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int pem_keyid(const dnssec_binary_t *pem, char **id);
