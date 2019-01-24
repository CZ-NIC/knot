/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
/*!
 * \file
 *
 * \addtogroup pem
 *
 * \brief PEM key format operations.
 *
 * @{
 */

#pragma once

#include <gnutls/gnutls.h>

#include <libdnssec/binary.h>

/*!
 * Create GnuTLS X.509 private key from unencrypted PEM data.
 *
 * \param[in]  pem  PEM binary data.
 * \param[out] key  Resulting private key.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_pem_to_x509(const dnssec_binary_t *pem, gnutls_x509_privkey_t *key);

/*!
 * Create GnuTLS private key from unencrypted PEM data.
 *
 * \param[in]  pem  PEM binary data.
 * \param[out] key  Resulting private key.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_pem_to_privkey(const dnssec_binary_t *pem, gnutls_privkey_t *key);

/*!
 * Export GnuTLS X.509 private key to PEM binary.
 *
 * \param[in]  key  Key to be exported.
 * \param[out] pem  Generated key in unencrypted PEM format.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_pem_from_x509(gnutls_x509_privkey_t key, dnssec_binary_t *pem);

/*! @} */
