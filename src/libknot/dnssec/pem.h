/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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

#include "libknot/dnssec/binary.h"

/*!
 * Create GnuTLS X.509 private key from unencrypted PEM data.
 *
 * \param[in]  pem  PEM binary data.
 * \param[out] key  Resulting private key.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int dnssec_pem_to_x509(const dnssec_binary_t *pem, gnutls_x509_privkey_t *key);

/*!
 * Create GnuTLS private key from unencrypted PEM data.
 *
 * \param[in]  pem  PEM binary data.
 * \param[out] key  Resulting private key.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int dnssec_pem_to_privkey(const dnssec_binary_t *pem, gnutls_privkey_t *key);

/*!
 * Export GnuTLS X.509 private key to PEM binary.
 *
 * \param[in]  key  Key to be exported.
 * \param[out] pem  Generated key in unencrypted PEM format.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int dnssec_pem_from_x509(gnutls_x509_privkey_t key, dnssec_binary_t *pem);

/*!
 * Export GnuTLS private key to PEM binary.
 *
 * \param[in]  key  Key to be exported.
 * \param[out] pem  Generated key in unencrypted PEM format.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int dnssec_pem_from_privkey(gnutls_privkey_t key, dnssec_binary_t *pem);

/*! @} */
