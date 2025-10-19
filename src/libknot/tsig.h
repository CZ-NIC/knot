/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \brief TSIG operations
 *
 * \addtogroup knot-tsig
 * @{
 */

#pragma once

#include "libknot/dname.h"
#include "libknot/dnssec/tsig.h"

/*!
 * \brief TSIG key.
 */
typedef struct {
	dnssec_tsig_algorithm_t algorithm;
	knot_dname_t *name;
	dnssec_binary_t secret;
} knot_tsig_key_t;

/*!
 * \brief Packet signing context.
 */
typedef struct {
	knot_tsig_key_t tsig_key;
	uint8_t *tsig_digest;
	size_t tsig_digestlen;
	uint64_t tsig_time_signed;
	size_t pkt_count;
} knot_sign_context_t;

/*!
 * \brief Initialize a new TSIG key from individual key parameters.
 *
 * \param[out] key         Key to be initialized.
 * \param[in]  algorithm   Algorithm name. NULL for default (hmac-md5).
 * \param[in]  name        Key name (domain name in presentation format).
 * \param[in]  secret_b64  Secret encoded using Base 64.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_tsig_key_init(knot_tsig_key_t *key, const char *algorithm,
                       const char *name, const char *secret_b64);

/*!
 * \brief Create a new TSIG key from a string encoding all parameters.
 *
 * \param[out] key     Key to be initialized.
 * \param[in]  params  Parameters in a form \a [algorithm:]name:base64_secret
 */
int knot_tsig_key_init_str(knot_tsig_key_t *key, const char *params);

/*!
 * \brief Create a new TSIG key by reading the parameters from a file.
 *
 * The file content is parsed by \a tsig_key_create_str.
 */
int knot_tsig_key_init_file(knot_tsig_key_t *key, const char *filename);

/*!
 * \brief Deinitialize TSIG key.
 */
void knot_tsig_key_deinit(knot_tsig_key_t *key);

/*!
 * \brief Duplicate a TSIG key.
 */
int knot_tsig_key_copy(knot_tsig_key_t *dst, const knot_tsig_key_t *src);

/*! @} */
