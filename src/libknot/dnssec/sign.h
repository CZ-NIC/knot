/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file sign.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief Low level DNSSEC signing functions.
 *
 * \addtogroup dnssec
 * @{
 */

#pragma once

#include "libknot/binary.h"
#include "libknot/consts.h"
#include "libknot/dnssec/key.h"

/*!
 * \brief Algorithm private key data and algorithm implementation (internal).
 */
struct knot_dnssec_key_data;
typedef struct knot_dnssec_key_data knot_dnssec_key_data_t;

/*!
 * \brief DNSSEC signature contextual data (internal).
 */
struct knot_dnssec_sign_context;
typedef struct knot_dnssec_sign_context knot_dnssec_sign_context_t;

/*!
 * \brief DNSSEC key representation.
 */
typedef struct {
	knot_dname_t *name;                //!< Key name (identifies signer).
	uint16_t keytag;                   //!< Key tag (for fast lookup).
	knot_dnssec_algorithm_t algorithm; //!< Algorithm identification.
	knot_dnssec_key_data_t *data;      //!< Private key data.
	knot_binary_t dnskey_rdata;        //!< DNSKEY RDATA.
} knot_dnssec_key_t;

/*- DNSSEC private key manipulation ------------------------------------------*/

/*!
 * \brief Fill DNSSEC key structure according to key parameters.
 *
 * \param params  Key parameters.
 * \param key     Output structure.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_dnssec_key_from_params(const knot_key_params_t *params,
                                knot_dnssec_key_t *key);

/*!
 * \brief Free DNSSEC key structure content.
 *
 * \note Does not free the structure itself.
 *
 * \param key  DNSSEC key.
 *
 * \return Error code, always KNOT_EOK.
 */
int knot_dnssec_key_free(knot_dnssec_key_t *key);


/*- DNSSEC low level signing interface----------------------------------------*/

/*!
 * \brief Initialize DNSSEC signing context.
 *
 * \param key  DNSSEC key.
 * \return DNSSEC signing context.
 */
knot_dnssec_sign_context_t *knot_dnssec_sign_init(const knot_dnssec_key_t *key);

/*!
 * \brief Free DNSSEC signing context.
 *
 * \param context  Context to be freed.
 */
void knot_dnssec_sign_free(knot_dnssec_sign_context_t *context);

/*!
 * \brief Get DNSSEC signature size.
 *
 * \param key  Key parameters.
 *
 * \return DNSSEC signature size. Zero in case of error.
 */
size_t knot_dnssec_sign_size(const knot_dnssec_key_t *key);

/**
 * \brief Clean DNSSEC signing context to start a new signature.
 *
 * Need not be called after knot_dnssec_sign_init().
 *
 * \param context	DNSSEC signing context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_dnssec_sign_new(knot_dnssec_sign_context_t *context);

/*!
 * \brief Add data to be covered by DNSSEC signature.
 *
 * \param context    DNSSEC signing context.
 * \param data       Pointer to data to be added.
 * \param data_size  Size of the data to be added.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_dnssec_sign_add(knot_dnssec_sign_context_t *context,
                         const uint8_t *data, size_t data_size);

/**
 * \brief Write down the DNSSEC signature for supplied data.
 *
 * \param context         DNSSEC signing context.
 * \param signature       Pointer to signature to be written.
 * \param signature_size  Allocated size for the signature.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_dnssec_sign_write(knot_dnssec_sign_context_t *context,
                           uint8_t *signature, size_t signature_size);

/**
 * \brief Verify the DNSSEC signature for supplied data.
 *
 * \param context         DNSSEC signing context.
 * \param signature       Signature.
 * \param signature_size  Size of the signature.
 *
 * \return Error code.
 * \retval KNOT_EOK                        The signature is valid.
 * \retval KNOT_DNSSEC_EINVALID_SIGNATURE  The signature is not valid.
 */
int knot_dnssec_sign_verify(knot_dnssec_sign_context_t *context,
                            const uint8_t *signature, size_t signature_size);

/*! @} */
