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
 * \file nsec5hash.h
 *
 * \author Dimitris Papadopoulos
 *
 * \brief Low level NSEC5 hashing functions.
 *
 * \addtogroup dnssec
 * @{
 */

#pragma once

#include "libknot/rrtype/nsec5.h"

#include "libknot/binary.h"
#include "libknot/consts.h"
#include "libknot/dnssec/key.h"


/*!
 * \brief Algorithm private key data and algorithm implementation (internal).
 */
struct knot_nsec5_key_data;
typedef struct knot_nsec5_key_data knot_nsec5_key_data_t;

/*!
 * \brief NSEC5 hash contextual data (internal).
 */
struct knot_nsec5_hash_context;
typedef struct knot_nsec5_hash_context knot_nsec5_hash_context_t;

/*!
 * \brief NSEC5 key representation.
 */
typedef struct {
    knot_dname_t *name;                    //!< Key name (identifies signer).
    uint16_t keytag;                       //!< Key tag (for fast lookup).
    knot_nsec5_hash_algorithm_t algorithm; //!< Algorithm identification.
    knot_nsec5_key_data_t *data;          //!< Private & Public key data.
    knot_binary_t nsec5key_rdata;            //!< DNSKEY RDATA.
} knot_nsec5_key_t;

/*- NSEC5 private & Public key manipulation ------------------------------------------*/

/*!
 * \brief Fill NSEC5 key structure according to key parameters.
 *
 * \param params  Key parameters.
 * \param key     Output structure.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_nsec5_key_from_params(const knot_key_params_t *params,
                                knot_nsec5_key_t *key);

/*!
 * \brief Free NSEC5 key structure content.
 *
 * \note Does not free the structure itself.
 *
 * \param key  NSEC5 key.
 *
 * \return Error code, always KNOT_EOK.
 */
int knot_nsec5_key_free(knot_nsec5_key_t *key);

/*- NSEC5 low level hashing interface----------------------------------------*/

/*!
 * \brief Initialize NSEC5 hashing context.
 *
 * \param key  NSEC5 key.
 * \return NSEC5 hashing context.
 */
knot_nsec5_hash_context_t *knot_nsec5_hash_init(const knot_nsec5_key_t *key);

/*!
 * \brief Free NSEC5 hashing context.
 *
 * \param context  Context to be freed.
 */
void knot_nsec5_hash_free(knot_nsec5_hash_context_t *context);

/*!
 * \brief Get NSEC5 hash size.
 *
 * \param key  Key parameters.
 *
 * \return NSEC5 hash size. Zero in case of error.
 */
size_t knot_nsec5_hash_size(const knot_nsec5_key_t *key);

/**
 * \brief Clean NSEC5 hashing context to start a new hash.
 *
 * Need not be called after knot_nsec5_hash_init().
 *
 * \param context	NSEC5 hashing context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_nsec5_hash_new(knot_nsec5_hash_context_t *context);

/*! Only runs once to load context
 * \brief Add data to be covered by NSEC5 hash.
 *
 * \param context    NSEC5 hashing context.
 * \param data       Pointer to data to be added.
 * \param data_size  Size of the data to be added.
 *
 * \return Error code, KNOT_EOK if successful.
*/
int knot_nsec5_hash_add(knot_nsec5_hash_context_t *context,
                           const knot_dname_t *data);

/**
 * \brief Write down the NSEC5 hash for supplied data.
 *
 * \param context         NSEC5 hashing context.
 * \param hash       Pointer to hash to be written.
 * \param hash_size  Allocated size for the hash.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_nsec5_hash_write(knot_nsec5_hash_context_t *context,
                           uint8_t *hash, size_t hash_size);

/**
 * \brief Verify the NSEC5 hash for supplied data.
 *
 * \param context         NSEC5 hashing context.
 * \param hash       Hash.
 * \param hash_size  Size of the hash.
 *
 * \return Error code.
 * \retval KNOT_EOK                        The hash is valid.
 * \retval KNOT_NSEC5_ECOMPUTE_HASH        The hash is not valid.
 */
int knot_nsec5_hash_verify(knot_nsec5_hash_context_t *context,
                            const uint8_t *hash, size_t hash_size);

int knot_nsec5_sha256(const uint8_t *data,
                        size_t data_size, uint8_t **digest, size_t *digest_size);

size_t knot_nsec5_final_hash_size(knot_nsec5_hash_context_t *context);

// FINAL OUTPUT
int knot_nsec5_hash(knot_nsec5_hash_context_t *context,
                    uint8_t **digest, size_t *digest_size);

int knot_nsec5_hash_full(knot_nsec5_hash_context_t *context,
                         uint8_t **digest, size_t *digest_size, uint8_t **sign, size_t *sign_size);
/*! @} */











