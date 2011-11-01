/*!
 * \file nsec3.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Functions for calcularing NSEC3 hashes.
 *
 * \addtogroup libknot
 * @{
 */
/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#ifndef _KNOT_NSEC3_H_
#define _KNOT_NSEC3_H_

#include <stdint.h>
#include <string.h>

#include "rrset.h"

#define KNOT_NSEC3_SHA_USE_EVP 0

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure representing the NSEC3PARAM resource record.
 */
struct knot_nsec3_params {
	uint8_t algorithm;    /*!< Hash algorithm. */
	uint8_t flags;        /*!< Flags. */
	uint16_t iterations;  /*!< Additional iterations of the hash function.*/
	uint8_t salt_length;  /*!< Length of the salt field in bytes. */
	uint8_t *salt;        /*!< Salt used in hashing. */
};

typedef struct knot_nsec3_params knot_nsec3_params_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Initializes the NSEC3PARAM structure.
 *
 * \param params NSEC3PARAM structure to initialize.
 * \param nsec3param The NSEC3PARAM RRset.
 *
 * \retval KNOT_EOK on success (always).
 */
int knot_nsec3_params_from_wire(knot_nsec3_params_t *params,
                                  const knot_rrset_t *nsec3param);

/*!
 * \brief Hashes the given data using the SHA1 hash and the given parameters.
 *
 * \param[in] params NSEC3PARAM structure with the required parameters for
 *                   hashing.
 * \param[in] data Data to hash.
 * \param[in] size Size of the data in bytes.
 * \param[out] digest Result will be store here.
 * \param[out] digest_size Size of the result in octets will be stored here.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_ENOMEM
 * \retval KNOT_EBADARG
 * \retval KNOT_ECRYPTO
 */
int knot_nsec3_sha1(const knot_nsec3_params_t *params, const uint8_t *data,
                      size_t size, uint8_t **digest, size_t *digest_size);

/*!
 * \brief Properly cleans up (but does not deallocate) the NSEC3PARAM structure.
 *
 * \param params NSEC3PARAMS structure to clean up.
 */
void knot_nsec3_params_free(knot_nsec3_params_t *params);

/*----------------------------------------------------------------------------*/

#endif /* _KNOT_NSEC3_H_ */

/*! @} */
