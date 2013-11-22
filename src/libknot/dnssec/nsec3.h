/*!
 * \file nsec3.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief Functions for computation of NSEC3 hashes.
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

#ifndef _KNOT_DNSSEC_NSEC3_H_
#define _KNOT_DNSSEC_NSEC3_H_

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "libknot/consts.h"
#include "libknot/rrset.h"

/*---------------------------------------------------------------------------*/


/*!
 * \brief Get length of the raw NSEC3 hash.
 *
 * \param algorithm  NSEC3 hash algorithm.
 *
 * \return Length of the hash, 0 for unknown hash algorithm.
 */
inline static size_t knot_nsec3_hash_length(uint8_t algorithm)
{
	if (algorithm == KNOT_NSEC3_ALGORITHM_SHA1) {
		return 20;
	} else {
		return 0;
	}
}

/*!
 * \brief Get length of the NSEC3 hash encoded in Base32 encoding.
 *
 * \param algorithm  NSEC3 hash algorithm.
 *
 * \return Length of the hash, 0 for unknown hash algorithm.
 */
inline static size_t knot_nsec3_hash_b32_length(uint8_t algorithm)
{
	if (algorithm == KNOT_NSEC3_ALGORITHM_SHA1) {
		return 32;
	} else {
		return 0;
	}
}

/*---------------------------------------------------------------------------*/

/*!
 * \brief Structure representing the NSEC3PARAM resource record.
 */
typedef struct {
	uint8_t algorithm;    //!< Hash algorithm.
	uint8_t flags;        //!< Flags.
	uint16_t iterations;  //!< Additional iterations of the hash function.
	uint8_t salt_length;  //!< Length of the salt field in bytes.
	uint8_t *salt;        //!< Salt used in hashing.
} knot_nsec3_params_t;

/*---------------------------------------------------------------------------*/

/*!
 * \brief Initialize the structure with NSEC3 params from NSEC3PARAM RR set.
 *
 * \param params      Structure to initialize.
 * \param nsec3param  The NSEC3PARAM RR set.
 *
 * \return Error code, KNOT_EOK on success.
 */
int knot_nsec3_params_from_wire(knot_nsec3_params_t *params,
                                const knot_rrset_t *rrset);
/*!
 * \brief Clean up structure with NSEC3 params (do not deallocate).
 *
 * \param params Structure with NSEC3 params.
 */
void knot_nsec3_params_free(knot_nsec3_params_t *params);

/*!
 * \brief Compute NSEC3 hash for given data.
 *
 * \param[in]  params       NSEC3 parameters.
 * \param[in]  data         Data to compute hash for.
 * \param[in]  size         Size of the data.
 * \param[out] digest       Computed hash.
 * \param[out] digest_size  Size of the computed hash.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_nsec3_hash(const knot_nsec3_params_t *params, const uint8_t *data,
                    size_t size, uint8_t **digest, size_t *digest_size);

#endif // _KNOT_DNSSEC_NSEC3_H_

/*! @} */
