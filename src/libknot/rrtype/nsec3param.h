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

#pragma once

#include <stdint.h>

#include "libknot/rdataset.h"

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

static inline
uint8_t knot_nsec3param_algorithm(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return *knot_rdata_offset(rrs, pos, 0);
}

static inline
uint8_t knot_nsec3param_flags(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return *knot_rdata_offset(rrs, pos, 1);
}

uint16_t knot_nsec3param_iterations(const knot_rdataset_t *rrs, size_t pos);

static inline
uint8_t knot_nsec3param_salt_length(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return *knot_rdata_offset(rrs, pos, 4);
}

static inline
const uint8_t *knot_nsec3param_salt(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return knot_rdata_offset(rrs, pos, 5);
}

/*!
 * \brief Initialize the structure with NSEC3 params from NSEC3PARAM RR set.
 *
 * \param params      Structure to initialize.
 * \param rrs         The NSEC3PARAM RRs.
 *
 * \return Error code, KNOT_EOK on success.
 */
int knot_nsec3param_from_wire(knot_nsec3_params_t *params,
                              const knot_rdataset_t *rrs);
/*!
 * \brief Clean up structure with NSEC3 params (do not deallocate).
 *
 * \param params Structure with NSEC3 params.
 */
static inline
void knot_nsec3param_free(knot_nsec3_params_t *params)
{
	if (params == NULL) {
		return;
	}

	free(params->salt);
}
