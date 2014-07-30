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

#include "common/mem.h"
#include "libknot/errcode.h"
#include "libknot/rrtype/nsec3param.h"

/*!
 * \brief Initialize the structure with NSEC3 params from NSEC3PARAM RR set.
 */
int knot_nsec3param_from_wire(knot_nsec3_params_t *params,
                                const knot_rdataset_t *rrs)
{
	if (params == NULL || rrs == NULL || rrs->rr_count == 0) {
		return KNOT_EINVAL;
	}

	knot_nsec3_params_t result = { 0 };

	result.algorithm   = knot_nsec3param_algorithm(rrs, 0);
	result.iterations  = knot_nsec3param_iterations(rrs, 0);
	result.flags       = knot_nsec3param_flags(rrs, 0);
	result.salt_length = knot_nsec3param_salt_length(rrs, 0);

	if (result.salt_length > 0) {
		result.salt = knot_memdup(knot_nsec3param_salt(rrs, 0),
		                          result.salt_length);
		if (!result.salt) {
			return KNOT_ENOMEM;
		}
	} else {
		result.salt = NULL;
	}

	knot_nsec3param_free(params);
	*params = result;

	return KNOT_EOK;
}

/*!
 * \brief Clean up structure with NSEC3 params (do not deallocate).
 */
void knot_nsec3param_free(knot_nsec3_params_t *params)
{
	free(params->salt);
}
