/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "dnssec/nsec.h"
#include "shared.h"
#include "wire.h"

#include "dnssec/binary.h"
#include "dnssec/error.h"

/*!
 * Free NSEC3 parameters.
 */
_public_
void dnssec_nsec3_params_free(dnssec_nsec3_params_t *params)
{
	if (!params) {
		return;
	}

	dnssec_binary_free(&params->salt);
	clear_struct(&params);
}

/*!
 * Parse NSEC3 parameters from NSEC3PARAM RDATA.
 *
 * \see RFC 5155 (section 4.2)
 */
_public_
int dnssec_nsec3_params_from_rdata(dnssec_nsec3_params_t *params,
				   const dnssec_binary_t *rdata)
{
	if (!params || !rdata || !rdata->data) {
		return DNSSEC_EINVAL;
	}

	dnssec_nsec3_params_t new_params = { 0 };

	wire_ctx_t wire = wire_init_binary(rdata);

	if (wire_available(&wire) < 5) {
		return DNSSEC_MALFORMED_DATA;
	}

	new_params.algorithm  = wire_read_u8(&wire);
	new_params.flags      = wire_read_u8(&wire);
	new_params.iterations = wire_read_u16(&wire);
	new_params.salt.size  = wire_read_u8(&wire);

	if (wire_available(&wire) != new_params.salt.size) {
		return DNSSEC_MALFORMED_DATA;
	}

	new_params.salt.data = malloc(new_params.salt.size);
	if (new_params.salt.data == NULL) {
		return DNSSEC_ENOMEM;
	}

	wire_read_binary(&wire, &new_params.salt);
	assert(wire_tell(&wire) == rdata->size);

	*params = new_params;

	return DNSSEC_EOK;
}
