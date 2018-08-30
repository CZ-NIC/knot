/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libdnssec/nsec.h"
#include "libdnssec/shared/shared.h"
#include "libdnssec/shared/binary_wire.h"

#include "libdnssec/binary.h"
#include "libdnssec/error.h"

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
	clear_struct(params);
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

	wire_ctx_t wire = binary_init(rdata);

	if (wire_ctx_available(&wire) < 5) {
		return DNSSEC_MALFORMED_DATA;
	}

	new_params.algorithm  = wire_ctx_read_u8(&wire);
	new_params.flags      = wire_ctx_read_u8(&wire);
	new_params.iterations = wire_ctx_read_u16(&wire);
	new_params.salt.size  = wire_ctx_read_u8(&wire);

	if (wire_ctx_available(&wire) != new_params.salt.size) {
		return DNSSEC_MALFORMED_DATA;
	}

	new_params.salt.data = malloc(new_params.salt.size);
	if (new_params.salt.data == NULL) {
		return DNSSEC_ENOMEM;
	}

	binary_read(&wire, &new_params.salt);
	assert(wire_ctx_offset(&wire) == rdata->size);

	*params = new_params;

	return DNSSEC_EOK;
}

_public_
bool dnssec_nsec_bitmap_contains(const uint8_t *bitmap, uint16_t size, uint16_t type)
{
	if (!bitmap || size == 0) {
		return false;
	}

	const uint8_t type_hi = (type >> 8); // Which window block contains type.
	const uint8_t type_lo = (type & 0xff);
	const uint8_t bitmap_idx = (type_lo >> 3); // Which byte in the window block contains type.
	const uint8_t bit_mask = 1 << (7 - (type_lo & 0x07)); // Which bit in the byte represents type.

	size_t bitmap_pos = 0;
	while (bitmap_pos + 3 <= size) {
		uint8_t block_idx = bitmap[bitmap_pos++]; // Skip window block No.
		uint8_t block_size = bitmap[bitmap_pos++]; // Skip window block size.

		// Size checks.
		if (block_size == 0 || bitmap_pos + block_size > size) {
			return false;
		}

		// Check whether we found the correct window block.
		if (block_idx == type_hi) {
			if (bitmap_idx < block_size) {
				// Check if the bit for type is set.
				return bitmap[bitmap_pos + bitmap_idx] & bit_mask;
			}
			return false;
		} else {
			bitmap_pos += block_size;
		}
	}

	return false;
}
