/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "libknot/dnssec/nsec.h"
#include "libknot/dnssec/shared/shared.h"
#include "libknot/dnssec/shared/binary_wire.h"

#include "libknot/dnssec/binary.h"
#include "libknot/dnssec/error.h"

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
		return KNOT_EINVAL;
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
		return KNOT_ENOMEM;
	}

	binary_read(&wire, &new_params.salt);
	assert(wire_ctx_offset(&wire) == rdata->size);

	*params = new_params;

	return KNOT_EOK;
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

_public_
bool dnssec_nsec3_params_match(const dnssec_nsec3_params_t *params1,
			       const dnssec_nsec3_params_t *params2)
{
	if (params1 != NULL && params2 != NULL) {
		return (params1->algorithm == params2->algorithm &&
			params1->flags == params2->flags &&
			params1->iterations == params2->iterations &&
			dnssec_binary_cmp(&params1->salt, &params2->salt) == 0);
	} else {
		return (params1 == NULL && params2 == NULL);
	}
}
