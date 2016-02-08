/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/dname.h"
#include "libknot/rdataset.h"

uint16_t knot_rrsig_type_covered(const knot_rdataset_t *rrs, size_t pos);

static inline
uint8_t knot_rrsig_algorithm(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return *knot_rdata_offset(rrs, pos, 2);
}

static inline
uint8_t knot_rrsig_labels(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return *knot_rdata_offset(rrs, pos, 3);
}

uint32_t knot_rrsig_original_ttl(const knot_rdataset_t *rrs, size_t pos);

uint32_t knot_rrsig_sig_expiration(const knot_rdataset_t *rrs, size_t pos);

uint32_t knot_rrsig_sig_inception(const knot_rdataset_t *rrs, size_t pos);

uint16_t knot_rrsig_key_tag(const knot_rdataset_t *rrs, size_t pos);

static inline
const knot_dname_t *knot_rrsig_signer_name(const knot_rdataset_t *rrs,
                                                 size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return knot_rdata_offset(rrs, pos, 18);
}

static inline
void knot_rrsig_signature(const knot_rdataset_t *rrs, size_t pos,
                                uint8_t **signature, size_t *signature_size)
{
	if (!signature || !signature_size) {
		return;
	}

	if (rrs == NULL || pos >= rrs->rr_count) {
		*signature = NULL;
		*signature_size = 0;
		return;
	}

	uint8_t *rdata = knot_rdata_offset(rrs, pos, 0);
	uint8_t *signer = rdata + 18;
	const knot_rdata_t *rr = knot_rdataset_at(rrs, pos);
	size_t total_size = knot_rdata_rdlen(rr);
	size_t header_size = 18 + knot_dname_size(signer);

	*signature = rdata + header_size;
	*signature_size = total_size - header_size;
}
