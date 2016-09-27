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

#include <assert.h>

#include "knot/server/serialization.h"
#include "libknot/libknot.h"

static size_t rr_binary_size(const knot_rrset_t *rrset, size_t rdata_pos)
{
	const knot_rdata_t *rr = knot_rdataset_at(&rrset->rrs, rdata_pos);
	if (rr) {
		// RR size + TTL
		return knot_rdata_rdlen(rr) + sizeof(uint32_t);
	} else {
		return 0;
	}
}

static uint64_t rrset_binary_size(const knot_rrset_t *rrset)
{
	if (rrset == NULL || rrset->rrs.rr_count == 0) {
		return 0;
	}
	uint64_t size = sizeof(uint64_t) + // size at the beginning
	              knot_dname_size(rrset->owner) + // owner data
	              sizeof(uint16_t) + // type
	              sizeof(uint16_t) + // class
	              sizeof(uint16_t);  //RR count
	uint16_t rdata_count = rrset->rrs.rr_count;
	for (uint16_t i = 0; i < rdata_count; i++) {
		/* Space to store length of one RR. */
		size += sizeof(uint32_t);
		/* Actual data. */
		size += rr_binary_size(rrset, i);
	}

	return size;
}

static void serialize_rr(const knot_rrset_t *rrset, size_t rdata_pos,
                         uint8_t *stream)
{
	const knot_rdata_t *rr = knot_rdataset_at(&rrset->rrs, rdata_pos);
	assert(rr);
	uint32_t ttl = knot_rdata_ttl(rr);
	memcpy(stream, &ttl, sizeof(uint32_t));
	memcpy(stream + sizeof(uint32_t), knot_rdata_data(rr), knot_rdata_rdlen(rr));
}

static int deserialize_rr(knot_rrset_t *rrset, const uint8_t *stream, uint32_t rdata_size)
{
	uint32_t ttl;
	memcpy(&ttl, stream, sizeof(uint32_t));
	return knot_rrset_add_rdata(rrset, stream + sizeof(uint32_t),
	                         rdata_size - sizeof(uint32_t), ttl, NULL);
}

int changeset_binary_size(const changeset_t *chgset, size_t *size)
{
	if (chgset == NULL || size == NULL) {
		return KNOT_EINVAL;
	}

	size_t soa_from_size = rrset_binary_size(chgset->soa_from);
	size_t soa_to_size = rrset_binary_size(chgset->soa_to);
	changeset_iter_t itt;
	changeset_iter_all(&itt, chgset);

	size_t change_size = 0;
	knot_rrset_t rrset = changeset_iter_next(&itt);
	while (!knot_rrset_empty(&rrset)) {
		change_size += rrset_binary_size(&rrset);
		rrset = changeset_iter_next(&itt);
	}

	changeset_iter_clear(&itt);

	*size = soa_from_size + soa_to_size + change_size;

	return KNOT_EOK;
}

int rrset_serialize(const knot_rrset_t *rrset, uint8_t *stream, size_t *size)
{
	if (rrset == NULL || rrset->rrs.data == NULL) {
		return KNOT_EINVAL;
	}

	uint64_t rrset_length = rrset_binary_size(rrset);
	memcpy(stream, &rrset_length, sizeof(uint64_t));

	size_t offset = sizeof(uint64_t);
	/* Save RR count. */
	const uint16_t rr_count = rrset->rrs.rr_count;
	memcpy(stream + offset, &rr_count, sizeof(uint16_t));
	offset += sizeof(uint16_t);
	/* Save owner. */
	offset += knot_dname_to_wire(stream + offset, rrset->owner, rrset_length - offset);

	/* Save static data. */
	memcpy(stream + offset, &rrset->type, sizeof(uint16_t));
	offset += sizeof(uint16_t);
	memcpy(stream + offset, &rrset->rclass, sizeof(uint16_t));
	offset += sizeof(uint16_t);

	/* Copy RDATA. */
	for (uint16_t i = 0; i < rr_count; i++) {
		uint32_t knot_rr_size = rr_binary_size(rrset, i);
		memcpy(stream + offset, &knot_rr_size, sizeof(uint32_t));
		offset += sizeof(uint32_t);
		serialize_rr(rrset, i, stream + offset);
		offset += knot_rr_size;
	}

	*size = offset;
	assert(*size == rrset_length);
	return KNOT_EOK;
}

int rrset_deserialize(const uint8_t *stream, size_t *stream_size,
                      knot_rrset_t *rrset)
{
	if (stream == NULL || stream_size == NULL ||
	    rrset == NULL) {
		return KNOT_EINVAL;
	}

	if (sizeof(uint64_t) > *stream_size) {
		return KNOT_ESPACE;
	}
	uint64_t rrset_length = 0;
	memcpy(&rrset_length, stream, sizeof(uint64_t));
	if (rrset_length > *stream_size) {
		return KNOT_ESPACE;
	}

	size_t offset = sizeof(uint64_t);
	uint16_t rdata_count = 0;
	memcpy(&rdata_count, stream + offset, sizeof(uint16_t));
	offset += sizeof(uint16_t);
	/* Read owner from the stream. */
	unsigned owner_size = knot_dname_size(stream + offset);
	knot_dname_t *owner = knot_dname_copy_part(stream + offset, owner_size, NULL);
	assert(owner);
	offset += owner_size;
	/* Read type. */
	uint16_t type = 0;
	memcpy(&type, stream + offset, sizeof(uint16_t));
	offset += sizeof(uint16_t);
	/* Read class. */
	uint16_t rclass = 0;
	memcpy(&rclass, stream + offset, sizeof(uint16_t));
	offset += sizeof(uint16_t);

	/* Create new RRSet. */
	knot_rrset_init(rrset, owner, type, rclass);

	/* Read RRs. */
	for (uint16_t i = 0; i < rdata_count; i++) {
		/*
		 * There's always size of rdata in the beginning.
		 * Needed because of remainders.
		 */
		uint32_t rdata_size = 0;
		memcpy(&rdata_size, stream + offset, sizeof(uint32_t));
		offset += sizeof(uint32_t);
		int ret = deserialize_rr(rrset, stream + offset, rdata_size);
		if (ret != KNOT_EOK) {
			knot_rrset_clear(rrset, NULL);
			return ret;
		}
		offset += rdata_size;
	}

	*stream_size = *stream_size - offset;

	return KNOT_EOK;
}
