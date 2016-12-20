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

#include <assert.h>

#include "knot/journal/serialization.h"
#include "libknot/libknot.h"
#include "contrib/wire_ctx.h"

static uint64_t rrset_binary_size(const knot_rrset_t *rrset)
{
	if (rrset == NULL || rrset->rrs.rr_count == 0) {
		return 0;
	}

	// Owner size + type + class + RR count.
	uint64_t size = knot_dname_size(rrset->owner) + 3 * sizeof(uint16_t);

	// RRs.
	for (uint16_t i = 0; i < rrset->rrs.rr_count; i++) {
		const knot_rdata_t *rr = knot_rdataset_at(&rrset->rrs, i);
		assert(rr);

		// TTL + RR size + RR.
		size += sizeof(uint32_t) + sizeof(uint16_t) + knot_rdata_rdlen(rr);
	}

	return size;
}

static int serialize_rrset(wire_ctx_t *wire, const knot_rrset_t *rrset)
{
	assert(wire);
	assert(rrset);

	// Write owner.
	int size = knot_dname_to_wire(wire->position, rrset->owner,
	                              wire_ctx_available(wire));
	if (size < 0) {
		return size;
	}
	wire_ctx_skip(wire, size);

	// Write rtype, rclass and RR count.
	wire_ctx_write_u16(wire, rrset->type);
	wire_ctx_write_u16(wire, rrset->rclass);
	wire_ctx_write_u16(wire, rrset->rrs.rr_count);

	// Write rdata items.
	for (uint16_t i = 0; i < rrset->rrs.rr_count; i++) {
		const knot_rdata_t *rr = knot_rdataset_at(&rrset->rrs, i);
		assert(rr);
		wire_ctx_write_u32(wire, knot_rdata_ttl(rr));
		wire_ctx_write_u16(wire, knot_rdata_rdlen(rr));
		wire_ctx_write(wire, knot_rdata_data(rr), knot_rdata_rdlen(rr));
	}

	return wire->error;
}

static int deserialize_rrset(wire_ctx_t *wire, knot_rrset_t *rrset)
{
	assert(wire);
	assert(rrset);

	// Read owner.
	int size = knot_dname_size(wire->position);
	if (size < 0) {
		return size;
	}
	knot_dname_t *owner = knot_dname_copy_part(wire->position, size, NULL);
	if (owner == NULL) {
		return KNOT_EMALF;
	}
	wire_ctx_skip(wire, size);

	// Read rtype, rclass and RR count.
	uint16_t type = wire_ctx_read_u16(wire);
	uint16_t rclass = wire_ctx_read_u16(wire);
	uint16_t count = wire_ctx_read_u16(wire);
	if (wire->error != KNOT_EOK) {
		return wire->error;
	}

	knot_rrset_init(rrset, owner, type, rclass);

	// Read rdata items.
	for (uint16_t i = 0; i < count; i++) {
		uint32_t ttl = wire_ctx_read_u32(wire);
		uint32_t rdata_size = wire_ctx_read_u16(wire);
		if (wire->error != KNOT_EOK ||
		    wire_ctx_available(wire) < rdata_size ||
		    knot_rrset_add_rdata(rrset, wire->position, rdata_size,
		                         ttl, NULL) != KNOT_EOK) {
			knot_rrset_clear(rrset, NULL);
			return KNOT_EMALF;
		}
		wire_ctx_skip(wire, rdata_size);
	}

	return wire->error;
}

size_t changeset_serialized_size(const changeset_t *ch)
{
	if (ch == NULL) {
		return 0;
	}

	size_t soa_from_size = rrset_binary_size(ch->soa_from);
	size_t soa_to_size = rrset_binary_size(ch->soa_to);

	changeset_iter_t it;
	changeset_iter_all(&it, ch);

	size_t change_size = 0;
	knot_rrset_t rrset = changeset_iter_next(&it);
	while (!knot_rrset_empty(&rrset)) {
		change_size += rrset_binary_size(&rrset);
		rrset = changeset_iter_next(&it);
	}

	changeset_iter_clear(&it);

	return soa_from_size + soa_to_size + change_size;
}

static int serialize_rrset_chunks(wire_ctx_t *wire, const knot_rrset_t *rrset,
                                  uint8_t *dst_chunks[], size_t chunk_size,
                                  size_t chunks_count, size_t *chunks_real_sizes,
                                  size_t *cur_chunk)
{
	assert(wire);
	assert(rrset);

	while (wire_ctx_available(wire) < rrset_binary_size(rrset)) {
		chunks_real_sizes[*cur_chunk] = wire_ctx_offset(wire);
		if (*cur_chunk >= chunks_count - 1) {
			return KNOT_ESPACE;
		}

		// Move to next chunk.
		if (wire->error != KNOT_EOK) {
			return wire->error;
		}

		(*cur_chunk)++;
		*wire = wire_ctx_init(dst_chunks[*cur_chunk], chunk_size);
	}

	return serialize_rrset(wire, rrset);
}

int changeset_serialize(const changeset_t *ch, uint8_t *dst_chunks[],
                        size_t chunk_size, size_t chunks_count, size_t *chunks_real_sizes,
                        size_t *chunks_real_count)
{
	if (ch == NULL || dst_chunks == NULL || chunk_size == 0 || chunks_count == 0 ||
	    chunks_real_sizes == NULL || chunks_real_count == NULL) {
		return KNOT_EINVAL;
	}

	for (int i = 0; i < chunks_count; i++) {
		chunks_real_sizes[i] = 0;
	}

	wire_ctx_t wire = wire_ctx_init(dst_chunks[0], chunk_size);
	size_t cur_chunk = 0;

	// Serialize SOA 'from'.
	int ret = serialize_rrset_chunks(&wire, ch->soa_from, dst_chunks, chunk_size,
	                                 chunks_count, chunks_real_sizes, &cur_chunk);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Serialize RRSets from the 'rem' section.
	changeset_iter_t it;
	ret = changeset_iter_rem(&it, ch);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_rrset_t rrset = changeset_iter_next(&it);
	while (!knot_rrset_empty(&rrset)) {
		ret = serialize_rrset_chunks(&wire, &rrset, dst_chunks, chunk_size,
		                             chunks_count, chunks_real_sizes, &cur_chunk);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&it);
			return ret;
		}
		rrset = changeset_iter_next(&it);
	}
	changeset_iter_clear(&it);

	// Serialize SOA 'to'.
	ret = serialize_rrset_chunks(&wire, ch->soa_to, dst_chunks, chunk_size,
	                             chunks_count, chunks_real_sizes, &cur_chunk);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Serialize RRSets from the 'add' section.
	ret = changeset_iter_add(&it, ch);
	if (ret != KNOT_EOK) {
		return ret;
	}

	rrset = changeset_iter_next(&it);
	while (!knot_rrset_empty(&rrset)) {
		ret = serialize_rrset_chunks(&wire, &rrset, dst_chunks, chunk_size,
		                             chunks_count, chunks_real_sizes, &cur_chunk);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&it);
			return ret;
		}
		rrset = changeset_iter_next(&it);
	}
	changeset_iter_clear(&it);

	chunks_real_sizes[cur_chunk] = wire_ctx_offset(&wire);
	*chunks_real_count = cur_chunk + 1;

	return wire.error;
}

int changeset_deserialize(changeset_t *ch, uint8_t *src_chunks[],
                          const size_t *chunks_sizes, size_t chunks_count)
{
	if (ch == NULL || src_chunks == NULL || chunks_sizes == NULL ||
	    chunks_count == 0) {
		return KNOT_EINVAL;
	}

	size_t cur_chunk = 0;
	wire_ctx_t wire = wire_ctx_init_const(src_chunks[0], chunks_sizes[0]);

	// Deserialize SOA 'from'.
	knot_rrset_t rrset;
	int ret = deserialize_rrset(&wire, &rrset);
	if (ret != KNOT_EOK) {
		return ret;
	}
	assert(rrset.type == KNOT_RRTYPE_SOA);

	ch->soa_from = knot_rrset_copy(&rrset, NULL);
	knot_rrset_clear(&rrset, NULL);
	if (ch->soa_from == NULL) {
		return KNOT_ENOMEM;
	}

	// Read remaining RRSets.
	bool in_remove_section = true;
	while (1) {
		// Move to next non-empty chunk.
		while (wire_ctx_available(&wire) <= 0) {
			if (wire.error != KNOT_EOK) {
				return wire.error;
			}
			if (++cur_chunk >= chunks_count) {
				return KNOT_EOK; // Standard end of the loop.
			}
			wire = wire_ctx_init_const(src_chunks[cur_chunk],
			                           chunks_sizes[cur_chunk]);
		}

		// Parse next RRSet.
		ret = deserialize_rrset(&wire, &rrset);
		if (ret != KNOT_EOK) {
			break;
		}

		// Check for next (and also last) SOA.
		if (rrset.type == KNOT_RRTYPE_SOA) {
			// Move to ADD section if in REMOVE.
			assert(in_remove_section);
			in_remove_section = false;

			ch->soa_to = knot_rrset_copy(&rrset, NULL);
			if (ch->soa_to == NULL) {
				ret = KNOT_ENOMEM;
			}
		} else {
			if (in_remove_section) {
				ret = changeset_add_removal(ch, &rrset, 0);
			} else {
				ret = changeset_add_addition(ch, &rrset, 0);
			}
		}

		knot_rrset_clear(&rrset, NULL);

		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return wire.error;
}
