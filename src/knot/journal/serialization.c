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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>

#include "knot/journal/serialization.h"
#include "libknot/libknot.h"
#include "contrib/wire_ctx.h"

#define SERIALIZE_RRSET_INIT (-1)
#define SERIALIZE_RRSET_DONE ((1L<<16)+1)

static int serialize_rrset(wire_ctx_t *wire, const knot_rrset_t *rrset, long *phase)
{
	assert(wire != NULL && rrset != NULL && phase != NULL);
	assert(*phase >= SERIALIZE_RRSET_INIT && *phase < SERIALIZE_RRSET_DONE);

	if (*phase == SERIALIZE_RRSET_INIT) {
		// write owner, type, class, rrcnt
		int size = knot_dname_to_wire(wire->position, rrset->owner,
		                              wire_ctx_available(wire));
		if (size < 0 || wire_ctx_available(wire) < size + 3 * sizeof(uint16_t)) {
			return KNOT_EOK;
		}
		wire_ctx_skip(wire, size);
		wire_ctx_write_u16(wire, rrset->type);
		wire_ctx_write_u16(wire, rrset->rclass);
		wire_ctx_write_u16(wire, rrset->rrs.rr_count);
		(*phase)++;
	}

	for ( ; *phase < rrset->rrs.rr_count; (*phase)++) {
		const knot_rdata_t *rr = knot_rdataset_at(&rrset->rrs, *phase);
		assert(rr);
		uint16_t rdlen = rr->len;
		if (wire_ctx_available(wire) < sizeof(uint32_t) + sizeof(uint16_t) + rdlen) {
			return KNOT_EOK;
		}
		// Compatibility, but one TTL per rrset would be enough.
		wire_ctx_write_u32(wire, rrset->ttl);
		wire_ctx_write_u16(wire, rdlen);
		wire_ctx_write(wire, rr->data, rdlen);
	}

	*phase = SERIALIZE_RRSET_DONE;
	return KNOT_EOK;
}

static int deserialize_rrset(wire_ctx_t *wire, knot_rrset_t *rrset, long *phase)
{
	assert(wire != NULL && rrset != NULL && phase != NULL);
	assert(*phase >= SERIALIZE_RRSET_INIT && *phase < SERIALIZE_RRSET_DONE);

	if (*phase == SERIALIZE_RRSET_INIT && wire_ctx_available(wire) > 0) {
		// Read owner, rtype, rclass and RR count.
		size_t size = knot_dname_size(wire->position);
		knot_dname_t *owner = knot_dname_copy(wire->position, NULL);
		if (owner == NULL || wire_ctx_available(wire) < size + 3 * sizeof(uint16_t)) {
			return KNOT_EMALF;
		}
		wire_ctx_skip(wire, size);
		uint16_t type = wire_ctx_read_u16(wire);
		uint16_t rclass = wire_ctx_read_u16(wire);
		uint16_t rrcount = wire_ctx_read_u16(wire);
		(*phase) = rrcount;
		if (wire->error != KNOT_EOK) {
			return wire->error;
		}
		knot_rrset_init(rrset, owner, type, rclass, 0);
	}

	bool first = true;
	for ( ; *phase > 0 && wire_ctx_available(wire) > 0; (*phase)--) {
		uint32_t ttl = wire_ctx_read_u32(wire);
		if (first) {
			rrset->ttl = ttl;
			first = false;
		}
		uint32_t rdata_size = wire_ctx_read_u16(wire);
		if (wire->error != KNOT_EOK ||
		    wire_ctx_available(wire) < rdata_size ||
		    knot_rrset_add_rdata(rrset, wire->position, rdata_size,
		                         NULL) != KNOT_EOK) {
			knot_rrset_clear(rrset, NULL);
			return KNOT_EMALF;
		}
		wire_ctx_skip(wire, rdata_size);
	}

	if (*phase == 0) {
		*phase = SERIALIZE_RRSET_DONE;
	}
	return KNOT_EOK;
}

static int serialize_rrset_chunks(wire_ctx_t *wire, const knot_rrset_t *rrset,
                                  uint8_t *dst_chunks[], size_t chunk_size,
                                  size_t chunks_count, size_t *chunks_real_sizes,
                                  size_t *cur_chunk)
{
	long phase = SERIALIZE_RRSET_INIT;
	while (1) {
		int ret = serialize_rrset(wire, rrset, &phase);
		if (ret != KNOT_EOK || phase == SERIALIZE_RRSET_DONE) {
			return ret;
		}
		// now the rrset didn't fit whole to this chunk
		if (*cur_chunk >= chunks_count - 1) {
			return KNOT_ESPACE;
		}
		if (wire->error != KNOT_EOK) {
			return wire->error;
		}
		chunks_real_sizes[*cur_chunk] = wire_ctx_offset(wire);
		(*cur_chunk)++;
		*wire = wire_ctx_init(dst_chunks[*cur_chunk], chunk_size);
	}
}

static int deserialize_rrset_chunks(wire_ctx_t *wire, knot_rrset_t *rrset,
                                    uint8_t *src_chunks[], const size_t *chunk_sizes,
                                    size_t chunks_count, size_t *cur_chunk)
{
	long phase = SERIALIZE_RRSET_INIT;
	while (1) {
		int ret = deserialize_rrset(wire, rrset, &phase);
		if (ret != KNOT_EOK || phase == SERIALIZE_RRSET_DONE) {
			return ret;
		}
		// now the rrset wasn't whole on this chunk
		if (*cur_chunk >= chunks_count - 1) {
			return KNOT_EMALF;
		}
		if (wire->error != KNOT_EOK) {
			return wire->error;
		}
		(*cur_chunk)++;
		assert(chunk_sizes[*cur_chunk] > 0);
		*wire = wire_ctx_init(src_chunks[*cur_chunk], chunk_sizes[*cur_chunk]);
	}
}

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
		size += sizeof(uint32_t) + sizeof(uint16_t) + rr->len;
	}

	return size;
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

int changeset_serialize(const changeset_t *ch, uint8_t *dst_chunks[],
                        size_t chunk_size, size_t chunks_count, size_t *chunks_real_sizes,
                        size_t *chunks_real_count)
{
	if (ch == NULL || dst_chunks == NULL || chunk_size == 0 || chunks_count == 0 ||
	    chunks_real_sizes == NULL || chunks_real_count == NULL) {
		return KNOT_EINVAL;
	}

	for (size_t i = 0; i < chunks_count; i++) {
		chunks_real_sizes[i] = 0;
	}

	wire_ctx_t wire = wire_ctx_init(dst_chunks[0], chunk_size);
	size_t cur_chunk = 0;

	if (ch->soa_from == NULL) {
		// serializing bootstrap changeset
		goto serialize_to; // note: it & ret & rrset are uninitialized here, we don't care
	}

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

serialize_to:
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
	int ret = deserialize_rrset_chunks(&wire, &rrset, src_chunks, chunks_sizes,
	                                   chunks_count, &cur_chunk);
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
	while (cur_chunk < chunks_count - 1 || wire_ctx_available(&wire) > 0) {
		// Parse next RRSet.
		ret = deserialize_rrset_chunks(&wire, &rrset, src_chunks, chunks_sizes,
		                               chunks_count, &cur_chunk);
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

	// If there was only one SOA record, we are in the bootstrap changeset.
	if (in_remove_section) {
		ch->soa_to = ch->soa_from;
		ch->soa_from = NULL;
		zone_contents_t *tmp = ch->add;
		ch->add = ch->remove;
		ch->remove = tmp;
	}

	return wire.error;
}
