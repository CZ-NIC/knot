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
	uint64_t size = /* sizeof(uint64_t) + // size at the beginning */
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

static int serialize_rrset(wire_ctx_t *wire, const knot_rrset_t *rrset)
{
	assert(wire);
	assert(rrset);

	/* Write owner. */
	int size = knot_dname_to_wire(wire->position, rrset->owner,
				      wire_ctx_available(wire));
	if (size < 0) {
		return size;
	}
	wire_ctx_skip(wire, size);

	/* Write rtype, rclass and RR count. */
	wire_ctx_write_u16(wire, rrset->type);
	wire_ctx_write_u16(wire, rrset->rclass);
	wire_ctx_write_u16(wire, rrset->rrs.rr_count);

	/* Write rdata items. */
	for (uint16_t i = 0; i < rrset->rrs.rr_count; i++) {
		const knot_rdata_t *rr = knot_rdataset_at(&rrset->rrs, i);
		assert(rr != NULL);
		wire_ctx_write_u32(wire, knot_rdata_ttl(rr));
		wire_ctx_write_u32(wire, knot_rdata_rdlen(rr));
		wire_ctx_write(wire, knot_rdata_data(rr), knot_rdata_rdlen(rr));
	}

	return wire->error;
}

static int deserialize_rrset(wire_ctx_t *wire, knot_rrset_t *rrset)
{
	assert(wire);
	assert(rrset);

	/* Read owner. */
	int size = knot_dname_size(wire->position);
	if (size < 0) {
		return size;
	}
	knot_dname_t *owner = knot_dname_copy_part(wire->position, size, NULL);
	if (owner == NULL) {
		return KNOT_EMALF;
	}
	wire_ctx_skip(wire, size);

	/* Read rtype, rclass and RR count. */
	uint16_t type = wire_ctx_read_u16(wire);
	uint16_t rclass = wire_ctx_read_u16(wire);
	uint16_t count = wire_ctx_read_u16(wire);
	if (wire->error != KNOT_EOK) {
		return wire->error;
	}

	knot_rrset_init(rrset, owner, type, rclass);

	/* Read rdata items. */
	for (uint16_t i = 0; i < count; i++) {
		uint32_t ttl = wire_ctx_read_u32(wire);
		uint32_t rdata_size = wire_ctx_read_u32(wire);
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

int serialize_rrset_chunks(wire_ctx_t *wire, const knot_rrset_t *rrset, uint8_t *dst_chunks[], size_t chunk_size, int chunks_count, size_t *chunks_real_sizes, int *cur_chunk)
{
	if (wire == NULL || chunks_real_sizes == NULL || cur_chunk == NULL || *cur_chunk < 0) return KNOT_EINVAL;

	while (wire_ctx_available(wire) < rrset_binary_size(rrset)) {
		chunks_real_sizes[*cur_chunk] = wire_ctx_offset(wire);
		if (*cur_chunk >= chunks_count - 1) {
			return KNOT_ESPACE;
		}
		// move to next chunk
		if (wire->error != KNOT_EOK) {
			return wire->error;
		}
		(*cur_chunk)++;
		*wire = wire_ctx_init(dst_chunks[*cur_chunk], chunk_size);
	}

	return serialize_rrset(wire, rrset);
}

/*!
 * \brief Serializes given changeset into chunked area.
 *
 * \param ch The changeset; dst_chunks The chunks to serialize into; chunk_size Maximum size of each chunk; chunks_count Maximum number of used chunks
 * \param chunks_real_sizes Output: real size of each chunk after serialization, or zeros for unused chunks
 * \param chunks_real_count Output: real # of chunks after serialization. Can be wrong if error returned!
 *
 * \retval KNOT_E*
 */
int changeset_serialize_chunks(const changeset_t *ch, uint8_t *dst_chunks[], size_t chunk_size, int chunks_count, size_t *chunks_real_sizes, int *chunks_real_count)
{
	if (ch == NULL) {
		return KNOT_EINVAL;
	}

	for (int i = 0; i < chunks_count; i++) chunks_real_sizes[i] = 0;

	wire_ctx_t wire = wire_ctx_init(dst_chunks[0], chunk_size);;
	int cur_chunk = 0;

	/* Serialize SOA 'from'. */
	int ret = serialize_rrset_chunks(&wire, ch->soa_from, dst_chunks, chunk_size, chunks_count, chunks_real_sizes, &cur_chunk);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Serialize RRSets from the 'rem' section. */
	changeset_iter_t it;
	ret = changeset_iter_rem(&it, ch);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_rrset_t rrset = changeset_iter_next(&it);
	while (!knot_rrset_empty(&rrset)) {
		ret = serialize_rrset_chunks(&wire, &rrset, dst_chunks, chunk_size, chunks_count, chunks_real_sizes, &cur_chunk);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&it);
			return ret;
		}
		rrset = changeset_iter_next(&it);
	}
	changeset_iter_clear(&it);

	/* Serialize SOA 'to'. */
	ret = serialize_rrset_chunks(&wire, ch->soa_to, dst_chunks, chunk_size, chunks_count, chunks_real_sizes, &cur_chunk);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Serialize RRSets from the 'add' section. */
	ret = changeset_iter_add(&it, ch);
	if (ret != KNOT_EOK) {
		return ret;
	}

	rrset = changeset_iter_next(&it);
	while (!knot_rrset_empty(&rrset)) {
		ret = serialize_rrset_chunks(&wire, &rrset, dst_chunks, chunk_size, chunks_count, chunks_real_sizes, &cur_chunk);
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

/*!
 * \brief Deserializes chunked area into ch
 */
int changeset_deserialize_chunks(changeset_t *ch, uint8_t *src_chunks[], const size_t *chunks_sizes, int chunks_count)
{
	if (ch == NULL || chunks_sizes == NULL || chunks_count == 0) {
		return KNOT_EINVAL;
	}

	int cur_chunk = 0;
	wire_ctx_t wire = wire_ctx_init_const(src_chunks[0], chunks_sizes[0]);

	// Deserialize SOA 'from'
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
		while (wire_ctx_available(&wire) <= 0) {
			if (wire.error != KNOT_EOK) return wire.error;
			if (++cur_chunk >= chunks_count) return KNOT_EOK; // HERE the standard end of the loop
			wire = wire_ctx_init_const(src_chunks[cur_chunk], chunks_sizes[cur_chunk]);
		}

		// Parse next RRSet.
		ret = deserialize_rrset(&wire, &rrset);
		if (ret != KNOT_EOK) {
			break;
		}

		// Check for next SOA.
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

int changeset_serialize(const changeset_t *ch, uint8_t *dst, size_t size)
{
	int ret, real_count = 0;
	size_t ignored_real_size;
	ret = changeset_serialize_chunks(ch, &dst, size, 1, &ignored_real_size, &real_count);
	assert(real_count == 0 || real_count == 1);
	if (ret == KNOT_EOK && size > 0 && real_count != 1) {
		ret = KNOT_ERROR;
	}
	return ret;
}

int changeset_deserialize(changeset_t *ch, const uint8_t *src, size_t size)
{
	return changeset_deserialize_chunks(ch, (uint8_t **) &src, &size, 1);
}
