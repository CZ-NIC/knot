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

#include <assert.h>

#include "knot/journal/serialization.h"
#include "libknot/libknot.h"

#define SERIALIZE_RRSET_INIT (-1)
#define SERIALIZE_RRSET_DONE ((1L<<16)+1)

typedef enum {
	PHASE_SOA_1,
	PHASE_REM,
	PHASE_SOA_2,
	PHASE_ADD,
	PHASE_END,
} serialize_phase_t;

#define RRSET_BUF_MAXSIZE 256

struct serialize_ctx {
	const changeset_t *ch;
	changeset_iter_t it;
	serialize_phase_t changeset_phase;
	long rrset_phase;
	knot_rrset_t rrset_buf[RRSET_BUF_MAXSIZE];
	size_t rrset_buf_size;
};

serialize_ctx_t *serialize_init(const changeset_t *ch)
{
	serialize_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return NULL;
	}

	ctx->ch = ch;
	ctx->changeset_phase = ch->soa_from != NULL ? PHASE_SOA_1 : PHASE_SOA_2;
	ctx->rrset_phase = SERIALIZE_RRSET_INIT;
	ctx->rrset_buf_size = 0;

	return ctx;
}

static knot_rrset_t get_next_rrset(serialize_ctx_t *ctx)
{
	knot_rrset_t res;
	knot_rrset_init_empty(&res);
	switch (ctx->changeset_phase) {
	case PHASE_SOA_1:
		changeset_iter_rem(&ctx->it, ctx->ch);
		ctx->changeset_phase = PHASE_REM;
		return *ctx->ch->soa_from;
	case PHASE_REM:
		res = changeset_iter_next(&ctx->it);
		if (knot_rrset_empty(&res)) {
			changeset_iter_clear(&ctx->it);
			changeset_iter_add(&ctx->it, ctx->ch);
			ctx->changeset_phase = PHASE_ADD;
			return *ctx->ch->soa_to;
		}
		return res;
	case PHASE_SOA_2:
		if (ctx->it.node != NULL) {
			changeset_iter_clear(&ctx->it);
		}
		changeset_iter_add(&ctx->it, ctx->ch);
		ctx->changeset_phase = PHASE_ADD;
		return *ctx->ch->soa_to;
	case PHASE_ADD:
		res = changeset_iter_next(&ctx->it);
		if (knot_rrset_empty(&res)) {
			changeset_iter_clear(&ctx->it);
			ctx->changeset_phase = PHASE_END;
		}
		return res;
	default:
		return res;
	}
}

void serialize_prepare(serialize_ctx_t *ctx, size_t max_size, size_t *realsize)
{
	*realsize = 0;

	// check if we are in middle of a rrset
	if (ctx->rrset_buf_size > 0) {
		ctx->rrset_buf[0] = ctx->rrset_buf[ctx->rrset_buf_size - 1];
		ctx->rrset_buf_size = 1;
	} else {
		ctx->rrset_buf[0] = get_next_rrset(ctx);
		if (ctx->changeset_phase == PHASE_END) {
			ctx->rrset_buf_size = 0;
			return;
		}
		ctx->rrset_buf_size = 1;
	}

	size_t candidate = 0;
	long tmp_phase = ctx->rrset_phase;
	while (1) {
		if (tmp_phase >= ctx->rrset_buf[ctx->rrset_buf_size - 1].rrs.count) {
			if (ctx->rrset_buf_size >= RRSET_BUF_MAXSIZE) {
				return;
			}
			ctx->rrset_buf[ctx->rrset_buf_size++] = get_next_rrset(ctx);
			if (ctx->changeset_phase == PHASE_END) {
				ctx->rrset_buf_size--;
				return;
			}
			tmp_phase = SERIALIZE_RRSET_INIT;
		}
		if (tmp_phase == SERIALIZE_RRSET_INIT) {
			candidate += 3 * sizeof(uint16_t) +
			             knot_dname_size(ctx->rrset_buf[ctx->rrset_buf_size - 1].owner);
		} else {
			candidate += sizeof(uint32_t) + sizeof(uint16_t) +
			             knot_rdataset_at(&ctx->rrset_buf[ctx->rrset_buf_size - 1].rrs, tmp_phase)->len;
		}
		if (candidate > max_size) {
			return;
		}
		*realsize = candidate;
		tmp_phase++;
	}
}

void serialize_chunk(serialize_ctx_t *ctx, uint8_t *dst_chunk, size_t chunk_size)
{
	wire_ctx_t wire = wire_ctx_init(dst_chunk, chunk_size);

	for (size_t i = 0; ; ) {
		if (ctx->rrset_phase >= ctx->rrset_buf[i].rrs.count) {
			if (++i >= ctx->rrset_buf_size) {
				break;
			}
			ctx->rrset_phase = SERIALIZE_RRSET_INIT;
		}
		if (ctx->rrset_phase == SERIALIZE_RRSET_INIT) {
			int size = knot_dname_to_wire(wire.position, ctx->rrset_buf[i].owner,
			                              wire_ctx_available(&wire));
			if (size < 0 || wire_ctx_available(&wire) < size + 3 * sizeof(uint16_t)) {
				break;
			}
			wire_ctx_skip(&wire, size);
			wire_ctx_write_u16(&wire, ctx->rrset_buf[i].type);
			wire_ctx_write_u16(&wire, ctx->rrset_buf[i].rclass);
			wire_ctx_write_u16(&wire, ctx->rrset_buf[i].rrs.count);
		} else {
			const knot_rdata_t *rr = knot_rdataset_at(&ctx->rrset_buf[i].rrs,
			                                          ctx->rrset_phase);
			assert(rr);
			uint16_t rdlen = rr->len;
			if (wire_ctx_available(&wire) < sizeof(uint32_t) + sizeof(uint16_t) + rdlen) {
				break;
			}
			// Compatibility, but one TTL per rrset would be enough.
			wire_ctx_write_u32(&wire, ctx->rrset_buf[i].ttl);
			wire_ctx_write_u16(&wire, rdlen);
			wire_ctx_write(&wire, rr->data, rdlen);
		}
		ctx->rrset_phase++;
	}
}

bool serialize_unfinished(serialize_ctx_t *ctx)
{
	return ctx->changeset_phase < PHASE_END;
}

void serialize_deinit(serialize_ctx_t *ctx)
{
	if (ctx->it.node != NULL) {
		changeset_iter_clear(&ctx->it);
	}
	free(ctx);
}

static uint64_t rrset_binary_size(const knot_rrset_t *rrset)
{
	if (rrset == NULL || rrset->rrs.count == 0) {
		return 0;
	}

	// Owner size + type + class + RR count.
	uint64_t size = knot_dname_size(rrset->owner) + 3 * sizeof(uint16_t);

	// RRs.
	knot_rdata_t *rr = rrset->rrs.rdata;
	for (uint16_t i = 0; i < rrset->rrs.count; i++) {
		// TTL + RR size + RR.
		size += sizeof(uint32_t) + sizeof(uint16_t) + rr->len;
		rr = knot_rdataset_next(rr);
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
	if (ch->remove == NULL) {
		changeset_iter_add(&it, ch);
	} else {
		changeset_iter_all(&it, ch);
	}

	size_t change_size = 0;
	knot_rrset_t rrset = changeset_iter_next(&it);
	while (!knot_rrset_empty(&rrset)) {
		change_size += rrset_binary_size(&rrset);
		rrset = changeset_iter_next(&it);
	}

	changeset_iter_clear(&it);

	return soa_from_size + soa_to_size + change_size;
}

int serialize_rrset(wire_ctx_t *wire, const knot_rrset_t *rrset)
{
	assert(wire != NULL && rrset != NULL);

	// write owner, type, class, rrcnt
	int size = knot_dname_to_wire(wire->position, rrset->owner,
				      wire_ctx_available(wire));
	if (size < 0 || wire_ctx_available(wire) < size + 3 * sizeof(uint16_t)) {
			assert(0);
	}
	wire_ctx_skip(wire, size);
	wire_ctx_write_u16(wire, rrset->type);
	wire_ctx_write_u16(wire, rrset->rclass);
	wire_ctx_write_u16(wire, rrset->rrs.count);

	for (size_t phase = 0; phase < rrset->rrs.count; phase++) {
		const knot_rdata_t *rr = knot_rdataset_at(&rrset->rrs, phase);
		assert(rr);
		uint16_t rdlen = rr->len;
		if (wire_ctx_available(wire) < sizeof(uint32_t) + sizeof(uint16_t) + rdlen) {
			assert(0);
		}
		wire_ctx_write_u32(wire, rrset->ttl);
		wire_ctx_write_u16(wire, rdlen);
		wire_ctx_write(wire, rr->data, rdlen);
	}

	return KNOT_EOK;
}

int deserialize_rrset(wire_ctx_t *wire, knot_rrset_t *rrset)
{
	assert(wire != NULL && rrset != NULL);

	// Read owner, rtype, rclass and RR count.
	int size = knot_dname_size(wire->position);
	if (size < 0) {
		assert(0);
	}
	knot_dname_t *owner = knot_dname_copy(wire->position, NULL);
	if (owner == NULL || wire_ctx_available(wire) < size + 3 * sizeof(uint16_t)) {
		knot_dname_free(owner, NULL);
		return KNOT_EMALF;
	}
	wire_ctx_skip(wire, size);
	uint16_t type = wire_ctx_read_u16(wire);
	uint16_t rclass = wire_ctx_read_u16(wire);
	uint16_t rrcount = wire_ctx_read_u16(wire);
	if (wire->error != KNOT_EOK) {
		knot_dname_free(owner, NULL);
		return wire->error;
	}
	if (rrset->owner != NULL) {
		if (knot_dname_cmp(owner, rrset->owner) != 0) {
			knot_dname_free(owner, NULL);
			return KNOT_ESEMCHECK;
		}
		knot_rrset_clear(rrset, NULL);
	}
	knot_rrset_init(rrset, owner, type, rclass, 0);

	for (size_t phase = 0; phase < rrcount && wire_ctx_available(wire) > 0; phase++) {
		uint32_t ttl = wire_ctx_read_u32(wire);
		uint32_t rdata_size = wire_ctx_read_u16(wire);
		if (phase == 0) {
			rrset->ttl = ttl;
		}
		if (wire->error != KNOT_EOK ||
		    wire_ctx_available(wire) < rdata_size ||
		    knot_rrset_add_rdata(rrset, wire->position, rdata_size,
					 NULL) != KNOT_EOK) {
			knot_rrset_clear(rrset, NULL);
			return KNOT_EMALF;
		}
		wire_ctx_skip(wire, rdata_size);
	}

	return KNOT_EOK;
}

size_t rrset_serialized_size(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}

	// Owner size + type + class + RR count.
	size_t size = knot_dname_size(rrset->owner) + 3 * sizeof(uint16_t);

	for (uint16_t i = 0; i < rrset->rrs.count; i++) {
		const knot_rdata_t *rr = knot_rdataset_at(&rrset->rrs, i);
		assert(rr);
		// TTL + RR size + RR.
		size += sizeof(uint32_t) + sizeof(uint16_t) + rr->len;
	}

	return size;
}
