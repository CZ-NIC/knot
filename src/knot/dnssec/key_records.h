/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "contrib/wire_ctx.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/updates/changesets.h"

void key_records_init(const kdnssec_ctx_t *ctx, key_records_t *r);

void key_records_from_apex(const zone_node_t *apex, key_records_t *r);

int key_records_add_rdata(key_records_t *r, uint16_t rrtype, uint8_t *rdata, uint16_t rdlen, uint32_t ttl);

void key_records_clear(key_records_t *r);

void key_records_clear_rdatasets(key_records_t *r);

int key_records_to_changeset(const key_records_t *r, changeset_t *ch,
                             bool rem, changeset_flag_t chfl);

int key_records_subtract(key_records_t *r, const key_records_t *against);

int key_records_intersect(key_records_t *r, const key_records_t *against);

int key_records_dump(char **buf, size_t *buf_size, const key_records_t *r, bool verbose);

int key_records_sign(const zone_key_t *key, key_records_t *r, const kdnssec_ctx_t *kctx);

// WARNING this modifies 'kctx' with updated timestamp and with zone_keys from r->dnskey
int key_records_verify(key_records_t *r, kdnssec_ctx_t *kctx, knot_time_t timestamp, knot_time_t min_valid);

size_t key_records_serialized_size(const key_records_t *r);

int key_records_serialize(wire_ctx_t *wire, const key_records_t *r);

int key_records_deserialize(wire_ctx_t *wire, key_records_t *r);

// Returns now if no records available.
int key_records_last_timestamp(kdnssec_ctx_t *ctx, knot_time_t *last);
