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

#pragma once

#include "contrib/wire_ctx.h"
#include "knot/dnssec/zone-keys.h"

void key_records_init(const kdnssec_ctx_t *ctx, key_records_t *r);

int key_records_add_rdata(key_records_t *r, uint16_t rrtype, uint8_t *rdata, uint16_t rdlen, uint32_t ttl);

void key_records_clear(key_records_t *r);

void key_records_clear_rdatasets(key_records_t *r);

int key_records_dump(char **buf, size_t *buf_size, const key_records_t *r);

int key_records_sign(const zone_key_t *key, key_records_t *r, const kdnssec_ctx_t *kctx);

size_t key_records_serialized_size(const key_records_t *r);

int key_records_serialize(wire_ctx_t *wire, const key_records_t *r);

int key_records_deserialize(wire_ctx_t *wire, key_records_t *r);
