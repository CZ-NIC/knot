/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

enum input_format {
	TXT = 0,
	BIN
};

typedef struct {
	const char *path;
	enum input_format format;
} input_t;

struct pkt_payload {
	struct pkt_payload *next;
	size_t len;
	uint8_t payload[];
};

extern struct pkt_payload *global_payloads;

bool load_queries(const input_t *input, uint16_t edns_size, uint16_t msgid, size_t maxcount);

void free_global_payloads(void);
