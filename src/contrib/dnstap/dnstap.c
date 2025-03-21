/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdint.h>
#include <stdlib.h>

#include "contrib/dnstap/dnstap.h"
#include "contrib/dnstap/dnstap.pb-c.h"

#define DNSTAP_INITIAL_BUF_SIZE         256

uint8_t* dt_pack(const Dnstap__Dnstap *d, uint8_t **buf, size_t *sz)
{
	ProtobufCBufferSimple sbuf = { { NULL } };

	sbuf.base.append = protobuf_c_buffer_simple_append;
	sbuf.len = 0;
	sbuf.alloced = DNSTAP_INITIAL_BUF_SIZE;
	sbuf.data = malloc(sbuf.alloced);
	if (sbuf.data == NULL) {
		return NULL;
	}
	sbuf.must_free_data = 1;

	*sz = dnstap__dnstap__pack_to_buffer(d, (ProtobufCBuffer *) &sbuf);
	*buf = sbuf.data;
	return *buf;
}
