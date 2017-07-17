/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <tap/basic.h>
#include <string.h>
#include <stdlib.h>

#include "libknot/descriptor.h"
#include "libknot/packet/wire.h"
#include "knot/nameserver/process_query.h"
#include "test_server.h"
#include "contrib/sockaddr.h"
#include "contrib/ucw/mempool.h"

/* Basic response check (4 TAP tests). */
static void answer_sanity_check(const uint8_t *query,
                                const uint8_t *answer, uint16_t answer_len,
                                uint8_t expected_rcode, const char *name)
{
	ok(answer_len >= KNOT_WIRE_HEADER_SIZE, "ns: len(%s answer) >= DNS header", name);
	if (answer_len >= KNOT_WIRE_HEADER_SIZE) {
		ok(knot_wire_get_qr(answer), "ns: %s answer has QR=1", name);
		is_int(expected_rcode, knot_wire_get_rcode(answer), "ns: %s answer RCODE=%d", name, expected_rcode);
		is_int(knot_wire_get_id(query), knot_wire_get_id(answer), "ns: %s MSGID match", name);
	} else {
		skip_block(3, "ns: can't check DNS header");
	}

}

/* Resolve query and check answer for sanity (2 TAP tests). */
static void exec_query(knot_layer_t *query_ctx, const char *name,
                       knot_pkt_t *query,
                       uint8_t expected_rcode)
{
	knot_pkt_t *answer = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	assert(answer);

	/* Input packet. */
	knot_pkt_parse(query, 0);
	int state = knot_layer_consume(query_ctx, query);

	ok(state == KNOT_STATE_PRODUCE || state == KNOT_STATE_FAIL, "ns: process %s query", name);

	/* Create answer. */
	state = knot_layer_produce(query_ctx, answer);
	if (state == KNOT_STATE_FAIL) {
		/* Allow 1 generic error response. */
		state = knot_layer_produce(query_ctx, answer);
	}

	ok(state == KNOT_STATE_DONE, "ns: answer %s query", name);

	/* Check answer. */
	answer_sanity_check(query->wire, answer->wire, answer->size, expected_rcode, name);

	knot_pkt_free(&answer);
}

/* \internal Helpers */
#define WIRE_COPY(dst, dst_len, src, src_len) \
	memcpy(dst, src, src_len); \
	dst_len = src_len;

int main(int argc, char *argv[])
{
	plan_lazy();

	knot_mm_t mm;
	mm_ctx_mempool(&mm, MM_DEFAULT_BLKSIZE);

	/* Create processing context. */
	knot_layer_t proc;
	memset(&proc, 0, sizeof(knot_layer_t));
	knot_layer_init(&proc, &mm, process_query_layer());

	/* Create fake server environment. */
	server_t server;
	int ret = create_fake_server(&server, proc.mm);
	is_int(KNOT_EOK, ret, "ns: fake server initialization");

	zone_t *zone = knot_zonedb_find(server.zone_db, ROOT_DNAME);

	/* Prepare. */
	knot_pkt_t *query = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, proc.mm);

	/* Create query processing parameter. */
	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(struct sockaddr_storage));
	sockaddr_set(&ss, AF_INET, "127.0.0.1", 53);
	knotd_qdata_params_t params = {
		.remote = &ss,
		.server = &server
	};

	/* Query processor (CH zone) */
	knot_layer_begin(&proc, &params);
	knot_pkt_clear(query);
	knot_pkt_put_question(query, IDSERVER_DNAME, KNOT_CLASS_CH, KNOT_RRTYPE_TXT);
	exec_query(&proc, "CH TXT", query, KNOT_RCODE_NOERROR);

	/* Query processor (valid input). */
	knot_layer_reset(&proc);
	knot_pkt_clear(query);
	knot_pkt_put_question(query, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);
	exec_query(&proc, "IN/root", query, KNOT_RCODE_NOERROR);

	/* Query processor (-1 bytes, not enough data). */
	knot_layer_reset(&proc);
	query->size -= 1;
	exec_query(&proc, "IN/few-data", query, KNOT_RCODE_FORMERR);
	query->size += 1;

	/* Query processor (+1 bytes trailing). */
	knot_layer_reset(&proc);
	query->wire[query->size] = '\1'; /* Initialize the "garbage" value. */
	query->size += 1;
	exec_query(&proc, "IN/trail-garbage", query, KNOT_RCODE_FORMERR);
	query->size -= 1;

	/* Forge NOTIFY query from SOA query. */
	knot_layer_reset(&proc);
	knot_wire_set_opcode(query->wire, KNOT_OPCODE_NOTIFY);
	exec_query(&proc, "IN/notify", query, KNOT_RCODE_NOTAUTH);

	/* Forge AXFR query. */
	knot_layer_reset(&proc);
	knot_pkt_clear(query);
	knot_pkt_put_question(query, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_AXFR);
	exec_query(&proc, "IN/axfr", query, KNOT_RCODE_NOTAUTH);

	/* Forge IXFR query (well formed). */
	knot_layer_reset(&proc);
	knot_pkt_clear(query);
	knot_pkt_put_question(query, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_IXFR);
	/* Append SOA RR. */
	knot_rrset_t soa_rr = node_rrset(zone->contents->apex, KNOT_RRTYPE_SOA);
	knot_pkt_begin(query, KNOT_AUTHORITY);
	knot_pkt_put(query, KNOT_COMPR_HINT_NONE, &soa_rr, 0);
	exec_query(&proc, "IN/ixfr", query, KNOT_RCODE_NOTAUTH);

	/* \note Tests below are not possible without proper zone and zone data. */
	/* #189 Process UPDATE query. */
	/* #189 Process AXFR client. */
	/* #189 Process IXFR client. */

	/* Query processor (smaller than DNS header, ignore). */
	knot_layer_reset(&proc);
	knot_pkt_clear(query);
	knot_pkt_put_question(query, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);
	size_t orig_query_size = query->size;
	query->size = KNOT_WIRE_HEADER_SIZE - 1;
	int state = knot_layer_consume(&proc, query);
	ok(state == KNOT_STATE_NOOP, "ns: IN/less-than-header query ignored");
	query->size = orig_query_size;

	/* Query processor (response, ignore). */
	knot_layer_reset(&proc);
	knot_wire_set_qr(query->wire);
	state = knot_layer_consume(&proc, query);
	ok(state == KNOT_STATE_NOOP, "ns: IN/less-than-header query ignored");

	/* Finish. */
	state = knot_layer_finish(&proc);
	ok(state == KNOT_STATE_NOOP, "ns: processing end" );

	/* Cleanup. */
	mp_delete((struct mempool *)mm.ctx);
	server_deinit(&server);
	conf_free(conf());

	return 0;
}

#undef WIRE_COPY
