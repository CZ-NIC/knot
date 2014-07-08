/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>
#include <string.h>
#include <stdlib.h>

#include "common/mempool.h"
#include "libknot/descriptor.h"
#include "libknot/packet/wire.h"
#include "knot/nameserver/process_query.h"
#include "fake_server.h"

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
static void exec_query(knot_process_t *query_ctx, const char *name,
                       const uint8_t *query, uint16_t query_len,
                       uint8_t expected_rcode)
{
	uint16_t answer_len = KNOT_WIRE_MAX_PKTSIZE;
	uint8_t answer[KNOT_WIRE_MAX_PKTSIZE];

	/* Input packet. */
	int state = knot_process_in(query, query_len, query_ctx);

	ok(state & (NS_PROC_FULL|NS_PROC_FAIL), "ns: process %s query", name);

	/* Create answer. */
	state = knot_process_out(answer, &answer_len, query_ctx);
	if (state & NS_PROC_FAIL) {
		/* Allow 1 generic error response. */
		answer_len = KNOT_WIRE_MAX_PKTSIZE;
		state = knot_process_out(answer, &answer_len, query_ctx);
	}

	ok(state == NS_PROC_DONE, "ns: answer %s query", name);

	/* Check answer. */
	answer_sanity_check(query, answer, answer_len, expected_rcode, name);
}

/* \internal Helpers */
#define WIRE_COPY(dst, dst_len, src, src_len) \
	memcpy(dst, src, src_len); \
	dst_len = src_len;

int main(int argc, char *argv[])
{
	plan(8*6 + 4); /* exec_query = 6 TAP tests */

	/* Create processing context. */
	knot_process_t proc;
	memset(&proc, 0, sizeof(knot_process_t));
	mm_ctx_mempool(&proc.mm, sizeof(knot_pkt_t));

	/* Create fake server environment. */
	server_t server;
	int ret = create_fake_server(&server, &proc.mm);
	ok(ret == KNOT_EOK, "ns: fake server initialization");

	zone_t *zone = knot_zonedb_find(server.zone_db, ROOT_DNAME);

	/* Prepare. */
	knot_pkt_t *query = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, &proc.mm);

	/* Create query processing parameter. */
	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(struct sockaddr_storage));
	sockaddr_set(&ss, AF_INET, "127.0.0.1", 53);
	struct process_query_param param = {0};
	param.remote = &ss;
	param.server = &server;

	/* Query processor (CH zone) */
	knot_process_begin(&proc, &param, NS_PROC_QUERY);
	knot_pkt_clear(query);
	knot_pkt_put_question(query, IDSERVER_DNAME, KNOT_CLASS_CH, KNOT_RRTYPE_TXT);
	exec_query(&proc, "CH TXT", query->wire, query->size, KNOT_RCODE_NOERROR);

	/* Query processor (valid input). */
	knot_process_reset(&proc);
	knot_pkt_clear(query);
	knot_pkt_put_question(query, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);
	exec_query(&proc, "IN/root", query->wire, query->size, KNOT_RCODE_NOERROR);

	/* Query processor (-1 bytes, not enough data). */
	knot_process_reset(&proc);
	exec_query(&proc, "IN/few-data", query->wire, query->size - 1, KNOT_RCODE_FORMERR);

	/* Query processor (+1 bytes trailing). */
	knot_process_reset(&proc);
	query->wire[query->size] = '\1'; /* Initialize the "garbage" value. */
	exec_query(&proc, "IN/trail-garbage", query->wire, query->size + 1, KNOT_RCODE_FORMERR);

	/* Forge NOTIFY query from SOA query. */
	knot_process_reset(&proc);
	knot_wire_set_opcode(query->wire, KNOT_OPCODE_NOTIFY);
	exec_query(&proc, "IN/notify", query->wire, query->size, KNOT_RCODE_NOTAUTH);

	/* Forge AXFR query. */
	knot_process_reset(&proc);
	knot_pkt_clear(query);
	knot_pkt_put_question(query, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_AXFR);
	exec_query(&proc, "IN/axfr", query->wire, query->size, KNOT_RCODE_NOTAUTH);

	/* Forge IXFR query (badly formed, no SOA in AUTHORITY section). */
	knot_process_reset(&proc);
	knot_pkt_clear(query);
	knot_pkt_put_question(query, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_IXFR);
	exec_query(&proc, "IN/ixfr-formerr", query->wire, query->size, KNOT_RCODE_FORMERR);

	/* Forge IXFR query (well formed). */
	knot_process_reset(&proc);
	/* Append SOA RR. */
	knot_rrset_t soa_rr = node_rrset(zone->contents->apex, KNOT_RRTYPE_SOA);
	knot_pkt_begin(query, KNOT_AUTHORITY);
	knot_pkt_put(query, COMPR_HINT_NONE, &soa_rr, 0);
	exec_query(&proc, "IN/ixfr", query->wire, query->size, KNOT_RCODE_NOTAUTH);

	/* \note Tests below are not possible without proper zone and zone data. */
	/* #189 Process UPDATE query. */
	/* #189 Process AXFR client. */
	/* #189 Process IXFR client. */

	/* Query processor (smaller than DNS header, ignore). */
	knot_process_reset(&proc);
	knot_pkt_clear(query);
	knot_pkt_put_question(query, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);
	int state = knot_process_in(query->wire, KNOT_WIRE_HEADER_SIZE - 1, &proc);
	ok(state == NS_PROC_NOOP, "ns: IN/less-than-header query ignored");

	/* Query processor (response, ignore). */
	knot_process_reset(&proc);
	knot_wire_set_qr(query->wire);
	state = knot_process_in(query->wire, query->size, &proc);
	ok(state == NS_PROC_NOOP, "ns: IN/less-than-header query ignored");

	/* Finish. */
	state = knot_process_finish(&proc);
	ok(state == NS_PROC_NOOP, "ns: processing end" );

	/* Cleanup. */
	mp_delete((struct mempool *)proc.mm.ctx);
	server_deinit(&server);

	return 0;
}

#undef WIRE_COPY
