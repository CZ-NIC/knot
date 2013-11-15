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

#include <config.h>
#include <tap/basic.h>

#include "common/mempool.h"
#include "libknot/packet/wire.h"
#include "libknot/nameserver/name-server.h"
#include "libknot/nameserver/ns_proc_query.h"

/* root zone query */
#define IN_QUERY_LEN 28
static const uint8_t IN_QUERY[IN_QUERY_LEN] = {
	0xac, 0x77, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x29,
	0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* CH TXT id.server */
#define CH_QUERY_LEN 27
static const uint8_t CH_QUERY[CH_QUERY_LEN] = {
	0xa0, 0xa2, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x69, 0x64, 0x06, 0x73, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x00, 0x00, 0x10, 0x00, 0x03
};

int main(int argc, char *argv[])
{
	plan(12);

	/* Prepare. */
	int state = NS_PROC_FAIL;
	uint8_t wire[KNOT_WIRE_MAX_PKTSIZE];
	uint16_t wire_len = KNOT_WIRE_MAX_PKTSIZE;

	/* Create fake name server. */
	knot_nameserver_t *ns = knot_ns_create();

	/* Create processing context. */
	ns_proc_context_t query_ctx;
	memset(&query_ctx, 0, sizeof(ns_proc_context_t));
	mm_ctx_mempool(&query_ctx.mm, sizeof(knot_pkt_t));
	query_ctx.ns = ns;

	/* Query processor (valid input). */
	state = ns_proc_begin(&query_ctx, NS_PROC_QUERY);
	ok(state & NS_PROC_MORE, "ns: init QUERY processor");
	state = ns_proc_in(IN_QUERY, IN_QUERY_LEN, &query_ctx);
	ok(state & NS_PROC_FULL, "ns: process IN query" );
	wire_len = sizeof(wire);
	state = ns_proc_out(wire, &wire_len, &query_ctx);
	ok(state & NS_PROC_FINISH, "ns: answer IN query" );

	/* Query processor (CH zone) */
	state = ns_proc_reset(&query_ctx);
	ok(state & NS_PROC_MORE, "ns: reset processing context" );
	state = ns_proc_in(CH_QUERY, CH_QUERY_LEN, &query_ctx);
	ok(state & NS_PROC_FULL, "ns: process CH query");
	wire_len = sizeof(wire);
	state = ns_proc_out(wire, &wire_len, &query_ctx);
	ok(state & NS_PROC_FINISH, "ns: answer CH query");
	/* Brief response check. */
	ok(wire_len > KNOT_WIRE_HEADER_SIZE, "ns: CH response > DNS header");
	ok(knot_wire_get_qr(wire), "ns: CH response has QR=1");
	is_int(KNOT_RCODE_NOERROR, knot_wire_get_rcode(wire), "ns: CH response RCODE=0");
	is_int(knot_wire_get_id(CH_QUERY), knot_wire_get_id(wire), "ns: CH MsgId match");

	/* Query processor (invalid input). */
	ns_proc_reset(&query_ctx);
	state = ns_proc_in(IN_QUERY, IN_QUERY_LEN - 1, &query_ctx);
	ok(state & NS_PROC_FAIL, "ns: process malformed SOA query" );
	state = ns_proc_finish(&query_ctx);
	ok(state & NS_PROC_FINISH, "ns: processing end" );

	/* #10 Process NOTIFY query. */

	/* #10 Process AXFR query. */

	/* #10 Process IXFR query. */

	/* #10 Process UPDATE query. */

	/* #10 Process AXFR client. */

	/* #10 Process IXFR client. */

	/* Cleanup. */
	mp_delete((struct mempool *)query_ctx.mm.ctx);
	knot_ns_destroy(&ns);

	return 0;
}
