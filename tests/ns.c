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
#include "common/descriptor.h"
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

/* SOA RDATA. */
#define SOA_RDLEN 30
static const uint8_t SOA_RDATA[SOA_RDLEN] = {
        0x02, 0x6e, 0x73, 0x00,        /* ns. */
        0x04, 'm', 'a', 'i', 'l', 0x00,/* mail. */
        0x77, 0xdf, 0x1e, 0x63,        /* serial */
        0x00, 0x01, 0x51, 0x80,        /* refresh */
        0x00, 0x00, 0x1c, 0x20,        /* retry */
        0x00, 0x0a, 0x8c, 0x00,        /* expire */
        0x00, 0x00, 0x0e, 0x10         /* min ttl */
};

#include "common/log.h"
int main(int argc, char *argv[])
{
	log_init();
	plan(12);

	/* Prepare. */
	int state = NS_PROC_FAIL;
	uint8_t wire[KNOT_WIRE_MAX_PKTSIZE];
	uint16_t wire_len = KNOT_WIRE_MAX_PKTSIZE;

	/* Create fake name server. */
	knot_nameserver_t *ns = knot_ns_create();
	ns->opt_rr = knot_edns_new();
	knot_edns_set_version(ns->opt_rr, EDNS_VERSION); 
	knot_edns_set_payload(ns->opt_rr, 4096);

	/* Insert root zone. */
	knot_dname_t *root_name = knot_dname_from_str(".");
	knot_node_t *apex = knot_node_new(root_name, NULL, 0);
	knot_rrset_t *soa_rrset = knot_rrset_new(root_name,
	                                         KNOT_RRTYPE_SOA, KNOT_CLASS_IN,
	                                         7200);
	knot_rrset_add_rdata(soa_rrset, SOA_RDATA, SOA_RDLEN);
	knot_node_add_rrset(apex, soa_rrset);
	knot_zone_t *root = knot_zone_new(apex);
	knot_zonedb_free(&ns->zone_db);
	ns->zone_db = knot_zonedb_new(1);
	knot_zonedb_add_zone(ns->zone_db, root);
	knot_zonedb_build_index(ns->zone_db);
	assert(knot_zonedb_find_zone_for_name(ns->zone_db, root_name));

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
