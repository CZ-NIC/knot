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
#include "knot/nameserver/name-server.h"
#include "knot/nameserver/ns_proc_query.h"
#include "knot/server/zones.h"

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

/* Create fake root zone. */
void create_root_zone(knot_nameserver_t *ns, mm_ctx_t *mm)
{
	/* Insert root zone. */
	knot_dname_t *root_name = knot_dname_from_str(".");
	knot_node_t *apex = knot_node_new(root_name, NULL, 0);
	knot_rrset_t *soa_rrset = knot_rrset_new(root_name,
	                                         KNOT_RRTYPE_SOA, KNOT_CLASS_IN,
	                                         7200);
	knot_rrset_add_rdata(soa_rrset, SOA_RDATA, SOA_RDLEN);
	knot_node_add_rrset(apex, soa_rrset);
	knot_zone_t *root = knot_zone_new(apex);

	/* Stub data. */
	root->data = mm->alloc(mm->ctx, sizeof(zonedata_t));
	memset(root->data, 0, sizeof(zonedata_t));

	/* Bake the zone. */
	knot_node_t *first_nsec3 = NULL, *last_nsec3 = NULL;
	knot_zone_contents_adjust_full(root->contents, &first_nsec3, &last_nsec3);

	/* Switch zone db. */
	knot_zonedb_free(&ns->zone_db);
	ns->zone_db = knot_zonedb_new(1);
	knot_zonedb_insert(ns->zone_db, root);
	knot_zonedb_build_index(ns->zone_db);
}

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
static void exec_query(ns_proc_context_t *query_ctx, const char *name,
                       const uint8_t *query, uint16_t query_len,
                       uint8_t expected_rcode)
{
	uint16_t answer_len = KNOT_WIRE_MAX_PKTSIZE;
	uint8_t answer[KNOT_WIRE_MAX_PKTSIZE];

	/* Input packet. */
	int state = ns_proc_in(query, query_len, query_ctx);

	ok(state & (NS_PROC_FULL|NS_PROC_FAIL), "ns: process %s query", name);

	/* Create answer. */
	state = ns_proc_out(answer, &answer_len, query_ctx);
	if (state & NS_PROC_FAIL) {
		/* Allow 1 generic error response. */
		answer_len = KNOT_WIRE_MAX_PKTSIZE;
		state = ns_proc_out(answer, &answer_len, query_ctx);
	}

	ok(state == NS_PROC_DONE, "ns: answer %s query", name);

	/* Check answer. */
	answer_sanity_check(query, answer, answer_len, expected_rcode, name);
}

/* \internal Helpers */
#define WIRE_COPY(dst, dst_len, src, src_len) \
	memcpy(dst, src, src_len); \
	dst_len = src_len;

#define ROOT_DNAME ((const uint8_t *)"")

int main(int argc, char *argv[])
{
	plan(8*6 + 3); /* exec_query = 6 TAP tests */

	/* Create processing context. */
	ns_proc_context_t query_ctx;
	memset(&query_ctx, 0, sizeof(ns_proc_context_t));
	mm_ctx_mempool(&query_ctx.mm, sizeof(knot_pkt_t));

	/* Create name server. */
	knot_nameserver_t *ns = knot_ns_create();
	ns->opt_rr = knot_edns_new();
	knot_edns_set_version(ns->opt_rr, EDNS_VERSION);
	knot_edns_set_payload(ns->opt_rr, 4096);
	ns->identity = "bogus.ns";
	ns->version = "0.11";
	query_ctx.ns = ns;

	/* Insert root zone. */
	create_root_zone(ns, &query_ctx.mm);
	knot_zone_t *zone = knot_zonedb_find(ns->zone_db, ROOT_DNAME);

	/* Prepare. */
	int state = NS_PROC_FAIL;
	uint8_t query_wire[KNOT_WIRE_MAX_PKTSIZE];
	uint16_t query_len = KNOT_WIRE_MAX_PKTSIZE;
	knot_pkt_t *query = knot_pkt_new(query_wire, query_len, &query_ctx.mm);

	/* Create query processing parameter. */
	struct ns_proc_query_param param = {0};
	sockaddr_set(&param.query_source, AF_INET, "127.0.0.1", 53);

	/* Query processor (CH zone) */
	state = ns_proc_begin(&query_ctx, &param, NS_PROC_QUERY);
	const uint8_t chaos_dname[] = "\2""id""\6""server"; /* id.server */
	knot_pkt_clear(query);
	knot_pkt_put_question(query, chaos_dname, KNOT_CLASS_CH, KNOT_RRTYPE_TXT);
	exec_query(&query_ctx, "CH TXT", query->wire, query->size, KNOT_RCODE_NOERROR);

	/* Query processor (valid input). */
	state = ns_proc_reset(&query_ctx);
	knot_pkt_clear(query);
	knot_pkt_put_question(query, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);
	exec_query(&query_ctx, "IN/root", query->wire, query->size, KNOT_RCODE_NOERROR);

	/* Query processor (-1 bytes, not enough data). */
	state = ns_proc_reset(&query_ctx);
	exec_query(&query_ctx, "IN/few-data", query->wire, query->size - 1, KNOT_RCODE_FORMERR);

	/* Query processor (+1 bytes trailing). */
	state = ns_proc_reset(&query_ctx);
	query->wire[query->size] = '\1'; /* Initialize the "garbage" value. */
	exec_query(&query_ctx, "IN/trail-garbage", query->wire, query->size + 1, KNOT_RCODE_FORMERR);

	/* Forge NOTIFY query from SOA query. */
	state = ns_proc_reset(&query_ctx);
	knot_wire_set_opcode(query->wire, KNOT_OPCODE_NOTIFY);
	exec_query(&query_ctx, "IN/notify", query->wire, query->size, KNOT_RCODE_NOTAUTH);

	/* Forge AXFR query. */
	ns_proc_reset(&query_ctx);
	knot_pkt_clear(query);
	knot_pkt_put_question(query, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_AXFR);
	exec_query(&query_ctx, "IN/axfr", query->wire, query->size, KNOT_RCODE_NOTAUTH);

	/* Forge IXFR query (badly formed, no SOA in AUTHORITY section). */
	ns_proc_reset(&query_ctx);
	knot_pkt_clear(query);
	knot_pkt_put_question(query, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_IXFR);
	exec_query(&query_ctx, "IN/ixfr-formerr", query->wire, query->size, KNOT_RCODE_FORMERR);

	/* Forge IXFR query (well formed). */
	ns_proc_reset(&query_ctx);
	/* Append SOA RR. */
	knot_rrset_t *soa_rr = knot_node_get_rrset(zone->contents->apex, KNOT_RRTYPE_SOA);
	knot_pkt_begin(query, KNOT_AUTHORITY);
	knot_pkt_put(query, COMPR_HINT_NONE, soa_rr, 0);
	exec_query(&query_ctx, "IN/ixfr", query->wire, query->size, KNOT_RCODE_NOTAUTH);

	/* \note Tests below are not possible without proper zone and zone data. */
	/* #189 Process UPDATE query. */
	/* #189 Process AXFR client. */
	/* #189 Process IXFR client. */

	/* Query processor (smaller than DNS header, ignore). */
	state = ns_proc_reset(&query_ctx);
	knot_pkt_clear(query);
	knot_pkt_put_question(query, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);
	state = ns_proc_in(query->wire, KNOT_WIRE_HEADER_SIZE - 1, &query_ctx);
	ok(state == NS_PROC_NOOP, "ns: IN/less-than-header query ignored");

	/* Query processor (response, ignore). */
	state = ns_proc_reset(&query_ctx);
	knot_wire_set_qr(query->wire);
	state = ns_proc_in(query->wire, query->size, &query_ctx);
	ok(state == NS_PROC_NOOP, "ns: IN/less-than-header query ignored");

	/* Finish. */
	state = ns_proc_finish(&query_ctx);
	ok(state == NS_PROC_NOOP, "ns: processing end" );

	/* Cleanup. */
	mp_delete((struct mempool *)query_ctx.mm.ctx);
	knot_ns_destroy(&ns);

	return 0;
}

#undef WIRE_COPY
