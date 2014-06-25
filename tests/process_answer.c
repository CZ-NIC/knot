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
#include "common/descriptor.h"
#include "libknot/packet/wire.h"
#include "knot/nameserver/process_answer.h"
#include "fake_server.h"

/* @note Test helpers. */
#define TEST_RESET() \
	knot_process_reset(proc); \
	knot_pkt_clear(pkt)

#define TEST_EXEC(expect, info) {\
	pkt->parsed = pkt->size; /* Simulate parsed packet. */ \
	int state = knot_process_in(pkt->wire, pkt->size, proc); \
	is_int((expect), state, "proc_answer: " info); \
	}

#define INVALID_COUNT  2
#define SPECIFIC_COUNT 1
#define INCLASS_COUNT  2
#define TEST_COUNT INVALID_COUNT + SPECIFIC_COUNT + INCLASS_COUNT

static void test_invalid(knot_pkt_t *pkt, knot_process_t *proc)
{
	/* Invalid packet - query. */
	TEST_RESET();
	knot_pkt_put_question(pkt, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_A);
	TEST_EXEC(NS_PROC_NOOP, "ignored query");

	/* Invalid packet - mangled. */
	TEST_RESET();
	knot_pkt_put_question(pkt, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_A);
	pkt->size += 1; /* Mangle size. */
	TEST_EXEC(NS_PROC_FAIL, "malformed query");
}

/* Test if context accepts only answer to specific query. */
static void test_specific(knot_pkt_t *pkt, knot_process_t *proc, struct process_answer_param *param)
{
	/* Set specific SOA query. */
	uint16_t query_id = 0xBEEF;
	knot_pkt_t *query = knot_pkt_new(NULL, KNOT_WIRE_MIN_PKTSIZE, &proc->mm);
	assert(query);
	knot_pkt_put_question(query, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);
	knot_wire_set_id(query->wire, query_id);
	param->query = query;

	/* MSGID mismatch */
	TEST_RESET();
	knot_pkt_init_response(pkt, param->query);
	knot_wire_set_id(pkt->wire, 0xDEAD);
	TEST_EXEC(NS_PROC_NOOP, "ignored mismatching MSGID");

	/* Clear the specific query. */
	knot_pkt_free(&query);
	param->query = NULL;
}

static void test_inclass(knot_pkt_t *pkt, knot_process_t *proc, struct process_answer_param *param)
{
	/* Set specific SOA query. */
	knot_pkt_t *query = knot_pkt_new(NULL, KNOT_WIRE_MIN_PKTSIZE, &proc->mm);
	assert(query);
	knot_pkt_put_question(query, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);
	param->query = query;

	/* SOA query answer. */
	TEST_RESET();
	zone_node_t *apex = param->zone->contents->apex;
	knot_rrset_t soa = node_rrset(apex, KNOT_RRTYPE_SOA);
	knot_pkt_put_question(pkt, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);
	knot_wire_set_qr(pkt->wire);
	knot_pkt_begin(pkt, KNOT_ANSWER);
	knot_pkt_put(pkt, COMPR_HINT_OWNER, &soa, 0);
	TEST_EXEC(NS_PROC_DONE, "IN/SOA answer");

	/* Unsupported anwer. */
	TEST_RESET();
	knot_pkt_put_question(pkt, ROOT_DNAME, KNOT_CLASS_IN, KNOT_RRTYPE_TXT);
	knot_wire_set_qr(pkt->wire);
	TEST_EXEC(NS_PROC_NOOP, "IN/unsupported answer");

	/* Clear the specific query. */
	knot_pkt_free(&query);
	param->query = NULL;
}

int main(int argc, char *argv[])
{
	plan(3 + TEST_COUNT);

	/* Create processing context. */
	knot_process_t proc;
	memset(&proc, 0, sizeof(knot_process_t));
	mm_ctx_mempool(&proc.mm, sizeof(knot_pkt_t));

	/* Create fake server environment. */
	server_t server;
	int ret = create_fake_server(&server, &proc.mm);
	ok(ret == KNOT_EOK, "proc_answer: fake server initialization");

	/* Prepare. */
	struct sockaddr_storage remote;
	memset(&remote, 0, sizeof(struct sockaddr_storage));
	sockaddr_set(&remote, AF_INET, "127.0.0.1", 53);
	struct process_answer_param param = {0};
	param.remote = &remote;
	param.zone = knot_zonedb_find(server.zone_db, ROOT_DNAME);
	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, &proc.mm);

	/* Begin processing. */
	int state = knot_process_begin(&proc, &param, NS_PROC_ANSWER);
	ok(state == NS_PROC_MORE, "proc_answer: expects packet after init");

	/* Invalid generic input tests. */
	test_invalid(pkt, &proc);

	/* Specific input tests (response to given query). */
	test_specific(pkt, &proc, &param);

	/* IN_CLASS input tests. */
	test_inclass(pkt, &proc, &param);

	/* IXFR input tests. */
	/* AXFR input tests. */
	/* NOTIFY input tests. */
	/* TSIG check tests. */

	/* Finish. */
	state = knot_process_finish(&proc);
	ok(state == NS_PROC_NOOP, "proc_answer: processing end" );

	/* Cleanup. */
	mp_delete((struct mempool *)proc.mm.ctx);
	server_deinit(&server);
	conf_free(conf());

	return 0;
}

#undef TEST_RESET
#undef TEST_EXEC
