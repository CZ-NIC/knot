/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <sys/types.h>
#include <sys/socket.h>
#include "tests/knot/rrl_tests.h"
#include "knot/server/rrl.h"
#include "knot/common.h"
#include "libknot/packet/response.h"
#include "libknot/packet/query.h"
#include "libknot/nameserver/name-server.h"

/* Enable time-dependent tests. */
//#define ENABLE_TIMED_TESTS

static int rrl_tests_count(int argc, char *argv[]);
static int rrl_tests_run(int argc, char *argv[]);

/*
 * Unit API.
 */
unit_api rrl_tests_api = {
	"RRL",
	&rrl_tests_count,
	&rrl_tests_run
};

/*
 *  Unit implementation.
 */

static int rrl_tests_count(int argc, char *argv[])
{
	int c = 6;
#ifndef ENABLE_TIMED_TESTS
	c -= 2;
#endif
	return c;
}

static int rrl_tests_run(int argc, char *argv[])
{
	/* Prepare query. */
	knot_question_t qst;
	qst.qclass = KNOT_CLASS_IN;
	qst.qtype = KNOT_RRTYPE_A;
	qst.qname = knot_dname_new_from_str("beef.", 5, NULL);
	knot_packet_t *query = knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
	knot_query_init(query);
	knot_packet_set_max_size(query, 512);
	knot_query_set_question(query, &qst);
	
	/* Prepare response */
	knot_nameserver_t *ns = knot_ns_create();
	uint8_t rbuf[65535];
	size_t rlen = sizeof(rbuf);
	memset(rbuf, 0, sizeof(rbuf));
	knot_ns_error_response_from_query(ns, query, KNOT_RCODE_NOERROR, rbuf, &rlen);
	
	rrl_req_t rq;
	rq.w = rbuf;
	rq.len = rlen;
	rq.qst = &qst;
	rq.flags = 0;
	
	/* 1. create rrl table */
	rrl_table_t *rrl = rrl_create(101);
	ok(rrl != NULL, "rrl: create");
	
	/* 2. set rate limit */
	uint32_t rate = 10;
	rrl_setrate(rrl, rate);
	ok(rate == rrl_rate(rrl), "rrl: setrate");

	/* 3. N unlimited requests. */
	knot_dname_t *apex = knot_dname_new_from_str("rrl.", 4, NULL);
	knot_zone_t *zone = knot_zone_new(knot_node_new(apex, NULL, 0), 0, 0);
	sockaddr_t addr;
	sockaddr_t addr6;
	sockaddr_set(&addr, AF_INET, "1.2.3.4", 0);
	sockaddr_set(&addr6, AF_INET6, "1122:3344:5566:7788::aabb", 0);
	int ret = 0;
	for (unsigned i = 0; i < rate; ++i) {
		if (rrl_query(rrl, &addr, &rq, zone) != KNOT_EOK ||
		    rrl_query(rrl, &addr6, &rq, zone) != KNOT_EOK) {
			ret = KNOT_ELIMIT;
			break;
		}
	}
	ok(ret == 0, "rrl: unlimited IPv4/v6 requests");

#ifdef ENABLE_TIMED_TESTS
	/* 4. limited request */
	ret = rrl_query(rrl, &addr, &rq, zone);
	ok(ret != 0, "rrl: throttled IPv4 request");

	/* 5. limited IPv6 request */
	ret = rrl_query(rrl, &addr6, &rq, zone);
	ok(ret != 0, "rrl: throttled IPv6 request");
#endif
	
	/* 6. invalid values. */
	ret = 0;
	lives_ok( {
	                  rrl_create(0);            // NULL
	                  ret += rrl_setrate(0, 0); // 0
	                  ret += rrl_rate(0);       // 0
	                  ret += rrl_setlocks(0,0); // -1
	                  ret += rrl_query(0, 0, 0, 0); // -1
	                  ret += rrl_query(rrl, 0, 0, 0); // -1
	                  ret += rrl_query(rrl, (void*)0x1, 0, 0); // -1
	                  ret += rrl_destroy(0); // -1
	}, "dthreads: not crashed while executing functions on NULL context");
	
	knot_dname_release(qst.qname);
	knot_dname_release(apex);
	knot_zone_deep_free(&zone, 0);
	knot_ns_destroy(&ns);
	knot_packet_free(&query);
	rrl_destroy(rrl);
	return 0;
}
