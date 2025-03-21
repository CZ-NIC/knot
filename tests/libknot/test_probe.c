/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <tap/basic.h>
#include <tap/files.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "contrib/sockaddr.h"
#include "libknot/packet/pkt.c"
#include "libknot/probe/probe.h"

int main(int argc, char *argv[])
{
	plan_lazy();

	knot_probe_t *probe_out = knot_probe_alloc();
	ok(probe_out != NULL, "probe: initialize output probe");
	knot_probe_t *probe_in = knot_probe_alloc();
	ok(probe_in != NULL, "probe: initialize input probe");

	int fd = knot_probe_fd(probe_out);
	ok(fd < 0, "probe: unavailable fd");

	char *workdir = test_mkdtemp();
	ok(workdir != NULL, "probe: create temporary workdir");

	int ret = knot_probe_set_producer(probe_out, workdir, 1);
	ok(ret == KNOT_ECONN, "probe: connect producer");

	ret = knot_probe_set_consumer(probe_in, workdir, 1);
	ok(ret == KNOT_EOK, "probe: connect consumer");
	fd = knot_probe_fd(probe_in);
	ok(fd >= 0, "probe: get input probe fd");

	ret = knot_probe_set_producer(probe_out, workdir, 1);
	ok(ret == KNOT_EOK, "probe: reconnect producer");
	fd = knot_probe_fd(probe_out);
	ok(fd >= 0, "probe: get output probe fd");

	struct sockaddr_storage addr;
	ret = sockaddr_set(&addr, AF_INET, "192.168.0.1", 53);
	ok(ret == KNOT_EOK, "probe: set address");

	knot_pkt_t *query = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	ok(query != NULL, "probe: create query");
	knot_pkt_t *reply = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	ok(reply != NULL, "probe: create reply");

	ret = knot_pkt_put_question(query, (const uint8_t *)"\x04test\x00",
	                            KNOT_CLASS_IN, KNOT_RRTYPE_SOA);
	ok(ret == KNOT_EOK, "probe: put query");

	knot_probe_data_t data_out;
	ret = knot_probe_data_set(&data_out, KNOT_PROBE_PROTO_UDP,
	                          &addr, &addr, query, reply, KNOT_RCODE_NXDOMAIN);
	ok(ret == KNOT_EOK, "probe: connect producer");

	knot_pkt_free(query);
	knot_pkt_free(reply);

	ret = knot_probe_produce(probe_out, &data_out, 1);
	ok(ret == KNOT_EOK, "probe: produce datagram");

	knot_probe_data_t data_in;
	ret = knot_probe_consume(probe_in, &data_in, 1, 20);
	ok(ret == 1, "probe: consume datagram");

	ret = memcmp(&data_in, &data_out, offsetof(knot_probe_data_t, query.qname));
	ok(ret == 0, "probe: data comparison");

	ret = knot_dname_cmp(data_in.query.qname, data_out.query.qname);
	ok(ret == 0, "probe: qname comparison");

	knot_probe_free(probe_in);
	knot_probe_free(probe_out);

	test_rm_rf(workdir);
	free(workdir);

	return 0;
}
