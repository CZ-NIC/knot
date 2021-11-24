/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
