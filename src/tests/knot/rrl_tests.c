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

#include <sys/socket.h>
#include "tests/knot/rrl_tests.h"
#include "knot/server/rrl.h"
#include "knot/common.h"
#include "libknot/packet/response.h"

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
	return 4;
}

static int rrl_tests_run(int argc, char *argv[])
{
	/* 1. create rrl table */
	rrl_table_t *rrl = rrl_create(100);
	ok(rrl != NULL, "rrl: create");
	
	/* 2. set rate limit */
	uint32_t rate = 10;
	rrl_setrate(rrl, rate);
	ok(rate == rrl_rate(rrl), "rrl: setrate");
	
	/* 3. N unlimited requests. */
	sockaddr_t addr;
	sockaddr_set(&addr, AF_INET, "127.0.0.1", 0);
	knot_packet_t *pkt = knot_packet_new(KNOT_PACKET_PREALLOC_NONE);
	knot_response_init(pkt);
	int ret = 0;
	for (unsigned i = 0; i < rate; ++i) {
		if (rrl_query(rrl, &addr, pkt) != KNOT_EOK) {
			ret = KNOT_ELIMIT;
			break;
		}
	}
	ok(ret == 0, "rrl: unlimited requests");
	
	/* 4 limited request */
	ret = rrl_query(rrl, &addr, pkt);
	ok(ret != 0, "rrl: throttled request");
	
	rrl_destroy(rrl);
	return 0;
}
