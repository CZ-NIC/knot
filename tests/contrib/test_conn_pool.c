/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <tap/basic.h>

#include "contrib/conn_pool.h"
#include "contrib/sockaddr.h"

static void test_dev_keying(void)
{
	conn_pool_t *pool = conn_pool_init(4, 60000, conn_pool_close_cb_dflt,
	                                   conn_pool_invalid_cb_allvalid);
	ok(pool != NULL, "conn_pool: init");

	struct sockaddr_storage src = { 0 }, dst = { 0 };
	sockaddr_set(&src, AF_INET, "127.0.0.1", 0);
	sockaddr_set(&dst, AF_INET, "127.0.0.2", 53);

	// Same source/destination, different (or no) device -- must be tracked
	// as independent connections, not collapsed into one another.
	ok(conn_pool_put(pool, &src, &dst, "eth0", 10) == CONN_POOL_FD_INVALID,
	   "conn_pool: put eth0 connection to a free slot");
	ok(conn_pool_put(pool, &src, &dst, "eth1", 20) == CONN_POOL_FD_INVALID,
	   "conn_pool: put eth1 connection to a free slot");
	ok(conn_pool_put(pool, &src, &dst, NULL, 30) == CONN_POOL_FD_INVALID,
	   "conn_pool: put no-device connection to a free slot");

	ok(conn_pool_get(pool, &src, &dst, "eth2") == CONN_POOL_FD_INVALID,
	   "conn_pool: get misses for an unrelated device");

	ok(conn_pool_get(pool, &src, &dst, "eth1") == 20,
	   "conn_pool: get hits the connection bound to the matching device");
	ok(conn_pool_get(pool, &src, &dst, "eth1") == CONN_POOL_FD_INVALID,
	   "conn_pool: get is one-shot -- already popped");

	ok(conn_pool_get(pool, &src, &dst, NULL) == 30,
	   "conn_pool: get with no device hits the no-device connection");

	ok(conn_pool_get(pool, &src, &dst, "eth0") == 10,
	   "conn_pool: get hits the last remaining (eth0) connection");

	conn_pool_deinit(pool);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	diag("conn_pool device keying");
	test_dev_keying();

	return 0;
}
