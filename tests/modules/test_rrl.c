/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libdnssec/crypto.h"
#include "libdnssec/random.h"
#include "libknot/libknot.h"
#include "contrib/sockaddr.h"
#include "knot/modules/rrl/functions.c"

/* Enable time-dependent tests. */
//#define ENABLE_TIMED_TESTS
#define RRL_SIZE 196613
#define RRL_THREADS 8
#define RRL_INSERTS (RRL_SIZE/(5*RRL_THREADS)) /* lf = 1/5 */

/* Disabled as default as it depends on random input.
 * Table may be consistent even if some collision occur (and they may occur).
 * Note: Disabled due to reported problems when running on VMs due to time
 * flow inconsistencies. Should work alright on a host machine.
 */
#ifdef ENABLE_TIMED_TESTS
struct bucketmap {
	unsigned i;
	uint64_t x;
};

/*! \brief Unit runnable. */
struct runnable_data {
	int passed;
	rrl_table_t *rrl;
	struct sockaddr_storage *addr;
	rrl_req_t *rq;
	knot_dname_t *zone;
};

static void* rrl_runnable(void *arg)
{
	struct runnable_data *d = (struct runnable_data *)arg;
	struct sockaddr_storage addr;
	memcpy(&addr, d->addr, sizeof(struct sockaddr_storage));
	int lock = -1;
	uint32_t now = time(NULL);
	struct bucketmap *m = malloc(RRL_INSERTS * sizeof(struct bucketmap));
	for (unsigned i = 0; i < RRL_INSERTS; ++i) {
		m[i].i = dnssec_random_uint32_t();
		((struct sockaddr_in *) &addr)->sin_addr.s_addr = m[i].i;
		rrl_item_t *b = rrl_hash(d->rrl, &addr, d->rq, d->zone, now, &lock);
		rrl_unlock(d->rrl, lock);
		m[i].x = b->netblk;
	}
	for (unsigned i = 0; i < RRL_INSERTS; ++i) {
		((struct sockaddr_in *) &addr)->sin_addr.s_addr = m[i].i;
		rrl_item_t *b = rrl_hash(d->rrl, &addr, d->rq, d->zone, now, &lock);
		rrl_unlock(d->rrl, lock);
		if (b->netblk != m[i].x) {
			d->passed = 0;
		}
	}
	free(m);
	return NULL;
}

static void rrl_hopscotch(struct runnable_data* rd)
{
	rd->passed = 1;
	pthread_t thr[RRL_THREADS];
	for (unsigned i = 0; i < RRL_THREADS; ++i) {
		pthread_create(thr + i, NULL, &rrl_runnable, rd);
	}
	for (unsigned i = 0; i < RRL_THREADS; ++i) {
		pthread_join(thr[i], NULL);
	}
}
#endif

int main(int argc, char *argv[])
{
	plan_lazy();

	dnssec_crypto_init();

	/* Prepare query. */
	knot_pkt_t *query = knot_pkt_new(NULL, 512, NULL);
	if (query == NULL) {
		return KNOT_ERROR; /* Fatal */
	}

	knot_dname_t *qname = knot_dname_from_str_alloc("beef.");
	int ret = knot_pkt_put_question(query, qname, KNOT_CLASS_IN, KNOT_RRTYPE_A);
	knot_dname_free(qname, NULL);
	if (ret != KNOT_EOK) {
		knot_pkt_free(query);
		return KNOT_ERROR; /* Fatal */
	}

	/* Prepare response */
	uint8_t rbuf[65535];
	size_t rlen = sizeof(rbuf);
	memcpy(rbuf, query->wire, query->size);
	knot_wire_flags_set_qr(rbuf);

	rrl_req_t rq;
	rq.w = rbuf;
	rq.len = rlen;
	rq.query = query;
	rq.flags = 0;

	/* 1. create rrl table */
	const uint32_t rate = 10;
	rrl_table_t *rrl = rrl_create(RRL_SIZE, rate);
	ok(rrl != NULL, "rrl: create");

	/* 4. N unlimited requests. */
	knot_dname_t *zone = knot_dname_from_str_alloc("rrl.");

	struct sockaddr_storage addr;
	struct sockaddr_storage addr6;
	sockaddr_set(&addr, AF_INET, "1.2.3.4", 0);
	sockaddr_set(&addr6, AF_INET6, "1122:3344:5566:7788::aabb", 0);
	ret = 0;
	for (unsigned i = 0; i < rate * RRL_CAPACITY; ++i) {
		if (rrl_query(rrl, &addr, &rq, zone, NULL) != KNOT_EOK ||
		    rrl_query(rrl, &addr6, &rq, zone, NULL) != KNOT_EOK) {
			ret = KNOT_ELIMIT;
			break;
		}
	}
	is_int(0, ret, "rrl: unlimited IPv4/v6 requests");

#ifdef ENABLE_TIMED_TESTS
	/* 5. limited request */
	ret = rrl_query(rrl, &addr, &rq, zone, NULL);
	is_int(KNOT_ELIMIT, ret, "rrl: throttled IPv4 request");

	/* 6. limited IPv6 request */
	ret = rrl_query(rrl, &addr6, &rq, zone, NULL);
	is_int(KNOT_ELIMIT, ret, "rrl: throttled IPv6 request");

	/* 8. hopscotch test */
	struct runnable_data rd = {
		1, rrl, &addr, &rq, zone
	};
	rrl_hopscotch(&rd);
	ok(rd.passed, "rrl: hashtable is ~ consistent");
#endif

	knot_dname_free(zone, NULL);
	knot_pkt_free(query);
	rrl_destroy(rrl);
	dnssec_crypto_cleanup();
	return 0;
}
