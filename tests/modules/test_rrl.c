/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <sched.h>

#include "libdnssec/crypto.h"
#include "libdnssec/random.h"
#include "libknot/libknot.h"
#include "contrib/sockaddr.h"

#include "time.h"
int fakeclock_gettime(clockid_t clockid, struct timespec *tp);
#define clock_gettime fakeclock_gettime
#include "knot/modules/rrl/functions.c"
#undef clock_gettime

#include <stdio.h>
#include <stdatomic.h>


#define RRL_PRICE_LOG 9   // highest price of all prefixes, same for IPv4 and IPv6

#define RRL_TABLE_SIZE  (1 << 20)
#define RRL_RATE_LIMIT  (1404301 / (1 << RRL_PRICE_LOG))

#define RRL_THREADS 8
//#define RRL_SYNC_WITH_REAL_TIME

uint32_t initial_limit(uint16_t rate_mult) {
	// return (1 << (16 - price_log)) - 1;
	return (1 << (16 - RRL_PRICE_LOG)) * rate_mult - 1;
}

// expected limits for parallel test (for largest prefix)
#define RRL_FIRST_BLOCKED        (1 << (16 - RRL_PRICE_LOG))
#define RRL_INITIAL_LIMIT_MIN    (RRL_FIRST_BLOCKED - 1)
#define RRL_INITIAL_LIMIT_MAX    (RRL_INITIAL_LIMIT_MIN + RRL_THREADS - 1)  // races may occur on first insertion into table
#define RRL_LONGTERM_LIMIT_MIN   (RRL_FIRST_BLOCKED / 2.0 / 32)
#define RRL_LONGTERM_LIMIT_MAX   (RRL_FIRST_BLOCKED / 2.0 / 32 + 1)
#define RRL_MAX_FP_RATIO         (0.00001)

#define BATCH_QUERIES_LOG  3   // threads acquire queries in batches of 8
#define HOSTS_LOG          3   // at most 6 attackers + 2 wildcard addresses for normal users
#define TICK_QUERIES_LOG  13   // at most 1024 queries per host per tick


/* Fix seed for randomness in RLL module. Change if improbable collisions arise. (one byte) */
#define RRL_SEED_GENERIC  1
#define RRL_SEED_AVX2     1

struct kru_generic {
	SIPHASH_KEY hash_key;
	// ...
};
struct kru_avx2 {
	char hash_key[48] ALIGNED(32);
	// ...
};


/* Override time in RRL module. */
struct timespec fakeclock_start;
uint32_t fakeclock_tick = 0;

void fakeclock_init(void) {
	clock_gettime(CLOCK_MONOTONIC_COARSE, &fakeclock_start);
	fakeclock_tick = 0;
}
int fakeclock_gettime(clockid_t clockid, struct timespec *tp) {
	uint32_t inc_msec = fakeclock_tick;
	tp->tv_sec = fakeclock_start.tv_sec + (fakeclock_start.tv_nsec / 1000000 + inc_msec) / 1000;
	tp->tv_nsec = (fakeclock_start.tv_nsec + (inc_msec % 1000) * 1000000) % 1000000000;
	return 0;
}



struct host {
	uint32_t queries_per_tick;
	int addr_family;
	char *addr_format;
	double min_passed, max_passed;
	_Atomic uint32_t passed;
};

struct stage {
	uint32_t first_tick, last_tick;
	struct host hosts[1 << HOSTS_LOG];
};


/*! \brief Unit runnable. */
struct runnable_data {
	rrl_table_t *rrl;
	rrl_req_t *rq;
	knot_dname_t *zone;
	int prime;
	_Atomic uint32_t *queries_acquired, *queries_done;
	struct stage *stages;
};

static void* rrl_runnable(void *arg)
{
	struct runnable_data *d = (struct runnable_data *)arg;
	size_t si = 0;

	char addr_str[40];
	struct sockaddr_storage addr;

	while (true) {
		uint32_t qi1 = atomic_fetch_add(d->queries_acquired, 1 << BATCH_QUERIES_LOG);

		/* increment time if needed; sync on incrementing using spinlock */
		uint32_t tick = qi1 >> TICK_QUERIES_LOG;
		for (size_t i = 1; tick != fakeclock_tick; i++) {
			if ((*d->queries_done >> TICK_QUERIES_LOG) >= tick) {
				fakeclock_tick = tick;
			}
			if (i % (1<<14) == 0) sched_yield();
			__sync_synchronize();
		}

		/* increment stage if needed */
		while (tick > d->stages[si].last_tick) {
			++si;
			if (!d->stages[si].first_tick) return NULL;
		}

#ifdef RRL_SYNC_WITH_REAL_TIME
		{
			struct timespec ts_fake, ts_real;
			do {
				fakeclock_gettime(CLOCK_MONOTONIC_COARSE, &ts_fake);
				clock_gettime(CLOCK_MONOTONIC_COARSE, &ts_real);
			} while (!((ts_real.tv_sec > ts_fake.tv_sec) || ((ts_real.tv_sec == ts_fake.tv_sec) && (ts_real.tv_nsec >= ts_fake.tv_nsec))));
		}
#endif

		if (tick >= d->stages[si].first_tick) {
			uint32_t qi2 = 0;
			do {
				uint32_t qi = qi1 + qi2;

				/* perform query qi */
				uint32_t hi = qi % (1 << HOSTS_LOG);
				if (!d->stages[si].hosts[hi].queries_per_tick) continue;
				uint32_t hqi = (qi % (1 << TICK_QUERIES_LOG)) >> HOSTS_LOG;  // host query index within tick
				if (hqi >= d->stages[si].hosts[hi].queries_per_tick) continue;
				hqi += (qi >> TICK_QUERIES_LOG) * d->stages[si].hosts[hi].queries_per_tick;  // across ticks
				snprintf(addr_str, sizeof(addr_str), d->stages[si].hosts[hi].addr_format, hqi % 0xff, (hqi >> 8) % 0xff, (hqi >> 16) % 0xff);
				sockaddr_set(&addr, d->stages[si].hosts[hi].addr_family, addr_str, 0);

				if (rrl_query(d->rrl, &addr, d->rq, d->zone, NULL) == KNOT_EOK) {
					atomic_fetch_add(&d->stages[si].hosts[hi].passed, 1);
				}

			} while ((qi2 = (qi2 + d->prime) % (1 << BATCH_QUERIES_LOG)));
		}
		atomic_fetch_add(d->queries_done, 1 << BATCH_QUERIES_LOG);
	}
}

int count_passing_queries(rrl_table_t *rrl, int addr_family, char *format, uint32_t min_value, uint32_t max_value, uint32_t max_queries) {
	struct sockaddr_storage addr;
	char addr_str[40];
	rrl_req_t rq = {0,};

	for (size_t i = 0; i < max_queries; i++) {
		snprintf(addr_str, sizeof(addr_str), format, i % (max_value - min_value + 1) + min_value);
		sockaddr_set(&addr, addr_family, addr_str, 0);
		if (rrl_query(rrl, &addr, &rq, NULL, NULL) != KNOT_EOK) {
			return i;
		}
	}
	return -1;
}

void test_rrl(char *impl_name, rrl_req_t rq, knot_dname_t *zone) {

	fakeclock_init();

	/* create rrl table */
	rrl_table_t *rrl = rrl_create(RRL_TABLE_SIZE, RRL_RATE_LIMIT);
	ok(rrl != NULL, "rrl(%s): create", impl_name);

	if (KRU.create == KRU_GENERIC.create) {
		struct kru_generic *kru = (struct kru_generic *) rrl->kru;
		memset(&kru->hash_key, RRL_SEED_GENERIC, sizeof(kru->hash_key));
	} else if (KRU.create == KRU_AVX2.create) {
		struct kru_avx2 *kru = (struct kru_avx2 *) rrl->kru;
		memset(&kru->hash_key, RRL_SEED_AVX2, sizeof(kru->hash_key));
	} else {
		assert(0);
	}


	/* N unlimited requests. */
	struct sockaddr_storage addr;
	struct sockaddr_storage addr6;
	sockaddr_set(&addr, AF_INET, "1.2.3.4", 0);
	sockaddr_set(&addr6, AF_INET6, "1122:3344:5566:7788::aabb", 0);
	int ret = 0;
	for (unsigned i = 0; i < RRL_INITIAL_LIMIT_MIN; ++i) {
		if (rrl_query(rrl, &addr, &rq, zone, NULL) != KNOT_EOK ||
		    rrl_query(rrl, &addr6, &rq, zone, NULL) != KNOT_EOK) {
			ret = KNOT_ELIMIT;
			break;
		}
	}
	is_int(0, ret, "rrl(%s): unlimited IPv4/v6 requests", impl_name);

	/* limited request */
	ret = rrl_query(rrl, &addr, &rq, zone, NULL);
	is_int(KNOT_ELIMIT, ret, "rrl(%s): blocked IPv4 request", impl_name);

	/* limited IPv6 request */
	ret = rrl_query(rrl, &addr6, &rq, zone, NULL);
	is_int(KNOT_ELIMIT, ret, "rrl(%s): blocked IPv6 request", impl_name);

	/* different namespaces for IPv4 and IPv6 */
	ret = count_passing_queries(rrl, AF_INET6, "0102:0304:%x::", 0,0xffff, 1 << 16);
	is_int(initial_limit(512), ret, "rrl(%s): different namespaces for IPv4 and IPv6 (needs limit on IPv6 /32)", impl_name);

	/* unblocked request */
	fakeclock_tick = 32;
	ret = rrl_query(rrl, &addr, &rq, zone, NULL);
	is_int(KNOT_EOK, ret, "rrl(%s): unblocked IPv4 request", impl_name);

	/* unblocked IPv6 request */
	ret = rrl_query(rrl, &addr6, &rq, zone, NULL);
	is_int(KNOT_EOK, ret, "rrl(%s): unblocked IPv6 request", impl_name);

	/* IPv4 multi-prefix tests */
	int limit = initial_limit(1);
	ret = count_passing_queries(rrl, AF_INET, "128.0.0.0", 0,0, 1 << 16);
	is_int(limit, ret, "rrl(%s): IPv4 limit for /32", impl_name);

	ret = count_passing_queries(rrl, AF_INET, "128.0.0.1", 0,0, 1);
	is_int(-1, ret, "rrl(%s): IPv4 limit for /32 not applied for /31", impl_name);

	limit = initial_limit(4) - initial_limit(1) - 1;
	ret = count_passing_queries(rrl, AF_INET, "128.0.0.%d", 2,15, 1 << 16);
	is_int(limit, ret, "rrl(%s): IPv4 limit for /28", impl_name);

	ret = count_passing_queries(rrl, AF_INET, "128.0.0.16", 0,0, 1);
	is_int(-1, ret, "rrl(%s): IPv4 limit for /28 not applied for /27", impl_name);

	limit = initial_limit(16) - initial_limit(4) - 1;
	ret = count_passing_queries(rrl, AF_INET, "128.0.0.%d", 17,255, 1 << 16);
	is_int(limit, ret, "rrl(%s): IPv4 limit for /24", impl_name);

	ret = count_passing_queries(rrl, AF_INET, "128.0.1.0", 1,1, 1);
	is_int(-1, ret, "rrl(%s): IPv4 limit for /24 not applied for /23", impl_name);


	/* IPv6 multi-prefix tests */
	limit = initial_limit(1);
	ret = count_passing_queries(rrl, AF_INET6, "8000::", 0,0, 1 << 16);
	is_int(limit, ret, "rrl(%s): IPv6 limit for /128", impl_name);

	ret = count_passing_queries(rrl, AF_INET6, "8000::1", 0,0, 1);
	is_int(-1, ret, "rrl(%s): IPv6 limit for /128 not applied for /127", impl_name);

	limit = initial_limit(4) - initial_limit(1) - 1;
	ret = count_passing_queries(rrl, AF_INET6, "8000:0:0:0:%02x00::", 0x01,0xff, 1 << 16);
	is_int(limit, ret, "rrl(%s): IPv6 limit for /64", impl_name);

	ret = count_passing_queries(rrl, AF_INET6, "8000:0:0:1::", 0,0, 1);
	is_int(-1, ret, "rrl(%s): IPv6 limit for /64 not applied for /63", impl_name);

	limit = initial_limit(16) - initial_limit(4) - 1;
	ret = count_passing_queries(rrl, AF_INET6, "8000:0:0:00%02x::", 0x01,0xff, 1 << 16);
	is_int(limit, ret, "rrl(%s): IPv6 limit for /56", impl_name);

	ret = count_passing_queries(rrl, AF_INET6, "8000:0:0:0100", 1,1, 1);
	is_int(-1, ret, "rrl(%s): IPv6 limit for /56 not applied for /55", impl_name);

	// prefix /32 is not tested here


	/* parallel tests */
	struct stage stages[] = {
		/* first tick, last tick, hosts */
		{32, 32, {
			/* queries per tick, family, address, min passed, max passed */
			{1024, AF_INET,  "%d.%d.%d.1",   1024 * (1 - RRL_MAX_FP_RATIO), 1024},
			{1024, AF_INET,  "3.3.3.3",      RRL_INITIAL_LIMIT_MIN,   RRL_INITIAL_LIMIT_MAX},
			{ 512, AF_INET,  "4.4.4.4",      RRL_INITIAL_LIMIT_MIN,   RRL_INITIAL_LIMIT_MAX},
			{1024, AF_INET6, "%x%x:%x00::1", 1024 * (1 - RRL_MAX_FP_RATIO), 1024},
			{1024, AF_INET6, "3333::3333",   RRL_INITIAL_LIMIT_MIN,   RRL_INITIAL_LIMIT_MAX},
			{ 512, AF_INET6, "4444::4444",   RRL_INITIAL_LIMIT_MIN,   RRL_INITIAL_LIMIT_MAX}
		}},
		{33, 1023, {
			{1024, AF_INET,  "%d.%d.%d.1",   1024 * (1 - RRL_MAX_FP_RATIO), 1024},
			{1024, AF_INET,  "3.3.3.3",      RRL_LONGTERM_LIMIT_MIN,  RRL_LONGTERM_LIMIT_MAX},
			{ 512, AF_INET,  "4.4.4.4",      RRL_LONGTERM_LIMIT_MIN,  RRL_LONGTERM_LIMIT_MAX},
			{1024, AF_INET6, "%x%x:%x00::1", 1024 * (1 - RRL_MAX_FP_RATIO), 1024},
			{1024, AF_INET6, "3333::3333",   RRL_LONGTERM_LIMIT_MIN,  RRL_LONGTERM_LIMIT_MAX},
			{ 512, AF_INET6, "4444::4444",   RRL_LONGTERM_LIMIT_MIN,  RRL_LONGTERM_LIMIT_MAX}
		}},
		{1024, 2047, {
			{1024, AF_INET,  "3.3.3.3",      RRL_LONGTERM_LIMIT_MIN,  RRL_LONGTERM_LIMIT_MAX},
			{1024, AF_INET6, "3333::3333",   RRL_LONGTERM_LIMIT_MIN,  RRL_LONGTERM_LIMIT_MAX},
		}},
		{2048, 2048, {
			{1024, AF_INET,  "%d.%d.%d.1",   1024 * (1 - RRL_MAX_FP_RATIO), 1024},
			{1024, AF_INET,  "3.3.3.3",      RRL_LONGTERM_LIMIT_MIN,  RRL_LONGTERM_LIMIT_MAX},
			{ 512, AF_INET,  "4.4.4.4",      RRL_INITIAL_LIMIT_MIN,   RRL_INITIAL_LIMIT_MAX},
			{1024, AF_INET6, "%x%x:%x00::1", 1024 * (1 - RRL_MAX_FP_RATIO), 1024},
			{1024, AF_INET6, "3333::3333",   RRL_LONGTERM_LIMIT_MIN,  RRL_LONGTERM_LIMIT_MAX},
			{ 512, AF_INET6, "4444::4444",   RRL_INITIAL_LIMIT_MIN,   RRL_INITIAL_LIMIT_MAX}
		}},
		{0}
	};

	pthread_t thr[RRL_THREADS];
	struct runnable_data rd[RRL_THREADS];
	_Atomic uint32_t queries_acquired = 0, queries_done = 0;
	int primes[] = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61};
	assert(sizeof(primes)/sizeof(*primes) >= RRL_THREADS);

	for (unsigned i = 0; i < RRL_THREADS; ++i) {
		rd[i].rrl = rrl;
		rd[i].queries_acquired = &queries_acquired;
		rd[i].queries_done = &queries_done;
		rd[i].prime = primes[i];
		rd[i].stages = stages;
		rd[i].zone = zone;
		rd[i].rq = &rq;
		pthread_create(thr + i, NULL, &rrl_runnable, rd + i);
	}
	for (unsigned i = 0; i < RRL_THREADS; ++i) {
		pthread_join(thr[i], NULL);
	}

	unsigned si = 0;
	do {
		struct host * const h = stages[si].hosts;
		uint32_t ticks = stages[si].last_tick - stages[si].first_tick + 1;
		for (size_t i = 0; h[i].queries_per_tick; i++) {
			ok( h[i].min_passed * ticks <= h[i].passed && h[i].passed <= h[i].max_passed * ticks,
				"rrl(%s): parallel stage %d, addr %s: %.2f <= %.4f <= %.2f", impl_name, si, h[i].addr_format, h[i].min_passed, (double)h[i].passed / ticks, h[i].max_passed);
		}
	} while (stages[++si].first_tick);

	rrl_destroy(rrl);
}

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
	rq.wire = rbuf;
	rq.len = rlen;
	rq.query = query;
	rq.flags = 0;

	/* 1. Endian-independent hash input buffer. */
	// TODO fix the expected outcomes; they differ as qname is now not considered
#if 0
	uint8_t buf[RRL_CLSBLK_MAXLEN];
	// CLS_LARGE + remote + dname wire.
	uint8_t expectedv4[] = "\x10\x01\x02\x03\x00\x00\x00\x00\x00\x04""beef";
	rrl_classify(buf, sizeof(buf), &addr, &rq, qname);
	is_int(0, memcmp(buf, expectedv4, sizeof(expectedv4)), "rrl: IPv4 hash input buffer");
	uint8_t expectedv6[] = "\x10\x11\x22\x33\x44\x55\x66\x77\x00\x04""beef";
	rrl_classify(buf, sizeof(buf), &addr6, &rq, qname);
	is_int(0, memcmp(buf, expectedv6, sizeof(expectedv6)), "rrl: IPv6 hash input buffer");
#endif

	knot_dname_t *zone = knot_dname_from_str_alloc("rrl.");

	assert(KRU_GENERIC.create != KRU_AVX2.create);
	bool test_avx2 = (KRU.create == KRU_AVX2.create);

	KRU = KRU_GENERIC;
	test_rrl("KRU_GENERIC", rq, zone);

	if (test_avx2) {
		KRU = KRU_AVX2;
		test_rrl("KRU_AVX2", rq, zone);
	}

	knot_dname_free(zone, NULL);
	knot_pkt_free(query);
	dnssec_crypto_cleanup();
	return 0;
}
