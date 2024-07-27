/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdatomic.h>

#include "libdnssec/crypto.h"
#include "libdnssec/random.h"
#include "libknot/libknot.h"
#include "contrib/openbsd/siphash.h"
#include "contrib/sockaddr.h"

#include "time.h"
int fakeclock_gettime(clockid_t clockid, struct timespec *tp);
#define clock_gettime fakeclock_gettime
#include "knot/modules/rrl/functions.c"
#undef clock_gettime

#define RRL_THREADS 4
//#define RRL_SYNC_WITH_REAL_TIME

#define BATCH_QUERIES_LOG  3   // threads acquire queries in batches of 8
#define HOSTS_LOG          3   // at most 6 attackers + 2 wildcard addresses for normal users
#define TICK_QUERIES_LOG  13   // at most 1024 queries per host per tick

// Accessing RRL configuration of INSTANT/RATE limits for V4/V6 and specific prefix.
#define LIMIT(type, Vx, prefix) (RRL_MULT(Vx, prefix) * RRL_ ## type ## _LIMIT)

#define RRL_CONFIG(Vx, name) RRL_ ## Vx ## _ ## name
#define RRL_MULT(Vx, prefix) get_mult(RRL_CONFIG(Vx, PREFIXES), RRL_CONFIG(Vx, RATE_MULT), RRL_CONFIG(Vx, PREFIXES_CNT), prefix)
static inline kru_price_t get_mult(uint8_t prefixes[], kru_price_t mults[], size_t cnt, uint8_t wanted_prefix) {
	for (size_t i = 0; i < cnt; i++)
		if (prefixes[i] == wanted_prefix)
			return mults[i];
	assert(0);
	return 0;
}

// Macro correction depending on the table mode.
int DIFF = 0;

// Instant limits and rate limits per msec.
#define INST(Vx, prefix)  (LIMIT(INSTANT, Vx, prefix) + DIFF)
#define RATEM(Vx, prefix) (LIMIT(RATE, Vx, prefix) / 1000 + DIFF)

// Expected range of limits for parallel test.
#define RANGE_INST(Vx, prefix)   INST(Vx, prefix) - 1,         INST(Vx, prefix) + RRL_THREADS - 1
#define RANGE_RATEM(Vx, prefix)  RATEM(Vx, prefix) - 1 - DIFF, RATEM(Vx, prefix) + RRL_THREADS - DIFF
#define RANGE_UNLIM(queries)     queries,                      queries

/* Fix seed for randomness in RLL module. Change if improbable collisions arise. (one byte) */
#define RRL_SEED_GENERIC  1
#define RRL_SEED_AVX2     1

struct kru_generic {
	SIPHASH_KEY hash_key;
	// ...
};
struct kru_avx2 {
	_Alignas(32) char hash_key[48];
	// ...
};

/* Override time in RRL module. */
struct timespec fakeclock_start;
uint32_t fakeclock_tick = 0;

void fakeclock_init(void)
{
	clock_gettime(CLOCK_MONOTONIC_COARSE, &fakeclock_start);
	fakeclock_tick = 0;
}

int fakeclock_gettime(clockid_t clockid, struct timespec *tp)
{
	uint32_t inc_msec = fakeclock_tick;
	tp->tv_sec = fakeclock_start.tv_sec + (fakeclock_start.tv_nsec / 1000000 + inc_msec) / 1000;
	tp->tv_nsec = (fakeclock_start.tv_nsec + (inc_msec % 1000) * 1000000) % 1000000000;
	return 0;
}

struct host {
	uint32_t queries_per_tick;
	int addr_family;
	char *addr_format;
	uint32_t min_passed, max_passed;
	_Atomic uint32_t passed;
};

struct stage {
	uint32_t first_tick, last_tick;
	struct host hosts[1 << HOSTS_LOG];
};

struct runnable_data {
	rrl_table_t *rrl;
	int prime;
	_Atomic uint32_t *queries_acquired, *queries_done;
	struct stage *stages;
};

static void *rrl_runnable(void *arg)
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
			} while (!((ts_real.tv_sec > ts_fake.tv_sec) ||
				   ((ts_real.tv_sec == ts_fake.tv_sec) && (ts_real.tv_nsec >= ts_fake.tv_nsec))));
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
				(void)snprintf(addr_str, sizeof(addr_str), d->stages[si].hosts[hi].addr_format,
				         hqi % 0xff, (hqi >> 8) % 0xff, (hqi >> 16) % 0xff);
				sockaddr_set(&addr, d->stages[si].hosts[hi].addr_family, addr_str, 0);

				if (rrl_query(d->rrl, &addr, NULL) == KNOT_EOK) {
					atomic_fetch_add(&d->stages[si].hosts[hi].passed, 1);
					if (!d->rrl->rw_mode) {
						rrl_update(d->rrl, &addr, 1);
					}
				}

			} while ((qi2 = (qi2 + d->prime) % (1 << BATCH_QUERIES_LOG)));
		}
		atomic_fetch_add(d->queries_done, 1 << BATCH_QUERIES_LOG);
	}
}

char *impl_name = "";
rrl_table_t *rrl = NULL;

void count_test(char *desc, int expected_passing, double margin_fract,
		int addr_family, char *addr_format, uint32_t min_value, uint32_t max_value)
{
	uint32_t max_queries = expected_passing > 0 ? 2 * expected_passing : -expected_passing;
	struct sockaddr_storage addr;
	char addr_str[40];
	int cnt = -1;

	for (size_t i = 0; i < max_queries; i++) {
		(void)snprintf(addr_str, sizeof(addr_str), addr_format,
				i % (max_value - min_value + 1) + min_value,
				i / (max_value - min_value + 1) % 256);
		sockaddr_set(&addr, addr_family, addr_str, 0);
		if (rrl_query(rrl, &addr, NULL) != KNOT_EOK) {
			cnt = i;
			break;
		}
		if (!rrl->rw_mode) {
			rrl_update(rrl, &addr, 1);
		}
	}

	if (expected_passing < 0) expected_passing = -1;
	if (margin_fract == 0) {
		is_int(expected_passing, cnt, "rrl(%s): %-48s [%7d ]", impl_name, desc, expected_passing);
	} else {
		int max_diff = expected_passing * margin_fract;
		ok((expected_passing - max_diff <= cnt) && (cnt <= expected_passing + max_diff),
			"rrl(%s): %-48s [%7d <=%7d      <=%7d ]", impl_name, desc,
			expected_passing - max_diff, cnt, expected_passing + max_diff);
	}
}

void test_rrl(bool rw_mode)
{
	size_t RRL_TABLE_SIZE = (1 << 20);
	uint32_t RRL_INSTANT_LIMIT = (1 << 7);
	uint32_t RRL_RATE_LIMIT = (1 << 16);
	if (rw_mode) {
		RRL_INSTANT_LIMIT = (1 << 8);
		RRL_RATE_LIMIT = (1 << 17);
	}

	fakeclock_init();

	/* create rrl table */
	rrl = rrl_create(RRL_TABLE_SIZE, RRL_INSTANT_LIMIT, RRL_RATE_LIMIT, rw_mode, 0);
	ok(rrl != NULL, "rrl(%s): create", impl_name);
	assert(rrl);

	if (KRU.initialize == KRU_GENERIC.initialize) {
		struct kru_generic *kru = (struct kru_generic *) rrl->kru;
		memset(&kru->hash_key, RRL_SEED_GENERIC, sizeof(kru->hash_key));
	} else if (KRU.initialize == KRU_AVX2.initialize) {
		struct kru_avx2 *kru = (struct kru_avx2 *) rrl->kru;
		memset(&kru->hash_key, RRL_SEED_AVX2, sizeof(kru->hash_key));
	} else {
		assert(0);
	}

	/* IPv4 multi-prefix tests */
	static_assert(RRL_V4_PREFIXES_CNT == 4,
			"There are no more IPv4 limited prefixes (/32, /24, /20, /18 will be tested).");

	count_test("IPv4 instant limit /32", INST(V4, 32), 0,
			AF_INET, "128.0.0.0", 0, 0);

	count_test("IPv4 instant limit /32 not applied on /31", -1, 0,
			AF_INET, "128.0.0.1", 0, 0);

	count_test("IPv4 instant limit /24", INST(V4, 24) - INST(V4, 32) - 1, 0,
			AF_INET, "128.0.0.%d", 2, 255);

	count_test("IPv4 instant limit /24 not applied on /23", -1, 0,
			AF_INET, "128.0.1.0", 0, 0);

	count_test("IPv4 instant limit /20", INST(V4, 20) - INST(V4, 24) - 1, 0.001,
			AF_INET, "128.0.%d.%d", 2, 15);

	count_test("IPv4 instant limit /20 not applied on /19", -1, 0,
			AF_INET, "128.0.16.0", 0, 0);

	count_test("IPv4 instant limit /18", INST(V4, 18) - INST(V4, 20) - 1, 0.01,
			AF_INET, "128.0.%d.%d", 17, 63);

	count_test("IPv4 instant limit /18 not applied on /17", -1, 0,
			AF_INET, "128.0.64.0", 0, 0);

	/* IPv6 multi-prefix tests */
	static_assert(RRL_V6_PREFIXES_CNT == 5,
			"There are no more IPv6 limited prefixes (/128, /64, /56, /48, /32 will be tested).");

	count_test("IPv6 instant limit /128, independent to IPv4", INST(V6, 128), 0,
			AF_INET6, "8000::", 0, 0);

	count_test("IPv6 instant limit /128 not applied on /127", -1, 0,
			AF_INET6, "8000::1", 0, 0);

	count_test("IPv6 instant limit /64", INST(V6, 64) - INST(V6, 128) - 1, 0,
			AF_INET6, "8000:0:0:0:%02x%02x::", 0x01, 0xff);

	count_test("IPv6 instant limit /64 not applied on /63", -1, 0,
			AF_INET6, "8000:0:0:1::", 0, 0);

	count_test("IPv6 instant limit /56", INST(V6, 56) - INST(V6, 64) - 1, rw_mode ? 0 : 0.01,
			AF_INET6, "8000:0:0:00%02x:%02x00::", 0x02, 0xff);

	count_test("IPv6 instant limit /56 not applied on /55", -1, 0,
			AF_INET6, "8000:0:0:0100::", 0, 0);

	count_test("IPv6 instant limit /48", INST(V6, 48) - INST(V6, 56) - 1, 0.01,
			AF_INET6, "8000:0:0:%02x%02x::", 0x02, 0xff);

	count_test("IPv6 instant limit /48 not applied on /47", -1, 0,
			AF_INET6, "8000:0:1::", 0, 0);

	count_test("IPv6 instant limit /32", INST(V6, 32) - INST(V6, 48) - 1, rw_mode ? 0.001 : 0,
			AF_INET6, "8000:0:%02x%02x::", 0x02, 0xff);

	count_test("IPv6 instant limit /32 not applied on /31", -1, 0,
			AF_INET6, "8000:1::", 0, 0);

	/* limit after 1 msec */
	fakeclock_tick++;

	count_test("IPv4 rate limit /32 after 1 msec", RATEM(V4, 32), 0,
			AF_INET, "128.0.0.0", 0, 0);

	count_test("IPv6 rate limit /128 after 1 msec", RATEM(V6, 128), 0,
			AF_INET6, "8000::", 0, 0);

	/* parallel tests */
	struct stage stages[] = {
		/* first tick, last tick, hosts */
		{32, 32, {
			/* queries per tick, family, address, min passed, max passed */
			{1024, AF_INET,  "%d.%d.%d.1",   RANGE_UNLIM (  1024   )},
			{1024, AF_INET,  "3.3.3.3",      RANGE_INST  ( V4,  32 )},
			{ 512, AF_INET,  "4.4.4.4",      RANGE_INST  ( V4,  32 )},
			{1024, AF_INET6, "%x%x:%x00::1", RANGE_UNLIM (  1024   )},
			{1024, AF_INET6, "3333::3333",   RANGE_INST  ( V6, 128 )},
			{ 512, AF_INET6, "4444::4444",   RANGE_INST  ( V6, 128 )}
		}},
		{33, 255, {
			{1024, AF_INET,  "%d.%d.%d.1",   RANGE_UNLIM (  1024   )},
			{1024, AF_INET,  "3.3.3.3",      RANGE_RATEM ( V4,  32 )},
			{ 512, AF_INET,  "4.4.4.4",      RANGE_RATEM ( V4,  32 )},
			{1024, AF_INET6, "%x%x:%x00::1", RANGE_UNLIM (  1024   )},
			{1024, AF_INET6, "3333::3333",   RANGE_RATEM ( V6, 128 )},
			{ 512, AF_INET6, "4444::4444",   RANGE_RATEM ( V6, 128 )},
		}},
		{256, 511, {
			{1024, AF_INET,  "3.3.3.3",      RANGE_RATEM ( V4,  32 )},
			{1024, AF_INET6, "3333::3333",   RANGE_RATEM ( V6, 128 )}
		}},
		{512, 512, {
			{1024, AF_INET,  "%d.%d.%d.1",   RANGE_UNLIM (  1024   )},
			{1024, AF_INET,  "3.3.3.3",      RANGE_RATEM ( V4,  32 )},
			{ 512, AF_INET,  "4.4.4.4",      RANGE_INST  ( V4,  32 )},
			{1024, AF_INET6, "%x%x:%x00::1", RANGE_UNLIM (  1024   )},
			{1024, AF_INET6, "3333::3333",   RANGE_RATEM ( V6, 128 )},
			{ 512, AF_INET6, "4444::4444",   RANGE_INST  ( V6, 128 )}
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
				"rrl(%s): parallel stage %d, addr %-25s [%7d <=%12.4f <=%7d ]", impl_name,
				si, h[i].addr_format, h[i].min_passed, (double)h[i].passed / ticks, h[i].max_passed);
		}
	} while (stages[++si].first_tick);

	rrl_destroy(rrl);
}

void test_rrl_mode(bool test_avx2, bool rw_mode)
{
	if (!rw_mode) {
		DIFF = 1;
	}

	KRU = KRU_GENERIC;
	impl_name = "KRU_GENERIC";
	test_rrl(rw_mode);

	if (test_avx2) {
		KRU = KRU_AVX2;
		impl_name = "KRU_AVX2";
		test_rrl(rw_mode);
	} else {
		diag("AVX2 NOT available");
	}
}

int main(int argc, char *argv[])
{
	plan_lazy();

	dnssec_crypto_init();

	assert(KRU_GENERIC.initialize != KRU_AVX2.initialize);
	bool test_avx2 = (KRU.initialize == KRU_AVX2.initialize);

	test_rrl_mode(test_avx2, true);
	test_rrl_mode(test_avx2, false);

	dnssec_crypto_cleanup();
	return 0;
}
