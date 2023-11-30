/** @file

KRU is a variant of Count sketch with aging

The point is to answer point-queries that estimate if the item has been heavily used recently.
To give more weight to recent usage, we use aging via exponential decay (simple to compute).
That has applications for garbage collection of cache and various limiting scenario
(excessive rate, traffic, CPU, maybe RAM).


### Choosing parameters

For limiting, `time` is probably in milliseconds from kr_now().
In case of DECAY_32, we get at most 46M per tick which gives 46G per second.
Say, if we want p QPS, we add `46G / p` for each query.

Tick length (`ticklen_log`) will need to be chosen the same for all users of a given table.
Smaller resolvers might choose more than a single millisecond to get longer half-life.

Size (`loads_bits` = log2 length):
 - The KRU takes 128 bytes * length * TABLE_COUNT + some small constants.
 - The length should probably be at least something like the square of the number of utilized CPUs.
   But this most likely won't be a limiting factor.
 - TODO: more info
   - Cache: it has fixed size in bytes, so we can estimate the number of keepable items,
     and/or we can choose how much of additional bytes to use for KRU.

*/

#include <stdlib.h>
#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "knot/modules/rrl/kru.h"
#include "contrib/openbsd/siphash.h"

#if __GNUC__ >= 4
	#define ALIGNED_CPU_CACHE __attribute__((aligned(64)))
	#define ALIGNED(_bytes)   __attribute__((aligned(_bytes)))
#else
	#define ALIGNED_CPU_CACHE
	#define ALIGNED(_bytes)
#endif

void *memzero(void *s, size_t n)
{
	typedef void *(*memset_t)(void *, int, size_t);
	static volatile memset_t volatile_memset = memset;
	return volatile_memset(s, 0, n);
}

/// Block of loads sharing the same time, so that we're more space-efficient.
/// It's exactly a single cache line.
struct load_cl {
	uint32_t time;
	#define LOADS_LEN 15
	int32_t loads[LOADS_LEN];
} ALIGNED_CPU_CACHE;
static_assert(64 == sizeof(struct load_cl), "bad size of struct load_cl");

/// Parametrization for speed of decay.
struct decay_config {
	/// Length of one tick is 2 ^ ticklen_log.
	uint32_t ticklen_log;
	/// Exponential decay with half-life of (2 ^ half_life_log) ticks.
	uint32_t half_life_log;
	/// Precomputed scaling constants.  Indexed by tick count [1 .. 2^half_life_log - 1],
	///   contains the corresponding factor of decay (<1, scaled to 2^31 and rounded).
	int32_t scales[];
};
typedef const struct decay_config decay_cfg_t;

/// Catch up the time drift with configurably slower decay.
static void update_time(struct load_cl *l, const uint32_t time_now, decay_cfg_t *decay)
{
	// We get `ticks` in this loop:
	//  - first, non-atomic check that no tick's happened (typical under attack)
	//  - on the second pass we advance l->time atomically
	uint32_t ticks;
	uint32_t time_last = l->time;
	for (int i = 1; i < 2; ++i,time_last = atomic_exchange(&l->time, time_now)) {
		ticks = (time_now - time_last) >> decay->ticklen_log;
		if (!ticks)
			return;
		// We accept some desynchronization of time_now (e.g. from different threads).
		if (ticks > (uint32_t)-1024)
			return;
	}
	// If we passed here, we should be the only thread updating l->time "right now".

	// Don't bother with complex computations if lots of ticks have passed.
	// TODO: maybe store max_ticks_log precomputed inside *decay? (or (1 << max_ticks_log)-1)
	const uint32_t max_ticks_log = /* ticks to shift by one bit */ decay->half_life_log
					/* + log2(bit count) */ + 3 + sizeof(l->loads[0]);
	if (ticks >> max_ticks_log > 0) {
		memset(l->loads, 0, sizeof(l->loads));
		return;
	}

	// some computations pulled outside of the cycle
	const uint32_t decay_frac = ticks & (((uint32_t)1 << decay->half_life_log) - 1);
	const uint32_t load_nonfrac_shift = ticks >> decay->half_life_log;
	for (int i = 0; i < LOADS_LEN; ++i) {
		// decay: first do the "fractional part of the bit shift"
		int64_t m = (int64_t)l->loads[i] * decay->scales[decay_frac];
		int32_t l1 = m >> 31;
		// finally the non-fractional part of the bit shift
		l->loads[i] = l1 >> load_nonfrac_shift;
		// rounding during signed shift(s) would be too complicated?
	}
}
/// Half-life of 32 ticks, consequently forgetting in about 1k ticks.
/// Experiment: if going by a single tick, after 840 steps +0 (or fixed at -46),
///  but accuracy at the beginning of that (first 32 ticks) is very good,
///  getting from max 2^31 - 1 to 2^30 - 9 or -2^31 to -2^30 - 17.
///  Max. decay per tick is 46016146.
const struct decay_config DECAY_32 = {
	.ticklen_log = 0,
	.half_life_log = 5,
	.scales = { // ghci> map (\i -> round(2^31 * 0.5 ** (i/32))) [1..31]
		0, 2101467502,2056437387,2012372174,1969251188,1927054196,1885761398,
		1845353420,1805811301,1767116489,1729250827,1692196547,1655936265,
		1620452965,1585730000,1551751076,1518500250,1485961921,1454120821,
		1422962010,1392470869,1362633090,1333434672,1304861917,1276901417,
		1249540052,1222764986,1196563654,1170923762,1145833280,1121280436,1097253708
	}
};


struct kru {
	/// Length of `loads_cls`, stored as binary logarithm.
	uint32_t loads_bits;
	/// Hashing secret.  Random but shared by all users of the table.
	SIPHASH_KEY hash_key;  // TODO use or remove

	#define TABLE_COUNT 2
	/// These are read-write.  Each struct has exactly one cache line.
	struct load_cl load_cls[][TABLE_COUNT];
};

struct kru *kru_init(uint32_t loads_bits)
{
	struct kru *kru = calloc(1, offsetof(struct kru, load_cls) + sizeof(struct load_cl) * TABLE_COUNT * (1 << loads_bits));

	kru->loads_bits = loads_bits;
	// hash_key zero-initialized

	return kru;
}
void kru_destroy(struct kru *kru) {
	free(kru);
}

/// Update limiting and return true iff it hit the limit instead.
bool kru_limited(struct kru *kru, uint64_t hash, uint32_t time_now, uint32_t price)
{
	assert(sizeof(hash) * 8 >= TABLE_COUNT * (kru->loads_bits + LOADS_LEN));

	// Choose two struct load_cl, i.e. two cache-lines to operate on,
	// update their notion of time, and copy all their loads.
	struct load_cl *l[TABLE_COUNT];
	int32_t l_c[TABLE_COUNT * LOADS_LEN];
	const uint32_t loads_mask = (1 << kru->loads_bits) - 1;
	for (int li = 0; li < TABLE_COUNT; ++li) {
		l[li] = &kru->load_cls[hash & loads_mask][li];
		hash >>= kru->loads_bits;
		update_time(l[li], time_now, &DECAY_32);
		memcpy(&l_c[li * LOADS_LEN], l[li]->loads, sizeof(l[li]->loads));
	}

	// Update the copied loads, saturating to max. value.
	// __builtin_add_overflow: GCC+clang most likely suffice for us
	// TODO: check that all is OK, maybe use addition with saturation in x86 asm
	// The estimate is median of values, so we only count how many are over limit.
	int over_limit = 0;
	for (int i = 0; i < TABLE_COUNT * LOADS_LEN; ++i) {
		const int32_t sign = 2 * ((int32_t)hash&1) - 1; // 0 or 1  ->  -1 or 1
		hash >>= 1;
		int32_t * const load = &l_c[i];
		if (__builtin_add_overflow(*load, sign * (int32_t)price, load)) {
			if (++over_limit > TABLE_COUNT * LOADS_LEN / 2)
				return true; // TODO: equality?
			*load = sign * (int32_t)((1ull<<31) - 1);
		}
	}
	// Not limited, so copy the updated loads back.
	for (int li = 0; li < TABLE_COUNT; ++li)
		memcpy(l[li]->loads, &l_c[li * LOADS_LEN], sizeof(l[li]->loads));
	return false;
}


#include <stdio.h>
#include <inttypes.h>
void test_decay32(void)
{
	struct load_cl l = { .loads[0] = (1ull<<31) - 1, .loads[1] = -(1ll<<31), .time = 0 };
	for (uint32_t time = 0; time < 850; ++time) {
		update_time(&l, time, &DECAY_32);
		printf("%3d: %08d %08d\n", time, (int)l.loads[0], (int)l.loads[1]);
	}
}


struct test_ctx {
	struct kru *kru;
	uint32_t time;
	uint32_t price;
	size_t cnt;
	struct test_cat {
		char *name;
		uint64_t id_min, id_max;
	} *cats;  // categories
};

void test_stage(struct test_ctx *ctx, uint32_t dur, uint64_t *freq) {
	printf("STAGE: ");
	for (size_t cat = 0; cat < ctx->cnt; ++cat) {
		printf("%" PRIu64 ", ", freq[cat]);
	}
	printf("ticks %" PRIu32 "-%" PRIu32 "\n", ctx->time, ctx->time + dur - 1);

	uint64_t freq_bounds[ctx->cnt];
	freq_bounds[0] = freq[0];
	for (size_t cat = 1; cat < ctx->cnt; ++cat) {
		freq_bounds[cat] = freq_bounds[cat-1] + freq[cat];
	}

	uint64_t cat_passed[ctx->cnt], cat_total[ctx->cnt];
	for (size_t cat = 0; cat < ctx->cnt; ++cat) {
		cat_passed[cat] = 0;
		cat_total[cat] = 0;
	}

	for (uint64_t end_time = ctx->time + dur; ctx->time < end_time; ctx->time++) {
		for (uint64_t i = 0; i < freq_bounds[ctx->cnt-1]; i++) {
			long rnd = random() % freq_bounds[ctx->cnt-1];  // TODO initialize random generator
			size_t cat;
			for (cat = 0; freq_bounds[cat] <= rnd; cat++);

			uint64_t id = random() % (ctx->cats[cat].id_max - ctx->cats[cat].id_min + 1) + ctx->cats[cat].id_min;

			cat_total[cat]++;
			uint64_t hash = SipHash24(&ctx->kru->hash_key, &id, sizeof(id));
			cat_passed[cat] += !kru_limited(ctx->kru, hash, ctx->time, ctx->price);
		}
	}
	for (size_t cat = 0; cat < ctx->cnt; ++cat) {
		printf("  %-15s:  %8.2f /%10.2f per tick, %8" PRIu64 " /%10" PRIu64 " in total, %8.4f %% passed \n",
				ctx->cats[cat].name,
				(float)cat_passed[cat] / dur, (float)cat_total[cat] / dur,
				cat_passed[cat], cat_total[cat],
				100.0 * cat_passed[cat] / cat_total[cat]);
	}
	printf("\n");
}

#define TEST_STAGE(duration, ...) test_stage(&ctx, duration, (uint64_t[]) {__VA_ARGS__});

void test(void) { // TODO more descriptive name
	struct kru *kru = kru_init(16);

	struct test_cat cats[] = {
		{ "normal",       1,1000  },   // normal queries come from 1000 different addreses indexed 1-1000
		{ "attackers", 1001,1002  }    // attackers use only two adresses indexed 1001,1002
	};

	struct test_ctx ctx = {.kru = kru, .time = 0, .cats = cats, .cnt = sizeof(cats)/sizeof(struct test_cat),
		.price = 1<<23  // same price for all packets
	};

	// in each out of 10 ticks send around 1000 queries from random normal addresses and 500000 from each of the two attackers
	TEST_STAGE( 10,    1000, 1000000); // (duration, normal, attackers)

	TEST_STAGE( 10,    1000, 1000000);
	TEST_STAGE( 100,   1000, 100000);
	TEST_STAGE( 100,   1000, 10000);
	TEST_STAGE( 100,   1000, 1000);
	TEST_STAGE( 100,   1000, 100);
	TEST_STAGE( 100,   1000, 10);
	TEST_STAGE( 10000, 1000, 2);  // both categories have the same frequency per individual

	TEST_STAGE( 100,   1000, 10000); // another attack after period without limitation

	kru_destroy(kru);
}

#undef TEST_STAGE

int main(int argc, char **argv)
{
	test();

	// struct kru kru __attribute__((unused));
	// test_decay32();
	return 0;
}
