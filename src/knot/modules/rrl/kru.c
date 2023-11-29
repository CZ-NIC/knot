/** @file

KRU is a Count-min sketch with aging

The point is to answer point-queries that estimate if the item has been heavily used recently.
To give more weight to recent usage, we use aging via exponential decay (simple to compute).
That has applications for garbage collection of cache and various limiting scenario
(excessive rate, traffic, CPU, maybe RAM).


### Choosing parameters

For limiting, `time` is probably in milliseconds from kr_now().
In case of DECAY_32, we get at most 92M per tick which gives 92G per second.
Say, if we want p QPS, we add `92G / p` for each query.

Tick length (`ticklen_log`) will need to be chosen the same for all users of a given table.
Smaller resolvers might choose more than a single millisecond to get longer half-life,
as it's advisable to allow at least several queries per tick.

Size (`loads_bits`):
 - The KRU takes 128 bytes * length + some small constants.
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
	uint32_t loads[LOADS_LEN];
} ALIGNED_CPU_CACHE;
static_assert(64 == sizeof(struct load_cl), "bad size of struct load_cl");

/// Parametrization for speed of decay.
struct decay_config {
	/// Length of one tick is 2 ^ ticklen_log.
	uint32_t ticklen_log;
	/// Exponential decay with half-life of (2 ^ half_life_log) ticks.
	uint32_t half_life_log;
	/// Precomputed scaling constants.  Indexed by tick count [1 .. 2^half_life_log - 1],
	///   contains the corresponding factor of decay (<1, scaled to 2^32 and rounded).
	uint32_t scales[];
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
		uint64_t m = (uint64_t)l->loads[i] * decay->scales[decay_frac];
		uint32_t l1 = (m >> 32) + /*rounding*/((m >> 31) & 1);
		// finally the non-fractional part of the bit shift
		l->loads[i] = l1 >> load_nonfrac_shift;
	}

}
/// Half-life of 32 ticks, consequently forgetting in about 1k ticks.
/// Experiment: if going by a single tick, fix-point at load 23 after 874 steps,
///  but accuracy at the beginning of that (first 32 ticks) is very good,
///  getting from max 2^32 - 1 to 2^31 - 7.  Max. decay per tick is 92032292.
const struct decay_config DECAY_32 = {
	.ticklen_log = 0,
	.half_life_log = 5,
	.scales = { // ghci> map (\i -> round(2^32 * 0.5 ** (i/32))) [1..31]
		0, 4202935003,4112874773,4024744348,3938502376,3854108391,3771522796,
		3690706840,3611622603,3534232978,3458501653,3384393094,3311872529,
		3240905930,3171459999,3103502151,3037000500,2971923842,2908241642,
		2845924021,2784941738,2725266179,2666869345,2609723834,2553802834,
		2499080105,2445529972,2393127307,2341847524,2291666561,2242560872,2194507417
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


/// Choose almost uniformly 4 bits out of 15, consume ~15 bits from hash, return bitmap.
uint32_t choose_4_15(uint64_t *hash) {
	// We use just a little less that 15 bits:  15 * 14 * 13 * 12  =  2^15 - 8
	// If the hash has exactly 15 bits, 4 combinations have higher probabilities by at most 0.003.
	// We can save 4 bits from ordering of chosen bits, if needed.

	uint32_t chosen_last;
		// bitmap containing one chosen bit out of 15, after shifts caused by previously chosen bits;
		// each previous bit to the right of the last one (or on same position) causes shift by one to the left;
		// shifts caused by the previous bits should be applied one-by-one ordered from the rightmost bit

	uint32_t chosen_unshifted[4] = {0};
		// bitmaps before left shifts with reverted left shifts that would be caused by the following bits;
		// those bitmaps can be used invariant to their order to recognize shifts in the following bit

	uint32_t chosen_all = 0;
	for (size_t i = 0; i < 4; i++) {
		chosen_unshifted[i] = chosen_last = 1 << *hash % (15-i);
		*hash /= (15-i);
		for (size_t j = 0; j < i; j++) {
			chosen_last <<= chosen_unshifted[i] >= chosen_unshifted[j];
			chosen_unshifted[j] >>= chosen_unshifted[i] < chosen_unshifted[j];
		}
		chosen_all |= chosen_last;
	}
	return chosen_all;
}

/// Update limiting and return true iff it hit the limit instead.
bool kru_limited(struct kru *kru, uint64_t hash, uint32_t time_now, uint32_t price)
{
	assert(sizeof(hash) * 8 >= TABLE_COUNT * (kru->loads_bits + 15));
	/*
		TODO: update/remove this comment, prob_bits were removed.
		Given 64-bit hash + TABLE_COUNT cache-lines of 15 items:
		prob_bits -> max loads_bits  | opt. heavy-hitter limit (see prob_bits comment)
		1 -> 24  | 2^26
		2 -> 17  | 2^20
		3 -> 9   | 2^13
		We might just need longer hash, e.g. an array of SIPHASHes.
	*/

	// Choose two struct load_cl, i.e. two cache-lines to operate on,
	// and update their notion of time.
	struct load_cl *l[TABLE_COUNT];
	const uint32_t loads_mask = (1 << kru->loads_bits) - 1;
	for (int li = 0; li < TABLE_COUNT; ++li) {
		l[li] = &kru->load_cls[hash & loads_mask][li];
		hash >>= kru->loads_bits;
		update_time(l[li], time_now, &DECAY_32);
	}

	const uint32_t limit = -price;
	// Check if an index indicates that we're under the limit.
	uint64_t prnd = hash;
	for (int li = 0; li < TABLE_COUNT; ++li) {
		assert(LOADS_LEN == 15);
		uint32_t chosen_loads = choose_4_15(&prnd);
		for (int i = 0; i < LOADS_LEN; ++i) {
			bool use_load = chosen_loads & 1;
			chosen_loads >>= 1;
			if (!use_load)
				continue;
			if (l[li]->loads[i] < limit)
				goto under_limit;
		}
	}
	return true; // All positions were on the limit or higher.
under_limit:
	// Update the loads, saturating to max. value (-1).
	// We're trying hard to avoid overflow even in case of races.
	//  __builtin_add_overflow: GCC+clang most likely suffice for us
	// TODO: check that all is OK, maybe use stdatomic.h
	//  or addition with saturation might be easy and efficient in x86 asm
	prnd = hash;
	for (int li = 0; li < TABLE_COUNT; ++li) {
		size_t cnt=0;
		uint32_t chosen_loads = choose_4_15(&prnd);
		for (int i = 0; i < LOADS_LEN; ++i) {
			bool use_load = chosen_loads & 1;
			chosen_loads >>= 1;
			if (!use_load)
				continue;
			uint32_t * const load = &l[li]->loads[i];
			if (__builtin_add_overflow(*load, price, load))
				*load = -1;
			cnt++;
		}
	}
	return false;
}


#include <stdio.h>
#include <inttypes.h>
void test_decay32(void)
{
	struct load_cl l = { .loads[0] = -1, .time = 0 };
	for (uint32_t time = 0; time < 1030; ++time) {
		update_time(&l, time, &DECAY_32);
		printf("%3d: %08zx\n", time, (size_t)l.loads[0]);
	}
}

void test_choose_4_15() {
	#define MAX_HASH    (15*14*13*12) // uniform distribution expected
	//#define MAX_HASH    (1<<15)     // case with exactly 15 bits, a little biased
	#define MAX_BITMAP  (1<<15)
	#define HIST_LEN    (10000)

	uint32_t chosen_cnts[MAX_BITMAP] = {0};
	for (uint64_t i = 0; i < MAX_HASH; i++) {
		uint64_t hash = i;
		uint32_t chosen = choose_4_15(&hash);
		if (chosen > MAX_BITMAP) {
			printf("bitmap out of range: %d %d\n", i, chosen);
			return;
		}
		chosen_cnts[chosen]++;
	}
	uint32_t hist[HIST_LEN] = {0};
	for (size_t i = 0; i < MAX_BITMAP; i++) {
		if (chosen_cnts[i] > HIST_LEN) {
			printf("short hist: %d %d\n", i, chosen_cnts[i]);
			return;
		}
		hist[chosen_cnts[i]]++;
	}
	int nonzero = 0;
	for (size_t i = 0; i < sizeof(hist)/sizeof(uint32_t); i++) {
		if (hist[i] == 0) continue;
		printf("%2d: %5d\n", i, hist[i]);
		if (i > 0) nonzero++;
	}

	if (nonzero = 1) {
		printf("Uniform.\n");
	} else {
		printf("Not uniform.\n");
	}

	#undef MAX_HASH
	#undef MAX_BITMAP
	#undef HIST_LEN
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
		{ "attackers", 1001,1001  }    // attackers use only two adresses indexed 1001,1002
	};

	struct test_ctx ctx = {.kru = kru, .time = 0, .cats = cats, .cnt = sizeof(cats)/sizeof(struct test_cat),
		.price = 1<<23  // same price for all packets
	};

	// in each out of 10 ticks send around 1000 queries from random normal addresses and 500000 from each of the two attackers
	TEST_STAGE( 1,     1000, 1000000); // (duration, normal, attackers)
	TEST_STAGE( 10,    1000, 1000000);

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
	//test_choose_4_15();

	test();

	// struct kru kru __attribute__((unused));
	// test_decay32();
	return 0;
}
