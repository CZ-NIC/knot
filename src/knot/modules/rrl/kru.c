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
#include "libdnssec/error.h"
#include "libdnssec/random.h"


#if __GNUC__ >= 4
	#define ALIGNED_CPU_CACHE __attribute__((aligned(64)))
	#define ALIGNED(_bytes)   __attribute__((aligned(_bytes)))
#else
	#define ALIGNED_CPU_CACHE
	#define ALIGNED(_bytes)
#endif

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

	if (dnssec_random_buffer((uint8_t *)&kru->hash_key, sizeof(kru->hash_key)) != DNSSEC_EOK) {
		free(kru);
		return NULL;
	}

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
bool kru_limited(struct kru *kru, void *buf, size_t buf_len, uint32_t time_now, uint32_t price)
{
	uint64_t hash = SipHash24(&kru->hash_key, buf, buf_len);
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
