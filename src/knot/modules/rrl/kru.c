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
 - The KRU takes 16 bytes * length + some small constant.
 - The length should probably be at least something like the square of the number of utilized CPUs.
   But this most likely won't be a limiting factor.
 - The length should be at least some multiple of max.number of heavy hitters to track.
   - The square of this ratio gives roughly the false-positive rate.
   - Cache: it has fixed size in bytes, so we can estimate the number of keepable items,
     and/or we can choose how much of additional bytes to use for KRU.

*/

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>

#include "knot/modules/rrl/kru.h"
#include "contrib/openbsd/siphash.h"

#if __GNUC__ >= 4
	#define ALIGNED_CPU_CACHE __attribute__((aligned(64)))
	#define ALIGNED(_bytes)   __attribute__((aligned(_bytes)))
#else
	#define ALIGNED_CPU_CACHE
	#define ALIGNED(_bytes)
#endif


struct load {
	uint32_t load, time;
// align to keep the whole struct in a single cache line
} ALIGNED(8);

/// Catch up the time drift.  Trivial version decaying to half on each tick.
static inline void update_time_trivial(struct load *l, uint32_t time_now, uint32_t ticklen_log)
{
	const uint32_t ticks = (time_now - l->time) >> ticklen_log;
	if (!ticks)
		return;
	l->time = time_now;
	l->load >>= ticks;
}

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
static void update_time(struct load *l, const uint32_t time_now, decay_cfg_t *decay)
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
	// Don't bother with complex computations if lots of ticks have passed.
	// TODO: maybe store max_ticks_log precomputed inside *decay? (or (1 << max_ticks_log)-1)
	const uint32_t max_ticks_log = /* ticks to shift by one bit */ decay->half_life_log
					/* + log2(bit count) */ + 3 + sizeof(l->load);
	if (ticks >> max_ticks_log > 0) {
		l->load = 0;
		return;
	}
	// Decay: first do the "fractional part of the bit shift".
	const uint32_t decay_frac = ticks & (((uint32_t)1 << decay->half_life_log) - 1);
	uint64_t m = (uint64_t)l->load * decay->scales[decay_frac];
	uint32_t l1 = (m >> 32) + /*rounding*/((m >> 31) & 1);
	// finally the non-fractional part of the bit shift
	l->load = l1 >> (ticks >> decay->half_life_log);
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
	/// Length of a tick, stored as binary logarithm.
	uint32_t ticklen_log;
	/// Length of `loads`, stored as binary logarithm.
	uint32_t loads_bits;
	/// Hashing secret.  Random but shared by all users of the table.
	SIPHASH_KEY hash_key;

	/// These are read-write, so avoid sharing a cache line with the constants above.
	struct load loads[][2] ALIGNED_CPU_CACHE;
};

/// Update limiting and return true iff it hit the limit instead.
bool kru_limited(struct kru *kru, uint64_t hash, uint32_t time_now, uint32_t price)
{
	// Compute the two locations in table
	const uint32_t loads_mask = (1 << kru->loads_bits) - 1;
	struct load *l0 = &kru->loads[hash & loads_mask][0];
	struct load *l1 = &kru->loads[(hash >> 32) & loads_mask][1];
	// Refresh their loads
	update_time(l0, time_now, &DECAY_32);
	const uint32_t l0_l = l0->load;
	update_time(l1, time_now, &DECAY_32);
	const uint32_t l1_l = l1->load;
	// Check whether we shot over the limit
	const uint32_t limit = -price;
	if (l0_l >= limit && l1_l >= limit)
		return true;
	// Update the loads, saturating to max. value (-1).
	// We're trying hard to avoid overflow even in case of races.
	// TODO: check that all is OK, maybe use stdatomic.h
	//  or addition with saturation might be easy and efficient in x86 asm
	//  or __builtin_add_overflow (GCC+clang most likely suffice for us)
	l0->load = (l0_l >= limit) ? -1 : l0_l + price;
	l1->load = (l1_l >= limit) ? -1 : l1_l + price;
	return false;
}


#include <stdio.h>
void test_decay32(void)
{
	struct load l = { .load = -1, .time = 0 };
	for (uint32_t time = 0; time < 1030; ++time) {
		update_time(&l, time, &DECAY_32);
		printf("%d: %zd\n", time, (size_t)l.load);
	}
}

int main(int argc, char **argv)
{
	struct kru kru __attribute__((unused));
	test_decay32();
	return 0;
}
