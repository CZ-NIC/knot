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
	int32_t loads[LOADS_LEN];
} ALIGNED_CPU_CACHE;
static_assert(64 == sizeof(struct load_cl), "bad size of struct load_cl");

#define KRU_DECAY_BITS 31
#include "knot/modules/rrl/kru-decay.c"

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

/// Update limiting and return true iff it hit the limit instead.
bool kru_limited(struct kru *kru, void *buf, size_t buf_len, uint32_t time_now, uint32_t price)
{

	uint64_t hash = SipHash24(&kru->hash_key, buf, buf_len);
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
			++over_limit;
			*load = sign * (int32_t)((1ull<<31) - 1);
		} else {
			if ((sign > 0 && *load > (1<<30)) ||
			    (sign < 0 && *load < -(1<<30))) {
				++over_limit;
			}
		}
		if (over_limit > TABLE_COUNT * LOADS_LEN / 2)
			return true; // TODO: equality?
	}
	// Not limited, so copy the updated loads back.
	for (int li = 0; li < TABLE_COUNT; ++li)
		memcpy(l[li]->loads, &l_c[li * LOADS_LEN], sizeof(l[li]->loads));
	return false;
}
