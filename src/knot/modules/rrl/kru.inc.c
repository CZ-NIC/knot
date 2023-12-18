/** @file

FIXME: clean up.  Lots of comments in the file are wrong now, etc.

KRU estimates recently pricey inputs

Authors of the simple agorithm (without aging, multi-choice, etc.):
  Metwally, D. Agrawal, and A. E. Abbadi.
  Efficient computation of frequent and top-k elements in data streams.
  In International Conference on Database Theory, 2005.

With TABLE_COUNT > 1 we're improving reliability by utilizing the property that
longest buckets (cache-lines) get very much shortened, already by providing two choices:
  https://en.wikipedia.org/wiki/2-choice_hashing

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

/// Block of loads sharing the same time, so that we're more space-efficient.
/// It's exactly a single cache line.
struct load_cl {
	_Atomic uint32_t time;
	#define LOADS_LEN 15
	uint16_t ids[LOADS_LEN];
	uint16_t loads[LOADS_LEN];
} ALIGNED_CPU_CACHE;
static_assert(64 == sizeof(struct load_cl), "bad size of struct load_cl");


#include "knot/modules/rrl/kru-decay.inc.c"


#include "libdnssec/error.h"
#include "libdnssec/random.h"
typedef uint64_t hash_t;
#if USE_AES
	/// 4-8 rounds should be an OK choice, most likely.  TODO: confirm
	#define AES_ROUNDS 4
#else
	#include "contrib/openbsd/siphash.h"
	/// 1,3 should be OK choice, probably.  TODO: confirm
	#define hash(_k, _p, _l)  SipHash((_k), 1, 3, (_p), (_l))
#endif


#if USE_AVX2 || USE_SSE41 || USE_AES
	#include <immintrin.h>
	#include <x86intrin.h>
#endif

struct kru {
#if USE_AES
	/// Hashing secret.  Random but shared by all users of the table.
	/// Let's not make it too large, so that header fits into 64 Bytes.
	char hash_key[48] ALIGNED(32);
#else
	/// Hashing secret.  Random but shared by all users of the table.
	SIPHASH_KEY hash_key;
#endif

	/// Length of `loads_cls`, stored as binary logarithm.
	uint32_t loads_bits;

	#define TABLE_COUNT 2
	/// These are read-write.  Each struct has exactly one cache line.
	struct load_cl load_cls[][TABLE_COUNT];
};

/// Convert capacity_log to loads_bits
static inline int32_t capacity2loads(int capacity_log)
{
	static_assert(LOADS_LEN == 15 && TABLE_COUNT == 2, "");
	// So, the pair of cache lines hold up to 2*15 elements.
	// Let's say that we can reliably store 16 = 1 << (1+3).
	// (probably more but certainly not 1 << 5)
	const int shift = 1 + 3;
	int loads_bits = capacity_log - shift;
	// Let's behave reasonably for weird capacity_log values.
	return loads_bits > 0 ? loads_bits : 1;
}

static struct kru *kru_create(int capacity_log)
{
	struct kru *kru;
	uint32_t loads_bits = capacity2loads(capacity_log);
	if (8 * sizeof(hash_t) < TABLE_COUNT * loads_bits
				+ 8 * sizeof(kru->load_cls[0]->ids[0])) {
		assert(false);
		return NULL;
	}

	size_t size = offsetof(struct kru, load_cls)
		    + sizeof(struct load_cl) * TABLE_COUNT * (1 << loads_bits);
	// ensure good alignment
	if (posix_memalign((void **)&kru, 64, size) != 0)
		return NULL;

	kru->loads_bits = loads_bits;

	if (dnssec_random_buffer((uint8_t *)&kru->hash_key, sizeof(kru->hash_key)) != DNSSEC_EOK) {
		free(kru);
		return NULL;
	}

	return kru;
}

/// Update limiting and return true iff it hit the limit instead.
static bool kru_limited(struct kru *kru, char key[static const 16], uint32_t time_now, uint16_t price)
{
	// Obtain hash of *buf.
	uint64_t hash;
#if !USE_AES
	hash = hash(&kru->hash_key, key, 16);
#else
	{
		__m128i h; /// hashing state
		h = _mm_load_si128((__m128i *)key);
		// Now do the the hashing itself.
		__m128i *aes_key = (void*)kru->hash_key;
		for (int i = 0; i < AES_ROUNDS; ++i) {
			int key_id = i % (sizeof(kru->hash_key) / sizeof(__m128i));
			h = _mm_aesenc_si128(h, _mm_load_si128(&aes_key[key_id]));
		}
		memcpy(&hash, &h, sizeof(hash));
	}
	//FIXME: gcc 12 is apparently mixing code of hashing with update_time() ?!
#endif

	// Choose the cache-lines to operate on
	struct load_cl *l[TABLE_COUNT];
	const uint32_t loads_mask = (1 << kru->loads_bits) - 1;
	// Fetch the two cache-lines in parallel before we really touch them.
	for (int li = 0; li < TABLE_COUNT; ++li) {
		l[li] = &kru->load_cls[hash & loads_mask][li];
		__builtin_prefetch(l[li], 0); // hope for read-only access
		hash >>= kru->loads_bits;
	}
	for (int li = 0; li < TABLE_COUNT; ++li)
		update_time(l[li], time_now, &DECAY_32);

	uint16_t id = hash;
	hash >>= 16;

	// Find matching element.  Matching 16 bits in addition to loads_bits.
	uint16_t *load = NULL;
#if !USE_AVX2
	for (int li = 0; li < TABLE_COUNT; ++li)
		for (int i = 0; i < LOADS_LEN; ++i)
			if (l[li]->ids[i] == id) {
				load = &l[li]->loads[i];
				goto load_found;
			}
#else
	const __m256i id_v = _mm256_set1_epi16(id);
	for (int li = 0; li < TABLE_COUNT; ++li) {
		static_assert(LOADS_LEN == 15 && sizeof(l[li]->ids[0]) == 2, "");
		// unfortunately we can't use aligned load here
		__m256i ids_v = _mm256_loadu_si256(((__m256i *)&l[li]->ids[-1]));
		__m256i match_mask = _mm256_cmpeq_epi16(ids_v, id_v);
		if (_mm256_testz_si256(match_mask, match_mask))
			continue; // no match of id
		int index = _bit_scan_reverse(_mm256_movemask_epi8(match_mask)) / 2 - 1;
		// there's a small possibility that we hit equality only on the -1 index
		if (index >= 0) {
			load = &l[li]->loads[index];
			goto load_found;
		}
	}
#endif

	if (load)
		goto load_found;

	// No match, so find position of the smallest load.
	int min_li = 0;
	int min_i = 0;
#if !USE_SSE41
	for (int li = 0; li < TABLE_COUNT; ++li)
		for (int i = 0; i < LOADS_LEN; ++i)
			if (l[li]->loads[i] < l[min_li]->loads[min_i]) {
				min_li = li;
				min_i = i;
			}
#else
	int min_val = 0;
	for (int li = 0; li < TABLE_COUNT; ++li) {
		// BEWARE: we're relying on the exact memory layout of struct load_cl,
		//  where the .loads array take 15 16-bit values at the very end.
		static_assert((offsetof(struct load_cl, loads) - 2) % 16 == 0,
				"bad alignment of struct load_cl::loads");
		static_assert(LOADS_LEN == 15 && sizeof(l[li]->loads[0]) == 2, "");
		__m128i *l_v = ((__m128i *)(&l[li]->loads[-1]));
		__m128i l0 = _mm_load_si128(l_v);
		__m128i l1 = _mm_load_si128(l_v + 1);
		// We want to avoid the first item in l0, so we maximize it.
		l0 = _mm_insert_epi16(l0, (1<<16)-1, 0);

		// Only one instruction can find minimum and its position,
		// and it works on 8x uint16_t.
		__m128i mp0 = _mm_minpos_epu16(l0);
		__m128i mp1 = _mm_minpos_epu16(l1);
		int min0 = _mm_extract_epi16(mp0, 0);
		int min1 = _mm_extract_epi16(mp1, 0);
		int min01, min_ix;
		if (min0 < min1) {
			min01 = min0;
			min_ix = _mm_extract_epi16(mp0, 1);
		} else {
			min01 = min1;
			min_ix = 8 + _mm_extract_epi16(mp1, 1);
		}

		if (li == 0 || min_val > min01) {
			min_li = li;
			min_i = min_ix;
			min_val = min01;
		}
	}
	// now, min_i (and min_ix) is offset by one due to alignment of .loads
	if (min_i != 0) // zero is very unlikely
		--min_i;
#endif

	l[min_li]->ids[min_i] = id;
	load = &l[min_li]->loads[min_i]; // TODO: goto load_found?
load_found:;
	const uint32_t limit = (1<<16) - price;
	if (*load >= limit) return true;
	if (__builtin_add_overflow(*load, price, load)) {
		*load = (1<<16) - 1;
		return true;
	} else {
		return false;
	}
}

struct kru_api KRU_API_NAME = {
	.create = kru_create,
	.limited = kru_limited,
};

