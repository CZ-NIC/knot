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

#if __GNUC__ >= 4
	#define ALIGNED_CPU_CACHE __attribute__((aligned(64)))
	#define ALIGNED(_bytes)   __attribute__((aligned(_bytes)))
#else
	#define ALIGNED_CPU_CACHE
	#define ALIGNED(_bytes)
#endif

// new-ish x86 (2015+ usually, Atom 2021+)
// TODO: improve this?
// SSE4.2 is in x86-64-v2, i.e. basically any reasonable x86 today
// AES is not in these levels but also in all reasonable x86
#ifdef __clang__
	#pragma clang attribute push (__attribute__((target("arch=x86-64-v3,aes"))), \
							apply_to = function)
#else
	#pragma GCC target("arch=x86-64-v3,aes")
#endif

/// Block of loads sharing the same time, so that we're more space-efficient.
/// It's exactly a single cache line.
struct load_cl {
	_Atomic uint32_t time;
	#define LOADS_LEN 15
	uint16_t ids[LOADS_LEN];
	uint16_t loads[LOADS_LEN];
} ALIGNED_CPU_CACHE;
static_assert(64 == sizeof(struct load_cl), "bad size of struct load_cl");

#define KRU_DECAY_BITS 16
#include "knot/modules/rrl/kru-decay.c"

#if USE_AES
	#define HASHES_CNT 2
#else
	#define HASHES_CNT 1
#endif
#include "knot/modules/rrl/kru-hash.c"

#if USE_AVX2 || USE_SSE41 || USE_AES
	#include <immintrin.h>
	#include <x86intrin.h>
#endif

struct kru {
#if USE_AES
	/// 4-8 rounds should be an OK choice, most likely.  TODO: confirm
	#define AES_ROUNDS 4
	/// Hashing secret.  Random but shared by all users of the table.
	/// Let's not make it too large, so that header fits into 64 Bytes.
	char hash_key[48] ALIGNED(32);
#else
	/// Hashing secret.  Random but shared by all users of the table.
	HASH_KEY_T hash_key;
#endif

	/// Length of `loads_cls`, stored as binary logarithm.
	uint32_t loads_bits;

	#define TABLE_COUNT 2
	/// These are read-write.  Each struct has exactly one cache line.
	struct load_cl load_cls[][TABLE_COUNT];
};

struct kru *kru_init(uint32_t loads_bits)
{
	if (HASH_BITS < TABLE_COUNT * loads_bits + 16/*ids are 16-bit*/) {
		assert(false);
		return NULL;
	}

	struct kru *kru;
	size_t size = offsetof(struct kru, load_cls)
		    + sizeof(struct load_cl) * TABLE_COUNT * (1 << loads_bits);
	// ensure good alignment
	if (posix_memalign((void **)&kru, 64, size) != 0)
		return NULL;

	kru->loads_bits = loads_bits;

	if (HASH_INIT(kru->hash_key)) {
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
	// Obtain hashes of *buf.
#if !USE_AES
	HASH_FROM_BUF(kru->hash_key, buf, buf_len);
#else
	int hash_remaining_bits = HASH_BITS;
	uint64_t hashes[2] ALIGNED(16);
	{
		__m128i h; /// hashing state
		// Load the *buf into `h`.  Zero-padding gets complicated.
		char buf_pad[sizeof(h)] ALIGNED(16);
		if (buf_len > sizeof(h))
			abort(); // TODO: we probably don't need more than 128 bits, but...
		memcpy(buf_pad, buf, buf_len);
		memset(buf_pad + buf_len, 0, sizeof(buf_pad) - buf_len);
		h = _mm_load_si128((void*)buf_pad);
		// Now do the the hashing itself.
		__m128i *key = (void*)kru->hash_key;
		for (int i = 0; i < AES_ROUNDS; ++i) {
			int key_id = i % (sizeof(kru->hash_key) / sizeof(__m128i));
			h = _mm_aesenc_si128(h, _mm_load_si128(&key[key_id]));
		}
		memcpy(hashes, &h, sizeof(h));
	}
	//FIXME: gcc 12 is apparently mixing code of hashing with update_time() ?!
#endif

	// Choose the cache-lines to operate on
	struct load_cl *l[TABLE_COUNT];
	//const uint32_t loads_mask = (1 << kru->loads_bits) - 1;
	// Fetch the two cache-lines in parallel before we really touch them.
	for (int li = 0; li < TABLE_COUNT; ++li) {
		l[li] = &kru->load_cls[HASH_GET_BITS(kru->loads_bits)][li];
		__builtin_prefetch(l[li], 0); // hope for read-only access
	}
	for (int li = 0; li < TABLE_COUNT; ++li)
		update_time(l[li], time_now, &DECAY_32);

	uint16_t id = HASH_GET_BITS(16);

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

#ifdef __clang__
	#pragma clang attribute pop
#endif
