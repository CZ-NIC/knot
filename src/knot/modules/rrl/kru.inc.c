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
	enum {
		SIPHASH_RC = 1,
		SIPHASH_RF = 3,
	};
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

struct query_ctx {
	struct load_cl *l[TABLE_COUNT];
	uint32_t time_now;
	uint16_t price;
	uint16_t id;
	uint16_t *load;
};

/// Phase 1/3 of a query -- hash, prefetch, ctx init. Based on one 16-byte key.
static inline void kru_limited_prefetch(struct kru *kru, uint32_t time_now, uint8_t key[static 16], uint16_t price, struct query_ctx *ctx)
{
	// Obtain hash of *buf.
	hash_t hash;
#if !USE_AES
	hash = SipHash(&kru->hash_key, SIPHASH_RC, SIPHASH_RF, key, 16);
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
#endif

	// Choose the cache-lines to operate on
	const uint32_t loads_mask = (1 << kru->loads_bits) - 1;
	// Fetch the two cache-lines in parallel before we really touch them.
	for (int li = 0; li < TABLE_COUNT; ++li) {
		struct load_cl * const l = &kru->load_cls[hash & loads_mask][li];
		__builtin_prefetch(l, 0); // hope for read-only access
		hash >>= kru->loads_bits;
		ctx->l[li] = l;
	}

	ctx->time_now = time_now;
	ctx->price = price;
	ctx->id = hash;
}


/// Phase 1/3 of a query -- hash, prefetch, ctx init. Based on a bit prefix of one 16-byte key.
static inline void kru_limited_prefetch_prefix(struct kru *kru, uint32_t time_now, uint8_t namespace, uint8_t key[static 16], uint8_t prefix, uint16_t price, struct query_ctx *ctx)
{
	// Obtain hash of *buf.
	hash_t hash;

#if !USE_AES
	{
		const int rc = SIPHASH_RC, rf = SIPHASH_RF;

		// Hash prefix of key, prefix size, and namespace together.
		SIPHASH_CTX hctx;
		SipHash_Init(&hctx, &kru->hash_key);
		SipHash_Update(&hctx, rc, rf, &namespace, sizeof(namespace));
		SipHash_Update(&hctx, rc, rf, &prefix, sizeof(prefix));
		SipHash_Update(&hctx, rc, rf, key, prefix / 8);
		if (prefix % 8) {
			const uint8_t masked_byte = key[prefix / 8] & (0xFF00 >> (prefix % 8));
			SipHash_Update(&hctx, rc, rf, &masked_byte, 1);
		}
		hash = SipHash_End(&hctx, rc, rf);
	}
#else
	{

		__m128i h; /// hashing state
		h = _mm_load_si128((__m128i *)key);

		{ // Keep only the prefix.
			const uint8_t p = prefix;

			// Prefix mask (1...0) -> little endian byte array (0x00 ... 0x00 0xFF ... 0xFF).
			__m128i mask = _mm_set_epi64x(
					(p < 64 ? (p == 0 ? 0 : -1ll << (64 - p)) : -1ll),  // higher 64 bits (1...) -> second half of byte array (... 0xFF)
					(p <= 64 ? 0 : -1ll << (128 - p)));                 // lower  64 bits (...0) ->  first half of byte array (0x00 ...)

			// Swap mask endianness (0x11 ... 0x11 0x00 ... 0x00).
			mask = _mm_shuffle_epi8(mask,
					_mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15));

			// Apply mask.
			h = _mm_and_si128(h, mask);
		}

		// Now do the the hashing itself.
		__m128i *aes_key = (void*)kru->hash_key;
		{
			// Mix namespace and prefix size into the first aes key.
			__m128i aes_key1 = _mm_insert_epi16(_mm_load_si128(aes_key), (namespace << 8) | prefix, 0);
			h = _mm_aesenc_si128(h, aes_key1);
		}
		for (int j = 1; j < AES_ROUNDS; ++j) {
			int key_id = j % (sizeof(kru->hash_key) / sizeof(__m128i));
			h = _mm_aesenc_si128(h, _mm_load_si128(&aes_key[key_id]));
		}
		memcpy(&hash, &h, sizeof(hash));
	}
#endif

	// Choose the cache-lines to operate on
	const uint32_t loads_mask = (1 << kru->loads_bits) - 1;
	// Fetch the two cache-lines in parallel before we really touch them.
	for (int li = 0; li < TABLE_COUNT; ++li) {
		struct load_cl * const l = &kru->load_cls[hash & loads_mask][li];
		__builtin_prefetch(l, 0); // hope for read-only access
		hash >>= kru->loads_bits;
		ctx->l[li] = l;
	}

	ctx->time_now = time_now;
	ctx->price = price;
	ctx->id = hash;
}

/// Phase 2/3 of a query -- returns answer with no state modification (except update_time).
static inline bool kru_limited_fetch(struct kru *kru, struct query_ctx *ctx)
{
	for (int li = 0; li < TABLE_COUNT; ++li) {
		update_time(ctx->l[li], ctx->time_now, &DECAY_32);
	}

	const uint16_t id = ctx->id;

	// Find matching element.  Matching 16 bits in addition to loads_bits.
	ctx->load = NULL;
#if !USE_AVX2
	for (int li = 0; li < TABLE_COUNT; ++li)
		for (int i = 0; i < LOADS_LEN; ++i)
			if (ctx->l[li]->ids[i] == id) {
				ctx->load = &ctx->l[li]->loads[i];
				goto load_found;
			}
#else
	const __m256i id_v = _mm256_set1_epi16(id);
	for (int li = 0; li < TABLE_COUNT; ++li) {
		static_assert(LOADS_LEN == 15 && sizeof(ctx->l[li]->ids[0]) == 2, "");
		// unfortunately we can't use aligned load here
		__m256i ids_v = _mm256_loadu_si256((__m256i *)(ctx->l[li]->ids - 1));
		__m256i match_mask = _mm256_cmpeq_epi16(ids_v, id_v);
		if (_mm256_testz_si256(match_mask, match_mask))
			continue; // no match of id
		int index = _bit_scan_reverse(_mm256_movemask_epi8(match_mask)) / 2 - 1;
		// there's a small possibility that we hit equality only on the -1 index
		if (index >= 0) {
			ctx->load = &ctx->l[li]->loads[index];
			goto load_found;
		}
	}
#endif

	return false;

load_found:;
	static_assert(ATOMIC_CHAR16_T_LOCK_FREE == 2, "insufficient atomics");
	const uint16_t price = ctx->price;
	const uint32_t limit = (1<<16) - price;
	return (*ctx->load >= limit);
}

/// Phase 3/3 of a query -- state update, return value overrides previous answer in case of race.
/// Not needed if blocked by fetch phase.
static inline bool kru_limited_update(struct kru *kru, struct query_ctx *ctx)
{
	_Atomic uint16_t *load_at;
	if (!ctx->load) {
		// No match, so find position of the smallest load.
		int min_li = 0;
		int min_i = 0;
#if !USE_SSE41
		for (int li = 0; li < TABLE_COUNT; ++li)
			for (int i = 0; i < LOADS_LEN; ++i)
				if (ctx->l[li]->loads[i] < ctx->l[min_li]->loads[min_i]) {
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
			static_assert(LOADS_LEN == 15 && sizeof(ctx->l[li]->loads[0]) == 2, "");
			__m128i *l_v = (__m128i *)(ctx->l[li]->loads - 1);
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

		ctx->l[min_li]->ids[min_i] = ctx->id;
		load_at = (_Atomic uint16_t *)&ctx->l[min_li]->loads[min_i];
	} else {
		load_at = (_Atomic uint16_t *)ctx->load;
	}

	static_assert(ATOMIC_CHAR16_T_LOCK_FREE == 2, "insufficient atomics");
	const uint16_t price = ctx->price;
	const uint32_t limit = (1<<16) - price;
	uint16_t load_orig = *load_at;
	do {
		if (load_orig >= limit)
			return true;
	} while (!atomic_compare_exchange_weak(load_at, &load_orig, load_orig + price));
	return false;
}

static bool kru_limited_multi_or(struct kru *kru, uint32_t time_now, uint8_t **keys, uint16_t *prices, size_t queries_cnt)
{
	struct query_ctx ctx[queries_cnt];

	for (size_t i = 0; i < queries_cnt; i++) {
		kru_limited_prefetch(kru, time_now, keys[i], prices[i], ctx + i);
	}
	for (size_t i = 0; i < queries_cnt; i++) {
		if (kru_limited_fetch(kru, ctx + i))
			return true;
	}
	bool ret = false;

	for (size_t i = 0; i < queries_cnt; i++) {
		ret |= kru_limited_update(kru, ctx + i);
	}

	return ret;
}

static bool kru_limited_multi_or_nobreak(struct kru *kru, uint32_t time_now, uint8_t **keys, uint16_t *prices, size_t queries_cnt)
{
	struct query_ctx ctx[queries_cnt];
	bool ret = false;

	for (size_t i = 0; i < queries_cnt; i++) {
		kru_limited_prefetch(kru, time_now, keys[i], prices[i], ctx + i);
	}
	for (size_t i = 0; i < queries_cnt; i++) {
		if (kru_limited_fetch(kru, ctx + i))
			ret = true;
	}
	if (ret) return true;

	for (size_t i = 0; i < queries_cnt; i++) {
		if (kru_limited_update(kru, ctx + i))
			ret = true;
	}

	return ret;
}

static bool kru_limited_multi_prefix_or(struct kru *kru, uint32_t time_now, uint8_t namespace, uint8_t key[static 16], uint8_t *prefixes, uint16_t *prices, size_t queries_cnt)
{
	struct query_ctx ctx[queries_cnt];

	for (size_t i = 0; i < queries_cnt; i++) {
		kru_limited_prefetch_prefix(kru, time_now, namespace, key, prefixes[i], prices[i], ctx + i);
	}

	for (size_t i = 0; i < queries_cnt; i++) {
		if (kru_limited_fetch(kru, ctx + i))
			return true;
	}

	bool ret = false;
	for (size_t i = 0; i < queries_cnt; i++) {
		ret |= kru_limited_update(kru, ctx + i);
	}

	return ret;
}

/// Update limiting and return true iff it hit the limit instead.
static bool kru_limited(struct kru *kru, uint32_t time_now, uint8_t key[static 16], uint16_t price)
{
	return kru_limited_multi_or(kru, time_now, &key, &price, 1);
}

#define KRU_API_INITIALIZER { \
	.create = kru_create, \
	.limited = kru_limited, \
	.limited_multi_or = kru_limited_multi_or, \
	.limited_multi_or_nobreak = kru_limited_multi_or_nobreak, \
	.limited_multi_prefix_or = kru_limited_multi_prefix_or, \
}
