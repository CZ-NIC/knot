/** @file

KRU is a variant of Count sketch with aging

The point is to answer point-queries that estimate if the item has been heavily used recently.
To give more weight to recent usage, we use aging via exponential decay (simple to compute).
That has applications for garbage collection of cache and various limiting scenario
(excessive rate, traffic, CPU, maybe RAM).


### Choosing parameters

For limiting, `time` is probably in milliseconds from kr_now().
In case of DECAY_32, we expect around 0.4k per tick which gives 0.4M per second.
Say, if we want p QPS, we add `0.4M / p` for each query.

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

//#pragma GCC optimize("O3")

// new-ish x86 (2015+ usually, Atom 2021+)
// FIXME: also provide at least some slower *generic* KRU implementation
#ifdef __clang__
	#pragma clang attribute push (__attribute__((target("arch=x86-64-v3,aes"))), \
							apply_to = function)
#else
	#pragma GCC target("arch=x86-64-v3,aes")
#endif


#include <stdlib.h>
#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <immintrin.h>
#include <x86intrin.h>

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
	_Atomic uint32_t time;
	#define LOADS_LEN 30
	int16_t loads[LOADS_LEN];
} ALIGNED_CPU_CACHE;
static_assert(64 == sizeof(struct load_cl), "bad size of struct load_cl");

/// Parametrization for speed of decay.
struct decay_config {
	/// Length of one tick is 2 ^ ticklen_log.
	uint32_t ticklen_log;
	/// Exponential decay with half-life of (2 ^ half_life_log) ticks.
	uint32_t half_life_log;
	/// Precomputed scaling constants.  Indexed by tick count [1 .. 2^half_life_log - 1],
	///   contains the corresponding factor of decay (<1, scaled to 2^16 and rounded).
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
		int32_t m = (int32_t)l->loads[i] * decay->scales[decay_frac];
		int32_t l1 = (m >> 16) + /*rounding*/((m >> 15)&1);
		// finally the non-fractional part of the bit shift
		l->loads[i] = l1 >> load_nonfrac_shift;
	}
}
/// Half-life of 32 ticks, consequently forgetting in about 330 ticks due to imprecision.
/// Experiment: if going by a single tick, after 330 steps fixed-point at +-23,
///  but accuracy at the beginning of that (first 32 ticks) is very good,
///  getting from max 2^15 - 1 to 2^14 + 2 or -2^15 to -2^14 - 3.
///  Max. decay per tick is 702 but for limit computation it will be more like 350.
const struct decay_config DECAY_32 = {
	.ticklen_log = 0,
	.half_life_log = 5,
	.scales = { // ghci> map (\i -> round(2^16 * 0.5 ** (i/32))) [1..31]
		0,64132,62757,61413,60097,58809,57549,56316,55109,53928,52773,
		51642,50535,49452,48393,47356,46341,45348,44376,43425,42495,41584,
		40693,39821,38968,38133,37316,36516,35734,34968,34219,33486
	}
};

#define USE_AES 1

struct kru {
#if USE_AES
	/// 4-8 rounds should be an OK choice, most likely.  TODO: confirm
	#define AES_ROUNDS 4
	/// Hashing secret.  Random but shared by all users of the table.
	/// Let's not make it too large, so that header fits into 64 Bytes.
	char hash_key[48] ALIGNED(32);
#else
	SIPHASH_KEY hash_key;
#endif

	/// Length of `loads_cls`, stored as binary logarithm.
	uint32_t loads_bits;

	#define TABLE_COUNT 2
	/// These are read-write.  Each struct has exactly one cache line.
	struct load_cl load_cls[][TABLE_COUNT];
};

struct kru *kru_init(uint32_t loads_bits)
{
	if (TABLE_COUNT * loads_bits > 64) { // for hash = hashes[0] below
		assert(false);
		return NULL;
	}

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
// LATER(optim.): perhaps loads and stores could be done substantially better.
{
	// Obtain hashes of *buf.
	uint64_t hashes[2] ALIGNED(16);
#if USE_AES
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
#else
	uint64_t siphash = SipHash24(&kru->hash_key, buf, buf_len);
	hashes[0] = hashes[1] = siphash;
	// hashes[1] = siphash >> (hash >> 62);
#endif

	// Choose two struct load_cl, i.e. two cache-lines to operate on,
	// update their notion of time, and copy all their loads to l_c.
	struct load_cl *l[TABLE_COUNT];
	char l_c[TABLE_COUNT * sizeof(struct load_cl)] ALIGNED(32);
	const uint32_t loads_mask = (1 << kru->loads_bits) - 1;
	uint64_t hash = hashes[0];
	for (int li = 0; li < TABLE_COUNT; ++li) {
		l[li] = &kru->load_cls[hash & loads_mask][li];
		hash >>= kru->loads_bits;
		update_time(l[li], time_now, &DECAY_32);
		memcpy(l_c + li * sizeof(l[li]->loads), l[li]->loads, sizeof(l[li]->loads));
	}
	static_assert(sizeof(l[0]->loads) == 64-4, "");
	// zero the rest of l_c
	memset(l_c + TABLE_COUNT * sizeof(l[0]->loads), 0,
		sizeof(l_c) - TABLE_COUNT * sizeof(l[0]->loads));
	static_assert(sizeof(l_c) - TABLE_COUNT * sizeof(l[0]->loads)  ==  TABLE_COUNT * 4, "");

	// Now the hottest loop: determine in how many places in l_c we've shot over limit.
	// We use x86 SIMD instructions, up to AVX2 level (-march=x86-64-v3)
	// Reference: https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html
	__m256i * const l_v = (__m256i *)l_c;
	const __m256i limit_neg_v = _mm256_set1_epi16(-(1<<14)); // TODO: confirm the limit?
	const __m256i price_v = _mm256_set1_epi16(price);
	const int VEC_COUNT = TABLE_COUNT * sizeof(struct load_cl) / sizeof(__m256i); // == 4
	// Prepare a 256-bit mask that chooses one bit per (16-bit) item.
	const __m256i hash_mask = _mm256_set_epi16(1<<0, 1<<1, 1<<2, 1<<3, 1<<4, 1<<5, 1<<6,
				1<<7, 1<<8, 1<<9, 1<<10, 1<<11, 1<<12, 1<<13, 1<<14,
				/*an inconsequential sign change here*/(short)(1<<15));
	const __m256i ones_v = _mm256_set1_epi16(1);

	int ol_count = 0; // counter for over-limit positions
	hash = hashes[1];
	static_assert(sizeof(hash) * 8 >= TABLE_COUNT * 32, "");
	static_assert(VEC_COUNT % 2 == 0, "");
	for (int i = 0; i < VEC_COUNT; i += 2) {
		// mask_itemsN = 16 bits of negated hash, expanded to 16-bit blocks of 1s or 0s
		__m256i mask_items1 = _mm256_cmpeq_epi16(
			_mm256_and_si256(_mm256_set1_epi16(hash), hash_mask),
			_mm256_setzero_si256()
		);
		__m256i mask_items2 = _mm256_cmpeq_epi16(
			_mm256_and_si256(_mm256_set1_epi16(hash >> 16), hash_mask),
			_mm256_setzero_si256()
		);
		hash >>= 32;
		// In int16_t these are -1 and 0, which is not convenient,
		// as _mm256_sign_epi16() works on ternary logic (negative, zero, positive)
		// Let's do *2-1, converting to +1 and -1 (for hash's 0 and 1).
		__m256i signs1 = _mm256_sub_epi16(_mm256_slli_epi16(mask_items1, 1), ones_v);
		__m256i signs2 = _mm256_sub_epi16(_mm256_slli_epi16(mask_items2, 1), ones_v);
		// Therefore _mm256_sign_epi16(X, signsN) will negate items that had 1-bit in hash

		__m256i loads1 = _mm256_load_si256(&l_v[i]);
		__m256i loads2 = _mm256_load_si256(&l_v[i+1]);
		// Now we compute ol_bmp = bitmap of over-limit positions (shuffled a bit):
		//   we negate load items based on hash, compare to limit,
		//   and extract into uint32_t.  The extraction comes in bit-pairs unfortunately.
		const uint32_t mask_even = 0xcccccccc;
		uint32_t olb1 = _mm256_movemask_epi8(
			_mm256_cmpgt_epi16(limit_neg_v, _mm256_sign_epi16(loads1, signs1))
		);
		uint32_t olb2 = _mm256_movemask_epi8(
			_mm256_cmpgt_epi16(limit_neg_v, _mm256_sign_epi16(loads2, signs2))
		);
		uint32_t ol_bmp = (olb1 & mask_even) | ((olb2 & mask_even) >> 1);

		// Accumulate the over-limit count.
		// With current contants we compare on 30, so we might exit early.
		ol_count += _popcnt32(ol_bmp);
		if (ol_count >= TABLE_COUNT * LOADS_LEN / 2)
			return true;

		// We add prices to the load items and store them.
		// It's subtraction due to the way that our signsN turned out.
		// That's independent of the over-limit computations just above.
		_mm256_store_si256(&l_v[i],
			_mm256_subs_epi16(loads1, _mm256_sign_epi16(price_v, signs1)));
		_mm256_store_si256(&l_v[i+1],
			_mm256_subs_epi16(loads2, _mm256_sign_epi16(price_v, signs2)));
	}

	// Not limited, so copy the updated loads back.
	for (int li = 0; li < TABLE_COUNT; ++li)
		memcpy(l[li]->loads, l_c + li * sizeof(l[li]->loads), sizeof(l[li]->loads));
	return false;
}

#ifdef __clang__
	#pragma clang attribute pop
#endif
