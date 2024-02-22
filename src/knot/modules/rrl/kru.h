
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
// FIXME: review the whole header; for now at least the main APIs should appear

#if __GNUC__ >= 4 || __clang_major__ >= 4
	#define ALIGNED_CPU_CACHE __attribute__((aligned(64)))
	#define ALIGNED(_bytes)   __attribute__((aligned(_bytes)))
#else
	#define ALIGNED_CPU_CACHE
	#define ALIGNED(_bytes)
#endif


// An unsigned integral type used for prices, blocking occurs when sum of prices overflows.
// Greater than 16-bit type enables randomized fractional incrementing as the internal counters are still 16-bit.
typedef uint32_t kru_price_t;

#define KRU_PRICE_BITS (8 * sizeof(kru_price_t))
#define KRU_MAX_DECAY (1404ll << (KRU_PRICE_BITS - 16))
#define KRU_LIMIT     (((kru_price_t)-1ll) - (1ll << (KRU_PRICE_BITS - 16)) + 2)

struct kru;

/// Usage: KRU.limited(...)
struct kru_api {
	/// Initialize a new KRU structure that can track roughly 2^capacity_log limited keys.
	///
	/// The kru parameter should point to a zeroed preallocated memory
	/// of size returned by get_size aligned to 64-bytes;
	/// deallocate the memory to destroy KRU.
	/// RAM: the current parametrization will use roughly 8 (or 16 for 32-bit version) bytes * 2^capacity_log.
	///
	/// The number of non-limited keys is basically arbitrary,
	/// but the total sum of prices per tick (for queries returning false)
	/// should not get over roughly 2^(capacity_log + 15).  // TODO adjust for 32 bits?
	/// Note that the _multi variants increase these totals
	/// by tracking multiple keys in a single query.
	///
	/// Returns false if kru is NULL or other failure occurs.
	bool (*initialize)(struct kru *kru, int capacity_log);

	/// Calculate size of the KRU structure.
	size_t (*get_size)(int capacity_log);

	/// Determine if a key should get limited (and update the KRU).
	/// key needs to be aligned to a multiple of 16 bytes.
	bool (*limited)(struct kru *kru, uint32_t time_now, uint8_t key[static const 16], kru_price_t price);

	/// Multiple queries. Returns OR of answers. Updates KRU only if no query is blocked (and possibly on race).
	bool (*limited_multi_or)(struct kru *kru, uint32_t time_now, uint8_t **keys, kru_price_t *prices, size_t queries_cnt);

	/// Same as previous but without short-circuit evaluation; for time measurement purposes.
	bool (*limited_multi_or_nobreak)(struct kru *kru, uint32_t time_now, uint8_t ** keys, kru_price_t *prices, size_t queries_cnt);

	/// Multiple queries based on different prefixes of a single key. Returns OR of answers. Updates KRU only if no query is blocked.
	/// The key of i-th query consists of prefixes[i] bits of key, prefixes[i], and namespace.
	bool (*limited_multi_prefix_or)(struct kru *kru, uint32_t time_now,
			uint8_t namespace, uint8_t key[static 16], uint8_t *prefixes, kru_price_t *prices, size_t queries_cnt);
};
// The functions are stored this way to make it easier to switch
// implementation based on detected CPU.
extern struct kru_api KRU;
extern const struct kru_api KRU_GENERIC, KRU_AVX2; // for tests only
