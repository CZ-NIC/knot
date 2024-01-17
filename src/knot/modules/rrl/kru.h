
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

struct kru;

struct kru_query {
	uint8_t key[16] ALIGNED(16);
	uint16_t price;
};

/// Usage: KRU.limited(...)
struct kru_api {
	/// Create a new KRU structure that can truck up to 1 << capacity_log
	/// limited keys (and basically arbitrary amount of non-limited keys).
	/// Use simply free() to destroy this structure.
	struct kru * (*create)(int capacity_log);

	// TODO: probably allow to split creation as follows.
	//size_t (*get_size)(int capacity_log);
	//void (*initialize)(struct kru *kru);

	/// Determine if a key should get limited (and update the KRU).
	/// key needs to be aligned to a multiple of 16 bytes.
	bool (*limited)(struct kru *kru, uint32_t time_now, struct kru_query *query);

	bool (*limited_multi_or)(struct kru *kru, uint32_t time_now, struct kru_query *queries, size_t queries_cnt);
	bool (*limited_multi_or_nobreak)(struct kru *kru, uint32_t time_now, struct kru_query *queries, size_t queries_cnt);
};
// The functions are stored this way to make it easier to switch
// implementation based on detected CPU.
extern struct kru_api KRU;
extern const struct kru_api KRU_GENERIC, KRU_AVX2; // for tests only



