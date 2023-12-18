
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
// FIXME: review the whole header; for now at least the main APIs should appear

struct kru;

/// Usage: KRU.limited(...)
struct kru_api {
	/// Create a new KRU structure that can track roughly 2^capacity_log limited keys.
	///
	/// Use simply free() to destroy this structure.
	/// RAM: the current parametrization will use 8 bytes * 2^capacity_log.
	///
	/// The number of non-limited keys is basically arbitrary,
	/// but the total sum of prices per tick (for queries returning false)
	/// should not get over roughly 2^(capacity_log + 15).
	/// Note that the _multi variants increase these totals
	/// by tracking multiple keys in a single query.
	struct kru * (*create)(int capacity_log);

	// TODO: probably allow to split creation as follows.
	//size_t (*get_size)(int capacity_log);
	//void (*initialize)(struct kru *kru);

	/// Determine if a key should get limited (and update the KRU).
	/// key needs to be aligned to a multiple of 16 bytes.
	bool (*limited)(struct kru *kru, char key[static const 16],
			uint32_t time_now, uint16_t price);
};
// The functions are stored this way to make it easier to switch
// implementation based on detected CPU.
extern struct kru_api KRU;


#if __GNUC__ >= 4 || __clang_major__ >= 4
	#define ALIGNED_CPU_CACHE __attribute__((aligned(64)))
	#define ALIGNED(_bytes)   __attribute__((aligned(_bytes)))
#else
	#define ALIGNED_CPU_CACHE
	#define ALIGNED(_bytes)
#endif

