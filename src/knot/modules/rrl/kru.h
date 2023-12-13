
#pragma once

#if defined(KRU_IMPL_min32bit)
#define KRU_IMPL_FILE "knot/modules/rrl/kru_min32bit.c"

#elif defined(KRU_IMPL_median32bit)
#define KRU_IMPL_FILE "knot/modules/rrl/kru_median32bit.c"

#elif defined(KRU_IMPL_median16bit_simd)
#define KRU_IMPL_FILE "knot/modules/rrl/kru_median16bit_simd.c"

#elif defined(KRU_IMPL_ss16bit)
#define KRU_IMPL_FILE "knot/modules/rrl/kru_ss16bit.c"

#elif defined(KRU_IMPL_ss16bit_simd)
#define USE_AES 1
#define USE_AVX2 1
#define USE_SSE41 1
#define KRU_IMPL_FILE "knot/modules/rrl/kru_ss16bit.c"

#elif defined(KRU_IMPL_ss32bit)
#define KRU_IMPL_FILE "knot/modules/rrl/kru_ss32bit.c"

#else // default
#warning Using min32bit as KRU implementation.
#define KRU_IMPL_min32bit
#define KRU_IMPL_FILE "knot/modules/rrl/kru_min32bit.c"
#endif


#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
// FIXME: review the whole header; for now at least the main APIs should appear

struct kru;
struct kru *kru_init(uint32_t loads_bits);
void kru_destroy(struct kru *kru);
bool kru_limited(struct kru *kru, void *buf, size_t buf_len, uint32_t time_now, uint32_t price);
