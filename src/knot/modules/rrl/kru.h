
#pragma once

#if defined(KRU_IMPL_min32bit)
#define KRU_IMPL_FILE "knot/modules/rrl/kru_min32bit.c"

#else // default
#define KRU_IMPL_min32bit
#define KRU_IMPL_FILE "knot/modules/rrl/kru_min32bit.c"
#endif


#include <stdbool.h>
#include <stdint.h>
// FIXME: review the whole header; for now at least the main APIs should appear

struct kru;
struct kru *kru_init(uint32_t loads_bits);
void kru_destroy(struct kru *kru);
bool kru_limited(struct kru *kru, void *buf, size_t buf_len, uint32_t time_now, uint32_t price);
