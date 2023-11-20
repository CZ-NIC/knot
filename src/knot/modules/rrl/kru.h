
#include <stdint.h>
// FIXME: review the whole header; for now at least the main APIs should appear

struct kru;
bool kru_limited(struct kru *kru, uint64_t hash, uint32_t time_now, uint32_t price);
