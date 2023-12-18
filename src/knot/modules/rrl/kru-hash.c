
#include "contrib/openbsd/siphash.h"
#include "libdnssec/error.h"
#include "libdnssec/random.h"


#define HASH_BITS (HASHES_CNT * 64)
typedef SIPHASH_KEY HASH_KEY_T[HASHES_CNT];

#define HASH_INIT(key) \
	(dnssec_random_buffer((uint8_t *)&key, sizeof(key)) != DNSSEC_EOK)

#define HASH_FROM_BUF(key, buf, buf_len) \
	int hash_remaining_bits = HASH_BITS; \
	uint64_t hashes[HASHES_CNT]; \
	for (size_t hash_i = 0; hash_i < HASHES_CNT; hash_i++) { \
		hashes[hash_i] = SipHash24(&key[hash_i], buf, buf_len); \
	}

#define HASH_GET_BITS(cnt) hash_get_bits(hashes, cnt, &hash_remaining_bits)
inline uint64_t hash_get_bits(uint64_t *hashes, size_t cnt, int *hash_remaining_bits) {
	assert(cnt <= 64);
	assert((*hash_remaining_bits -= cnt) >= 0);
	uint64_t ret = hashes[0] & ((1ull<<cnt) - 1);
	hashes[0] >>= cnt;
	for (size_t hash_i = 0; hash_i < HASHES_CNT - 1; hash_i++) {
		hashes[hash_i] += hashes[hash_i + 1] << (64-cnt);
		hashes[hash_i + 1] >>= cnt;
	}
	return ret;
}
