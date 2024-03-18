/*  Copyright (C) 2023 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <time.h>
#include <stdatomic.h>

#include "knot/modules/rrl/functions.h"
#include "contrib/musl/inet_ntop.h"
#include "contrib/openbsd/strlcat.h"
#include "contrib/sockaddr.h"
#include "contrib/time.h"
#include "libdnssec/error.h"
#include "libdnssec/random.h"

/* CIDR block prefix lengths for v4/v6 */
// Hardcoded also in unit tests.

#define RRL_V4_PREFIXES  (uint8_t[])       {  18,  20, 24, 32 }
#define RRL_V4_RATE_MULT (kru_price_t[])   { 768, 256, 32,  1 }

#define RRL_V6_PREFIXES  (uint8_t[])       { 32, 48, 56, 64, 128 }
#define RRL_V6_RATE_MULT (kru_price_t[])   { 64,  4,  3,  2,   1 }

#define RRL_V4_PREFIXES_CNT (sizeof(RRL_V4_PREFIXES) / sizeof(*RRL_V4_PREFIXES))
#define RRL_V6_PREFIXES_CNT (sizeof(RRL_V6_PREFIXES) / sizeof(*RRL_V6_PREFIXES))
#define RRL_MAX_PREFIXES_CNT ((RRL_V4_PREFIXES_CNT > RRL_V6_PREFIXES_CNT) ? RRL_V4_PREFIXES_CNT : RRL_V6_PREFIXES_CNT)

struct rrl_table {
	kru_price_t v4_prices[RRL_V4_PREFIXES_CNT];
	kru_price_t v6_prices[RRL_V6_PREFIXES_CNT];
	uint32_t log_period;
	_Atomic uint32_t log_time;
	uint8_t kru[] ALIGNED(64);
};

static void addr_tostr(char *dst, size_t maxlen, const struct sockaddr_storage *ss)
{
	const void *addr;

	if (ss->ss_family == AF_INET6) {
		addr = &((struct sockaddr_in6 *)ss)->sin6_addr;
	} else {
		addr = &((struct sockaddr_in *)ss)->sin_addr;
	}

	if (knot_inet_ntop(ss->ss_family, addr, dst, maxlen) == NULL) {
		dst[0] = '\0';
	}
}

static void rrl_log_limited(knotd_mod_t *mod, const struct sockaddr_storage *ss, const uint8_t prefix)
{
	if (mod == NULL || ss == NULL) {
		return;
	}

	char addr_str[SOCKADDR_STRLEN];
	addr_tostr(addr_str, sizeof(addr_str), ss);

	knotd_mod_log(mod, LOG_NOTICE, "address %s limited on /%d", addr_str, prefix);
}

rrl_table_t *rrl_create(size_t size, uint32_t instant_limit, uint32_t rate_limit, uint32_t log_period)
{
	size--;
	size_t capacity_log = 1;
	while (size >>= 1) capacity_log++;

	rrl_table_t *rrl;
	if (posix_memalign((void **)&rrl, 64, offsetof(struct rrl_table, kru) + KRU.get_size(capacity_log)) != 0) {
		return NULL;
	}

	const kru_price_t base_price = KRU_LIMIT / instant_limit;
	const kru_price_t max_decay = rate_limit > 1000ll * instant_limit ? base_price :
		(uint64_t) base_price * rate_limit / 1000;

	if (!KRU.initialize((struct kru *)rrl->kru, capacity_log, max_decay)) {
		free(rrl);
		return NULL;
	}

	for (size_t i = 0; i < RRL_V4_PREFIXES_CNT; i++) {
		rrl->v4_prices[i] = base_price / RRL_V4_RATE_MULT[i];
	}

	for (size_t i = 0; i < RRL_V6_PREFIXES_CNT; i++) {
		rrl->v6_prices[i] = base_price / RRL_V6_RATE_MULT[i];
	}

	rrl->log_period = log_period;

	{
		struct timespec now_ts = {0};
		clock_gettime(CLOCK_MONOTONIC_COARSE, &now_ts);
		uint32_t now = now_ts.tv_sec * 1000 + now_ts.tv_nsec / 1000000;
		rrl->log_time = now - log_period;
	}

	return rrl;
}

int rrl_query(rrl_table_t *rrl, const struct sockaddr_storage *remote,
              rrl_req_t *req, const knot_dname_t *zone, knotd_mod_t *mod)
{
	if (!rrl || !req || !remote) {
		return KNOT_EINVAL;
	}

	struct timespec now_ts = {0};
	clock_gettime(CLOCK_MONOTONIC_COARSE, &now_ts);
	uint32_t now = now_ts.tv_sec * 1000 + now_ts.tv_nsec / 1000000;

	uint8_t key[16] ALIGNED(16) = {0, };
	uint8_t limited_prefix;
	if (remote->ss_family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)remote;
		memcpy(key, &ipv6->sin6_addr, 16);

		limited_prefix = KRU.limited_multi_prefix_or((struct kru *)rrl->kru, now,
				1, key, RRL_V6_PREFIXES, rrl->v6_prices, RRL_V6_PREFIXES_CNT);
	} else {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)remote;
		memcpy(key, &ipv4->sin_addr, 4);

		limited_prefix = KRU.limited_multi_prefix_or((struct kru *)rrl->kru, now,
				0, key, RRL_V4_PREFIXES, rrl->v4_prices, RRL_V4_PREFIXES_CNT);
	}

	uint32_t log_time_orig = atomic_load_explicit(&rrl->log_time, memory_order_relaxed);
	if (rrl->log_period && limited_prefix && (now - log_time_orig + 1024 >= rrl->log_period + 1024)) {
		do {
			if (atomic_compare_exchange_weak_explicit(&rrl->log_time, &log_time_orig, now, memory_order_relaxed, memory_order_relaxed)) {
				rrl_log_limited(mod, remote, limited_prefix);
				break;
			}
		} while (now - log_time_orig + 1024 >= rrl->log_period + 1024);
	}

	return limited_prefix ? KNOT_ELIMIT : KNOT_EOK;
}

bool rrl_slip_roll(int n_slip)
{
	switch (n_slip) {
	case 0:
		return false;
	case 1:
		return true;
	default:
		return (dnssec_random_uint16_t() % n_slip == 0);
	}
}

void rrl_destroy(rrl_table_t *rrl)
{
	free(rrl);
}
