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

#include "knot/modules/rrl/functions.h"
#include "contrib/musl/inet_ntop.h"
#include "contrib/openbsd/strlcat.h"
#include "contrib/sockaddr.h"
#include "contrib/time.h"
#include "libdnssec/error.h"
#include "libdnssec/random.h"

/* CIDR block prefix lengths for v4/v6 */
// Hardcoded also in unit tests.

#define RRL_V4_PREFIXES  (uint8_t[])  {  24,  28,  32}
#define RRL_V4_RATE_MULT (uint16_t[]) {  16,   4,   1}

#define RRL_V6_PREFIXES  (uint8_t[])  {  32,  56,  64, 128}
#define RRL_V6_RATE_MULT (uint16_t[]) { 512,  16,   4,   1}

#define RRL_V4_PREFIXES_CNT (sizeof(RRL_V4_PREFIXES) / sizeof(*RRL_V4_PREFIXES))
#define RRL_V6_PREFIXES_CNT (sizeof(RRL_V6_PREFIXES) / sizeof(*RRL_V6_PREFIXES))
#define RRL_MAX_PREFIXES_CNT ((RRL_V4_PREFIXES_CNT > RRL_V6_PREFIXES_CNT) ? RRL_V4_PREFIXES_CNT : RRL_V6_PREFIXES_CNT)

struct rrl_table {
	uint16_t v4_prices[RRL_V4_PREFIXES_CNT];
	uint16_t v6_prices[RRL_V6_PREFIXES_CNT];
	uint8_t kru[] ALIGNED(64);
};

/*
static void subnet_tostr(char *dst, size_t maxlen, const struct sockaddr_storage *ss) // TODO remove or adapt
{
	const void *addr;
	const char *suffix;

	if (ss->ss_family == AF_INET6) {
		addr = &((struct sockaddr_in6 *)ss)->sin6_addr;
		suffix = "/56";
	} else {
		addr = &((struct sockaddr_in *)ss)->sin_addr;
		suffix = "/24";
	}

	if (knot_inet_ntop(ss->ss_family, addr, dst, maxlen) != NULL) {
		strlcat(dst, suffix, maxlen);
	} else {
		dst[0] = '\0';
	}
}

static void rrl_log_state(knotd_mod_t *mod, const struct sockaddr_storage *ss,
                          uint16_t flags, uint8_t cls, const knot_dname_t *qname) // TODO remove or adapt, not used
{
	if (mod == NULL || ss == NULL) {
		return;
	}

	char addr_str[SOCKADDR_STRLEN];
	subnet_tostr(addr_str, sizeof(addr_str), ss);

	const char *what = "leaves";
	if (flags & RRL_BF_ELIMIT) {
		what = "enters";
	}

	knot_dname_txt_storage_t buf;
	char *qname_str = knot_dname_to_str(buf, qname, sizeof(buf));
	if (qname_str == NULL) {
		qname_str = "?";
	}

	knotd_mod_log(mod, LOG_NOTICE, "address/subnet %s, class %s, qname %s, %s limiting",
	              addr_str, rrl_clsstr(cls), qname_str, what);
}
*/

rrl_table_t *rrl_create(size_t size, uint32_t rate)
{
	size--;
	size_t capacity_log = 1;
	while (size >>= 1) capacity_log++;

	rrl_table_t *rrl;
	if (posix_memalign((void **)&rrl, 64, offsetof(struct rrl_table, kru) + KRU.get_size(capacity_log)) != 0) {
		return NULL;
	}

	if (!KRU.initialize((struct kru *)rrl->kru, capacity_log)) {
		free(rrl);
		return NULL;
	}

	const uint16_t base_price = 1404301 / rate;
		// max price decay per tick:  1404.301
		// rate limit per tick:       rate / 1000

	for (size_t i = 0; i < RRL_V4_PREFIXES_CNT; i++) {
		rrl->v4_prices[i] = base_price / RRL_V4_RATE_MULT[i];
	}

	for (size_t i = 0; i < RRL_V6_PREFIXES_CNT; i++) {
		rrl->v6_prices[i] = base_price / RRL_V6_RATE_MULT[i];
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
	if (remote->ss_family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)remote;
		memcpy(key, &ipv6->sin6_addr, 16);

		return KRU.limited_multi_prefix_or((struct kru *)rrl->kru, now, 1, key, RRL_V6_PREFIXES, rrl->v6_prices, RRL_V6_PREFIXES_CNT)
			? KNOT_ELIMIT : KNOT_EOK;

	} else {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)remote;
		memcpy(key, &ipv4->sin_addr, 4);

		return KRU.limited_multi_prefix_or((struct kru *)rrl->kru, now, 0, key, RRL_V4_PREFIXES, rrl->v4_prices, RRL_V4_PREFIXES_CNT)
			? KNOT_ELIMIT : KNOT_EOK;
	}
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
