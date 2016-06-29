/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tap/basic.h>

#include "libknot/consts.h"
#include "libknot/cookies/alg-fnv64.h"
#include "libknot/cookies/server.h"
#include "libknot/errcode.h"
#include "libknot/rrtype/opt.h"
#include "libknot/rrtype/opt-cookie.h"

const char *cookie_opts[] = {
	"\x00\x0a" "\x00\x10" "\x00\x01\x02\x03\x04\x05\x06\x07" "\xe0\xd9\x95\x4e\xbc\xc3\x99\x18", /* 8 octets long wrong server cookie. */
	"\x00\x0a" "\x00\x10" "\x00\x01\x02\x03\x04\x05\x06\x07" "\xe0\xd9\x95\x4e\xbc\xc3\x99\x19", /* 8 octets long OK server cookie. */
	"\x00\x0a" "\x00\x18" "\x00\x01\x02\x03\x04\x05\x06\x07" "\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\xc0\xbd\xdb\xec\x19\x78\x88\x38", /* 8B nonce 8B hash long wrong server cookie. */
	"\x00\x0a" "\x00\x18" "\x00\x01\x02\x03\x04\x05\x06\x07" "\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\xc0\xbd\xdb\xec\x19\x78\x88\x39" /* 8B nonce 8B hash long OK server cookie. */
};

#define ROPT(i) ((const uint8_t *)cookie_opts[(i)])

static void get_opt_cookies(const uint8_t *opt, struct knot_dns_cookies *cookies)
{
	memset(cookies, 0, sizeof(*cookies));

	if (opt == NULL) {
		return;
	}

	const uint8_t *data = knot_edns_opt_get_data((uint8_t *)opt);
	uint16_t data_len = knot_edns_opt_get_length((uint8_t *)opt);

	knot_edns_opt_cookie_parse(data, data_len,
	                           &cookies->cc, &cookies->cc_len,
	                           &cookies->sc, &cookies->sc_len);
}

static int init_sa4(struct sockaddr_in *sa, uint16_t port, const char *addr)
{
	memset(sa, 0, sizeof(*sa));

	sa->sin_family = AF_INET;
	sa->sin_port = port;
	int ret = inet_pton(sa->sin_family, addr, &sa->sin_addr);
	return ret;
}

static int init_sa6(struct sockaddr_in6 *sa, uint16_t port, const char *addr)
{
	memset(sa, 0, sizeof(*sa));

	sa->sin6_family = AF_INET6;
	sa->sin6_port = port;
	int ret = inet_pton(sa->sin6_family, addr, &sa->sin6_addr);
	return ret;
}

#define PORT 0
#define A4_0 "127.0.0.1"
#define A4_1 "10.0.0.1"

#define A6_0 "2001:db8:8714:3a90::12"
#define A6_1 "::1"

int main(int argc, char *argv[])
{
	plan_lazy();

	int ret;

	struct sockaddr unspec_sa = {
		.sa_family = AF_UNSPEC
	};
	struct sockaddr_in c4_sa, s4_sa;
	struct sockaddr_in6 c6_sa, s6_sa;

	const uint8_t sc0[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	const uint8_t sc1[] = { 0, 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17 };

	const uint8_t cc[] = { 0, 1, 2, 3, 4, 5, 6, 7 };

	const uint8_t secret[] = { 0, 1, 2, 3, 4, 5, 6, 7 };

	const uint8_t nonce[] = { 10, 11, 12, 13, 14, 15, 16, 17 };

	uint8_t hash[32] = { 0 };
	uint16_t hash_len;

	struct knot_sc_content sc_content;

	struct knot_sc_private srvr_data = { 0 };
	struct knot_sc_input sc_in = { 0 };

	init_sa4(&c4_sa, PORT, A4_0);
	init_sa4(&s4_sa, PORT, A4_1);

	init_sa6(&c6_sa, PORT, A6_0);
	init_sa6(&s6_sa, PORT, A6_1);

	struct knot_dns_cookies cookies;

	/* Server cookie hash algorithm. */

	hash_len = sizeof(hash);
	ret = knot_sc_alg_fnv64.hash_func(NULL, hash, &hash_len);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie no input");

	memset(&sc_in, 0, sizeof(sc_in));
	sc_in.cc = NULL;
	sc_in.cc_len = 0;
	sc_in.nonce = NULL;
	sc_in.nonce_len = 0;
	sc_in.srvr_data = NULL;
	hash_len = sizeof(hash);
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, hash, &hash_len);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie input no data");

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = NULL;
	srvr_data.secret_data = NULL;
	srvr_data.secret_len = 0;
	sc_in.cc = NULL;
	sc_in.cc_len = 0;
	sc_in.nonce = NULL;
	sc_in.nonce_len = 0;
	sc_in.srvr_data = &srvr_data;
	hash_len = sizeof(hash);
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, hash, &hash_len);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie input no data");

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = NULL;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	sc_in.cc = cc;
	sc_in.cc_len = sizeof(cc);
	sc_in.nonce = nonce;
	sc_in.nonce_len = sizeof(nonce);
	sc_in.srvr_data = &srvr_data;
	hash_len = sizeof(hash);
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, NULL, NULL);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie output no socket");

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	srvr_data.secret_data = NULL;
	srvr_data.secret_len = 0;
	sc_in.cc = cc;
	sc_in.cc_len = sizeof(cc);
	sc_in.nonce = nonce;
	sc_in.nonce_len = sizeof(nonce);
	sc_in.srvr_data = &srvr_data;
	hash_len = sizeof(hash);
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, NULL, NULL);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie output no secret");

	memset(&sc_in, 0, sizeof(sc_in));
	sc_in.cc = cc;
	sc_in.cc_len = sizeof(cc);
	sc_in.nonce = nonce;
	sc_in.nonce_len = sizeof(nonce);
	sc_in.srvr_data = NULL;
	hash_len = sizeof(hash);
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, NULL, NULL);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie output no server data");

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	sc_in.cc = cc;
	sc_in.cc_len = sizeof(cc);
	sc_in.nonce = nonce;
	sc_in.nonce_len = sizeof(nonce);
	sc_in.srvr_data = &srvr_data;
	hash_len = sizeof(hash);
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, NULL, NULL);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie output no hash");

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	sc_in.cc = cc;
	sc_in.cc_len = sizeof(cc);
	sc_in.nonce = nonce;
	sc_in.nonce_len = sizeof(nonce);
	sc_in.srvr_data = &srvr_data;
	hash_len = 1;
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, hash, &hash_len);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie output hash no space ");

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	sc_in.cc = cc;
	sc_in.cc_len = sizeof(cc);
	sc_in.nonce = nonce;
	sc_in.nonce_len = sizeof(nonce);
	sc_in.srvr_data = &srvr_data;
	hash_len = sizeof(hash);
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, hash, &hash_len);
	ok(ret == KNOT_EOK, "cookies: FNV64 server cookie output");
	{
		uint8_t expected[] = { 0x75, 0x45, 0x7c, 0x9a, 0xe0, 0x13, 0xa8, 0xea };
		ok(sizeof(expected) == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 server cookie content");
	}

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	sc_in.cc = cc;
	sc_in.cc_len = sizeof(cc);
	sc_in.nonce = nonce;
	sc_in.nonce_len = sizeof(nonce);
	sc_in.srvr_data = &srvr_data;
	hash_len = sizeof(hash);
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, hash, &hash_len);
	ok(ret == KNOT_EOK, "cookies: FNV64 server cookie output");
	{
		uint8_t expected[] = { 0xc0, 0xbd, 0xdb, 0xec, 0x19, 0x78, 0x88, 0x39 };
		ok(sizeof(expected) == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 server cookie content");
	}

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	sc_in.cc = cc;
	sc_in.cc_len = sizeof(cc);
	sc_in.nonce = NULL;
	sc_in.nonce_len = 0;
	sc_in.srvr_data = &srvr_data;
	hash_len = sizeof(hash);
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, hash, &hash_len);
	ok(ret == KNOT_EOK, "cookies: FNV64 server cookie output");
	{
		uint8_t expected[] = { 0xe0, 0xd9, 0x95, 0x4e, 0xbc, 0xc3, 0x99, 0x19 };
		ok(sizeof(expected) == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 server cookie content");
	}

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&unspec_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	sc_in.cc = cc;
	sc_in.cc_len = sizeof(cc);
	sc_in.nonce = nonce;
	sc_in.nonce_len = sizeof(nonce);
	sc_in.srvr_data = &srvr_data;
	hash_len = sizeof(hash);
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, hash, &hash_len);
	ok(ret == KNOT_EOK, "cookies: FNV64 server cookie output");
	{
		uint8_t expected[] = { 0x4d, 0xde, 0xfa, 0x22, 0xb9, 0x0a, 0xcc, 0xd8 };
		ok(sizeof(expected) == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 server cookie content");
	}

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&unspec_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	sc_in.cc = cc;
	sc_in.cc_len = sizeof(cc) - 1;
	sc_in.nonce = nonce;
	sc_in.nonce_len = sizeof(nonce);
	sc_in.srvr_data = &srvr_data;
	hash_len = sizeof(hash);
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, hash, &hash_len);
	ok(ret == KNOT_EOK, "cookies: FNV64 server cookie output");
	{
		uint8_t expected[] = { 0xa0, 0x35, 0xe3, 0xe0, 0x78, 0x7a, 0x91, 0xaf };
		ok(sizeof(expected) == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 server cookie content");
	}

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&unspec_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	sc_in.cc = cc;
	sc_in.cc_len = sizeof(cc);
	sc_in.nonce = nonce;
	sc_in.nonce_len = sizeof(nonce) - 1;
	sc_in.srvr_data = &srvr_data;
	hash_len = sizeof(hash);
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, hash, &hash_len);
	ok(ret == KNOT_EOK, "cookies: FNV64 server cookie output");
	{
		uint8_t expected[] = { 0x8e, 0xa3, 0xf8, 0x97, 0x84, 0x0a, 0x3d, 0x8b };
		ok(sizeof(expected) == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 server cookie content");
	}

	/* Server cookie parse. */

	const void *DUMMYPTR = (void *)1;
	const int DUMMYVAL = 1;

	ret = knot_sc_parse(0, NULL, 0, &sc_content);
	ok(ret == KNOT_EINVAL, "cookies: parse server cookie no cookie");

	ret = knot_sc_parse(0, sc0, sizeof(sc0), NULL);
	ok(ret == KNOT_EINVAL, "cookies: parse server cookie no content");

	ret = knot_sc_parse(sizeof(sc0), sc0, sizeof(sc0), &sc_content);
	ok(ret == KNOT_EINVAL, "cookies: parse server cookie too large nonce");

	sc_content.nonce = sc_content.hash = DUMMYPTR;
	sc_content.nonce_len = sc_content.hash_len = DUMMYVAL;
	ret = knot_sc_parse(0, sc0, sizeof(sc0), &sc_content);
	ok(ret == KNOT_EOK &&
	   sc_content.nonce == NULL && sc_content.nonce_len == 0 &&
	   sc_content.hash == sc0 && sc_content.hash_len == sizeof(sc0), "cookies: parse server cookie 0B nonce");

	sc_content.nonce = sc_content.hash = DUMMYPTR;
	sc_content.nonce_len = sc_content.hash_len = DUMMYVAL;
	ret = knot_sc_parse(8, sc1, sizeof(sc1), &sc_content);
	ok(ret == KNOT_EOK &&
	   sc_content.nonce == sc1 && sc_content.nonce_len == 8 &&
	   sc_content.hash == (sc1 + 8) && sc_content.hash_len == 8, "cookies: parse server cookie 8B nonce");

	/* Server cookie check. */

	get_opt_cookies(ROPT(1), &cookies);
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	ret = knot_sc_check(1, &cookies, &srvr_data, &knot_sc_alg_fnv64);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie check - wrong nonce length");

	get_opt_cookies(ROPT(1), &cookies);
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	ret = knot_sc_check(17, &cookies, &srvr_data, &knot_sc_alg_fnv64);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie check - too long nonce");

	get_opt_cookies(ROPT(1), &cookies);
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	ret = knot_sc_check(0, NULL, &srvr_data, &knot_sc_alg_fnv64);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie check - no cookies");

	get_opt_cookies(ROPT(1), &cookies);
	cookies.cc = NULL;
	cookies.cc_len = 0;
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	ret = knot_sc_check(0, NULL, &srvr_data, &knot_sc_alg_fnv64);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie check - no client cookie");

	get_opt_cookies(ROPT(1), &cookies);
	cookies.sc = NULL;
	cookies.sc_len = 0;
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	ret = knot_sc_check(0, NULL, &srvr_data, &knot_sc_alg_fnv64);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie check - no server cookie");

	get_opt_cookies(ROPT(1), &cookies);
	srvr_data.clnt_sockaddr = NULL;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	ret = knot_sc_check(0, NULL, &srvr_data, &knot_sc_alg_fnv64);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie check - no socket address");

	get_opt_cookies(ROPT(1), &cookies);
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret_data = NULL;
	srvr_data.secret_len = 0;
	ret = knot_sc_check(0, &cookies, &srvr_data, &knot_sc_alg_fnv64);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie check - no secret");

	get_opt_cookies(ROPT(0), &cookies);
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	ret = knot_sc_check(0, &cookies, &srvr_data, &knot_sc_alg_fnv64);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie check - bad server cookie");

	get_opt_cookies(ROPT(1), &cookies);
	srvr_data.clnt_sockaddr = (struct sockaddr *)&unspec_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	ret = knot_sc_check(0, &cookies, &srvr_data, &knot_sc_alg_fnv64);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie check - bad socket");

	get_opt_cookies(ROPT(1), &cookies);
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret) - 1;
	ret = knot_sc_check(0, &cookies, &srvr_data, &knot_sc_alg_fnv64);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie check - bad secret");

	get_opt_cookies(ROPT(1), &cookies);
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	ret = knot_sc_check(0, &cookies, &srvr_data, &knot_sc_alg_fnv64);
	ok(ret == KNOT_EOK, "cookies: FNV64 server cookie check");

	get_opt_cookies(ROPT(2), &cookies);
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	ret = knot_sc_check(8, &cookies, &srvr_data, &knot_sc_alg_fnv64);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie check - bad server cookie");

	get_opt_cookies(ROPT(3), &cookies);
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = sizeof(secret);
	ret = knot_sc_check(8, &cookies, &srvr_data, &knot_sc_alg_fnv64);
	ok(ret == KNOT_EOK, "cookies: FNV64 server cookie check");

	return 0;
}
