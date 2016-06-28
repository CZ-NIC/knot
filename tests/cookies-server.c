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
	plan(25);

	int ret;

	struct sockaddr unspec_sa = {
		.sa_family = AF_UNSPEC
	};
	struct sockaddr_in c4_sa, s4_sa;
	struct sockaddr_in6 c6_sa, s6_sa;

#define SC0_LEN 8
	const uint8_t sc0[SC0_LEN] = { 0, 1, 2, 3, 4, 5, 6, 7 };
#define SC1_LEN 16
	const uint8_t sc1[SC1_LEN] = { 0, 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17 };

#define CC_LEN 8
	const uint8_t cc[CC_LEN] = { 0, 1, 2, 3, 4, 5, 6, 7 };

#define SECRET_LEN 8
	const uint8_t secret[SECRET_LEN] = { 0, 1, 2, 3, 4, 5, 6, 7 };

#define NONCE_LEN 8
	const uint8_t nonce[NONCE_LEN] = { 10, 11, 12, 13, 14, 15, 16, 17 };

#define HASH_MAX 32
	uint8_t hash[HASH_MAX];
	uint16_t hash_len;

	struct knot_sc_content sc_content;

	struct knot_sc_private srvr_data = { 0 };
	struct knot_sc_input sc_in = { 0 };

	init_sa4(&c4_sa, PORT, A4_0);
	init_sa4(&s4_sa, PORT, A4_1);

	init_sa6(&c6_sa, PORT, A6_0);
	init_sa6(&s6_sa, PORT, A6_1);

	/* Server cookie hash algorithm. */

	hash_len = HASH_MAX;
	ret = knot_sc_alg_fnv64.hash_func(NULL, hash, &hash_len);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie no input");

	memset(&sc_in, 0, sizeof(sc_in));
	sc_in.cc = NULL;
	sc_in.cc_len = 0;
	sc_in.nonce = NULL;
	sc_in.nonce_len = 0;
	sc_in.srvr_data = NULL;
	hash_len = HASH_MAX;
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
	hash_len = HASH_MAX;
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, hash, &hash_len);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie input no data");

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = NULL;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = SECRET_LEN;
	sc_in.cc = cc;
	sc_in.cc_len = CC_LEN;
	sc_in.nonce = nonce;
	sc_in.nonce_len = NONCE_LEN;
	sc_in.srvr_data = &srvr_data;
	hash_len = HASH_MAX;
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, NULL, NULL);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie output no socket");

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	srvr_data.secret_data = NULL;
	srvr_data.secret_len = 0;
	sc_in.cc = cc;
	sc_in.cc_len = CC_LEN;
	sc_in.nonce = nonce;
	sc_in.nonce_len = NONCE_LEN;
	sc_in.srvr_data = &srvr_data;
	hash_len = HASH_MAX;
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, NULL, NULL);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie output no secret");

	memset(&sc_in, 0, sizeof(sc_in));
	sc_in.cc = cc;
	sc_in.cc_len = CC_LEN;
	sc_in.nonce = nonce;
	sc_in.nonce_len = NONCE_LEN;
	sc_in.srvr_data = NULL;
	hash_len = HASH_MAX;
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, NULL, NULL);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie output no server data");

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = SECRET_LEN;
	sc_in.cc = cc;
	sc_in.cc_len = CC_LEN;
	sc_in.nonce = nonce;
	sc_in.nonce_len = NONCE_LEN;
	sc_in.srvr_data = &srvr_data;
	hash_len = HASH_MAX;
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, NULL, NULL);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie output no hash");

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = SECRET_LEN;
	sc_in.cc = cc;
	sc_in.cc_len = CC_LEN;
	sc_in.nonce = nonce;
	sc_in.nonce_len = NONCE_LEN;
	sc_in.srvr_data = &srvr_data;
	hash_len = 1;
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, hash, &hash_len);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 server cookie output hash no space ");

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = SECRET_LEN;
	sc_in.cc = cc;
	sc_in.cc_len = CC_LEN;
	sc_in.nonce = nonce;
	sc_in.nonce_len = NONCE_LEN;
	sc_in.srvr_data = &srvr_data;
	hash_len = HASH_MAX;
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, hash, &hash_len);
	ok(ret == KNOT_EOK, "cookies: FNV64 server cookie output");
	{
#define EXPECTED_LEN 8
		uint8_t expected[EXPECTED_LEN] = { 0x75, 0x45, 0x7c, 0x9a, 0xe0, 0x13, 0xa8, 0xea };

		ok(EXPECTED_LEN == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 server cookie content");
#undef EXPECTED_LEN
	}

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = SECRET_LEN;
	sc_in.cc = cc;
	sc_in.cc_len = CC_LEN;
	sc_in.nonce = nonce;
	sc_in.nonce_len = NONCE_LEN;
	sc_in.srvr_data = &srvr_data;
	hash_len = HASH_MAX;
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, hash, &hash_len);
	ok(ret == KNOT_EOK, "cookies: FNV64 server cookie output");
	{
#define EXPECTED_LEN 8
		uint8_t expected[EXPECTED_LEN] = { 0xc0, 0xbd, 0xdb, 0xec, 0x19, 0x78, 0x88, 0x39 };

		ok(EXPECTED_LEN == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 server cookie content");
#undef EXPECTED_LEN
	}

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = SECRET_LEN;
	sc_in.cc = cc;
	sc_in.cc_len = CC_LEN;
	sc_in.nonce = NULL;
	sc_in.nonce_len = 0;
	sc_in.srvr_data = &srvr_data;
	hash_len = HASH_MAX;
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, hash, &hash_len);
	ok(ret == KNOT_EOK, "cookies: FNV64 server cookie output");
	{
#define EXPECTED_LEN 8
		uint8_t expected[EXPECTED_LEN] = { 0xe0, 0xd9, 0x95, 0x4e, 0xbc, 0xc3, 0x99, 0x19 };

		ok(EXPECTED_LEN == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 server cookie content");
#undef EXPECTED_LEN
	}

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&unspec_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = SECRET_LEN;
	sc_in.cc = cc;
	sc_in.cc_len = CC_LEN;
	sc_in.nonce = nonce;
	sc_in.nonce_len = NONCE_LEN;
	sc_in.srvr_data = &srvr_data;
	hash_len = HASH_MAX;
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, hash, &hash_len);
	ok(ret == KNOT_EOK, "cookies: FNV64 server cookie output");
	{
#define EXPECTED_LEN 8
		uint8_t expected[EXPECTED_LEN] = { 0x4d, 0xde, 0xfa, 0x22, 0xb9, 0x0a, 0xcc, 0xd8 };

		ok(EXPECTED_LEN == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 server cookie content");
#undef EXPECTED_LEN
	}

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&unspec_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = SECRET_LEN;
	sc_in.cc = cc;
	sc_in.cc_len = CC_LEN - 1;
	sc_in.nonce = nonce;
	sc_in.nonce_len = NONCE_LEN;
	sc_in.srvr_data = &srvr_data;
	hash_len = HASH_MAX;
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, hash, &hash_len);
	ok(ret == KNOT_EOK, "cookies: FNV64 server cookie output");
	{
#define EXPECTED_LEN 8
		uint8_t expected[EXPECTED_LEN] = { 0xa0, 0x35, 0xe3, 0xe0, 0x78, 0x7a, 0x91, 0xaf };

		ok(EXPECTED_LEN == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 server cookie content");
#undef EXPECTED_LEN
	}

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&unspec_sa;
	srvr_data.secret_data = secret;
	srvr_data.secret_len = SECRET_LEN;
	sc_in.cc = cc;
	sc_in.cc_len = CC_LEN;
	sc_in.nonce = nonce;
	sc_in.nonce_len = NONCE_LEN - 1;
	sc_in.srvr_data = &srvr_data;
	hash_len = HASH_MAX;
	ret = knot_sc_alg_fnv64.hash_func(&sc_in, hash, &hash_len);
	ok(ret == KNOT_EOK, "cookies: FNV64 server cookie output");
	{
#define EXPECTED_LEN 8
		uint8_t expected[EXPECTED_LEN] = { 0x8e, 0xa3, 0xf8, 0x97, 0x84, 0x0a, 0x3d, 0x8b };

		ok(EXPECTED_LEN == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 server cookie content");
#undef EXPECTED_LEN
	}

	/* Server cookie parse. */

#define DUMMYPTR ((void *)0x01)
#define DUMMYVAL 1

	ret = knot_sc_parse(0, NULL, 0, &sc_content);
	ok(ret == KNOT_EINVAL, "cookies: parse server cookie no cookie");

	ret = knot_sc_parse(0, sc0, SC0_LEN, NULL);
	ok(ret == KNOT_EINVAL, "cookies: parse server cookie no content");

	ret = knot_sc_parse(SC0_LEN, sc0, SC0_LEN, &sc_content);
	ok(ret == KNOT_EINVAL, "cookies: parse server cookie too large nonce");

	sc_content.nonce = sc_content.hash = DUMMYPTR;
	sc_content.nonce_len = sc_content.hash_len = DUMMYVAL;
	ret = knot_sc_parse(0, sc0, SC0_LEN, &sc_content);
	ok(ret == KNOT_EOK &&
	   sc_content.nonce == NULL && sc_content.nonce_len == 0 &&
	   sc_content.hash == sc0 && sc_content.hash_len == SC0_LEN, "cookies: parse server cookie 0B nonce");

	sc_content.nonce = sc_content.hash = DUMMYPTR;
	sc_content.nonce_len = sc_content.hash_len = DUMMYVAL;
	ret = knot_sc_parse(8, sc1, SC1_LEN, &sc_content);
	ok(ret == KNOT_EOK &&
	   sc_content.nonce == sc1 && sc_content.nonce_len == 8 &&
	   sc_content.hash == (sc1 + 8) && sc_content.hash_len == 8, "cookies: parse server cookie 8B nonce");

	/* Server cookie check. */

	/* TODO */

	return 0;
}
