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
#include "libknot/cookies/client.h"
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

int main(int argc, char *argv[])
{
	plan_lazy();

	int ret;

	struct sockaddr unspec_sa = {
		.sa_family = AF_UNSPEC
	};
	struct sockaddr_in c4_sa, s4_sa;
	struct sockaddr_in6 c6_sa, s6_sa;

	const uint8_t secret[] = { 0, 1, 2, 3, 4, 5, 6, 7 };

	uint8_t hash[32] = { 0 };
	uint16_t hash_len;

	struct knot_cc_input cc_in = { 0 };

	init_sa4(&c4_sa, 0, "127.0.0.1");
	init_sa4(&s4_sa, 0, "10.0.0.1");

	init_sa6(&c6_sa, 0, "2001:db8:8714:3a90::12");
	init_sa6(&s6_sa, 0, "::1");

	/* Client cookie hash algorithm. */

	hash_len = sizeof(hash);
	ret = knot_cc_alg_fnv64.gen_func(NULL, hash, &hash_len);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie no input");

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = NULL;
	cc_in.srvr_sockaddr = NULL;
	cc_in.secret_data = NULL;
	cc_in.secret_len = 0;
	hash_len = sizeof(hash);
	ret = knot_cc_alg_fnv64.gen_func(&cc_in, hash, &hash_len);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie input no data");

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s4_sa;
	cc_in.secret_data = NULL;
	cc_in.secret_len = 0;
	hash_len = sizeof(hash);
	ret = knot_cc_alg_fnv64.gen_func(&cc_in, hash, &hash_len);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie input no secret");

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = NULL;
	cc_in.srvr_sockaddr = NULL;
	cc_in.secret_data = secret;
	cc_in.secret_len = sizeof(secret);
	hash_len = sizeof(hash);
	ret = knot_cc_alg_fnv64.gen_func(&cc_in, hash, &hash_len);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie input no socket");

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s4_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = sizeof(secret);
	hash_len = sizeof(hash);
	ret = knot_cc_alg_fnv64.gen_func(&cc_in, NULL, NULL);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie output no hash");

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s4_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = sizeof(secret);
	hash_len = 1;
	ret = knot_cc_alg_fnv64.gen_func(&cc_in, hash, &hash_len);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie hash no space");

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s4_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = sizeof(secret);
	hash_len = sizeof(hash);
	ret = knot_cc_alg_fnv64.gen_func(&cc_in, hash, &hash_len);
	ok(ret == KNOT_EOK && hash_len == knot_cc_alg_fnv64.cc_size, "cookies: FNV64 client cookie output");
	{
		uint8_t expected[] = { 0x74, 0x31, 0xf9, 0xa8, 0x03, 0xef, 0x15, 0xb1 };
		ok(sizeof(expected) == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 client cookie content");
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = NULL;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s4_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = sizeof(secret);
	hash_len = sizeof(hash);
	ret = knot_cc_alg_fnv64.gen_func(&cc_in, hash, &hash_len);
	ok(ret == KNOT_EOK && hash_len == knot_cc_alg_fnv64.cc_size, "cookies: FNV64 client cookie output");
	{
		uint8_t expected[] = { 0x7c, 0x62, 0x25, 0xd2, 0x43, 0xdd, 0x09, 0xe7 };
		ok(sizeof(expected) == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 client cookie content");
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&unspec_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s4_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = sizeof(secret);
	hash_len = sizeof(hash);
	ret = knot_cc_alg_fnv64.gen_func(&cc_in, hash, &hash_len);
	ok(ret == KNOT_EOK && hash_len == knot_cc_alg_fnv64.cc_size, "cookies: FNV64 client cookie output");
	{
		uint8_t expected[] = { 0x7c, 0x62, 0x25, 0xd2, 0x43, 0xdd, 0x09, 0xe7 };
		ok(sizeof(expected) == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 client cookie content");
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	cc_in.srvr_sockaddr = NULL;
	cc_in.secret_data = secret;
	cc_in.secret_len = sizeof(secret);
	hash_len = sizeof(hash);
	ret = knot_cc_alg_fnv64.gen_func(&cc_in, hash, &hash_len);
	ok(ret == KNOT_EOK && hash_len == knot_cc_alg_fnv64.cc_size, "cookies: FNV64 client cookie output");
	{
		uint8_t expected[] = { 0x05, 0xa9, 0xd1, 0x08, 0x1b, 0x98, 0xe0, 0xaa };
		ok(sizeof(expected) == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 client cookie content");
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&unspec_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = sizeof(secret);
	hash_len = sizeof(hash);
	ret = knot_cc_alg_fnv64.gen_func(&cc_in, hash, &hash_len);
	ok(ret == KNOT_EOK && hash_len == knot_cc_alg_fnv64.cc_size, "cookies: FNV64 client cookie output");
	{
		uint8_t expected[] = { 0x05, 0xa9, 0xd1, 0x08, 0x1b, 0x98, 0xe0, 0xaa };
		ok(sizeof(expected) == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 client cookie content");
	}

	/* Client cookie check. */

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s6_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = sizeof(secret);
	{
		ret = knot_cc_check(NULL, 0, &cc_in, &knot_cc_alg_fnv64);
		ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie check no cookie");
	}

	{
		uint8_t cookie[] = { 0x33, 0x0c, 0xa6, 0x80, 0x94, 0x17, 0xe5, 0xaf };
		ret = knot_cc_check(cookie, sizeof(cookie), NULL, &knot_cc_alg_fnv64);
		ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie check no input");
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s6_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = sizeof(secret);
	{
		uint8_t cookie[] = { 0x33, 0x0c, 0xa6, 0x80, 0x94, 0x17, 0xe5, 0xaf };
		ret = knot_cc_check(cookie, sizeof(cookie), &cc_in, NULL);
		ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie check no algorithm");
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s6_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = sizeof(secret);
	{
		uint8_t cookie[] = { 0x33, 0x0c, 0xa6, 0x80, 0x94, 0x17, 0xe5, 0xaf };
		ret = knot_cc_check(cookie, sizeof(cookie), &cc_in, &knot_cc_alg_fnv64);
		ok(ret == KNOT_EOK, "cookies: FNV64 client good cookie check");
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s6_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = sizeof(secret);
	{
		uint8_t cookie[] = { 0x33, 0x0c, 0xa6, 0x80, 0x94, 0x17, 0xe5, 0xaf };
		ret = knot_cc_check(cookie, sizeof(cookie) - 1, &cc_in, &knot_cc_alg_fnv64);
		ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie check invalid length");
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s6_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = sizeof(secret);
	{
		uint8_t cookie[] = { 0x33, 0x0c, 0xa6, 0x80, 0x94, 0x17, 0xe5, 0xae };
		ret = knot_cc_check(cookie, sizeof(cookie), &cc_in, &knot_cc_alg_fnv64);
		ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie check invalid cookie");
	}
}
