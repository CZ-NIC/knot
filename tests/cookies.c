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
#include "libknot/cookies/server.h"
#include "libknot/errcode.h"
#include "libknot/rrtype/opt.h"
#include "libknot/rrtype/opt-cookie.h"

#define OPTCOUNT 9

const char *cookie_opts[OPTCOUNT] = {
	"\x00\x0a" "\x00\x00", /* Zero length cookie. */
	"\x00\x0a" "\x00\x01" "\x00", /* Short client cookie. */
	"\x00\x0a" "\x00\x07" "\x00\x01\x02\x03\x04\x05\x06", /* Short client cookie. */
	"\x00\x0a" "\x00\x09" "\x00\x01\x02\x03\x04\x05\x06\x07" "\x08", /* Short server cookie. */
	"\x00\x0a" "\x00\x0f" "\x00\x01\x02\x03\x04\x05\x06\x07" "\x08\x09\x0a\x0b\x0c\x0d\x0e", /* Short server cookie. */
	"\x00\x0a" "\x00\x29" "\x00\x01\x02\x03\x04\x05\x06\x07" "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28", /* Long server cookie. */
	"\x00\x0a" "\x00\x08" "\x00\x01\x02\x03\x04\x05\x06\x07", /* Only client cookie. */
	"\x00\x0a" "\x00\x10" "\x00\x01\x02\x03\x04\x05\x06\x07" "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", /* 8 octets long server cookie. */
	"\x00\x0a" "\x00\x28" "\x00\x01\x02\x03\x04\x05\x06\x07" "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27" /* 32 octets long server cookie. */
};

#define ROPT(i) ((const uint8_t *)cookie_opts[(i)])

static int init_sa4(struct sockaddr_in *sa, uint16_t port, const char *addr)
{
	memset(sa, 0, sizeof(*sa));

	sa->sin_family = AF_INET;
	sa->sin_port = port;
	int ret = inet_pton(sa->sin_family, addr, &sa->sin_addr);
	fprintf(stderr, "%s(): %d\n", __func__, ret);
	return ret;
}

static int init_sa6(struct sockaddr_in6 *sa, uint16_t port, const char *addr)
{
	memset(sa, 0, sizeof(*sa));

	sa->sin6_family = AF_INET6;
	sa->sin6_port = port;
	int ret = inet_pton(sa->sin6_family, addr, &sa->sin6_addr);
	fprintf(stderr, "%s(): %d\n", __func__, ret);
	return ret;
}

#define PORT 0
#define A4_0 "127.0.0.1"
#define A4_1 "10.0.0.1"

#define A6_0 "2001:db8:8714:3a90::12"
#define A6_1 "::1"

static void get_opt_data(const uint8_t *opt,
                         const uint8_t **data, uint16_t *data_len)
{
	if (opt == NULL) {
		*data = NULL;
		*data_len = 0;
	}

	*data = knot_edns_opt_get_data((uint8_t *)opt);
	*data_len = knot_edns_opt_get_length((uint8_t *)opt);
}

int main(int argc, char *argv[])
{
	plan(4);

	uint16_t code;
	uint16_t data_len;
	const uint8_t *data;
	int ret;

	const uint8_t *cc, *sc;
	uint16_t cc_len, sc_len;

	struct sockaddr unspec_sa = {
		.sa_family = AF_UNSPEC
	};
	struct sockaddr_in c4_sa, s4_sa;
	struct sockaddr_in6 c6_sa, s6_sa;

#define SECRET_LEN 8
	const uint8_t secret[SECRET_LEN] = { 0, 1, 2, 3, 4, 5, 6, 7 };

#define HASH_MAX 32
	uint8_t hash[HASH_MAX];
	uint16_t hash_len;

	struct knot_cc_input cc_in = { 0 };

	init_sa4(&c4_sa, PORT, A4_0);
	init_sa4(&s4_sa, PORT, A4_1);

	init_sa6(&c6_sa, PORT, A6_0);
	init_sa6(&s6_sa, PORT, A6_1);

	code = knot_edns_opt_get_code(ROPT(0));
	ok(code == KNOT_EDNS_OPTION_COOKIE, "cookies: EDNS OPT code");

	data_len = knot_edns_opt_get_length(ROPT(1));
	ok(data_len == 1, "cookies: EDNS OPT length");

	/* Should return pointer to data, although option has zero length. */
	data = knot_edns_opt_get_data((uint8_t *)ROPT(0));
	ok(data != NULL, "cookies: EDNS OPT zero data");

	data = knot_edns_opt_get_data((uint8_t *)ROPT(1));
	ok(data != NULL, "cookies: EDNS OPT data");

	ret = knot_edns_opt_cookie_parse(NULL, 0, NULL, NULL, NULL, NULL);
	ok(ret == KNOT_EINVAL, "cookies: EDNS OPT parse NULL");

	/* Malformed cookies. */

	get_opt_data(ROPT(0), &data, &data_len);
	ret = knot_edns_opt_cookie_parse(data, data_len, NULL, NULL, NULL, NULL);
	ok(ret == KNOT_EMALF, "cookies: EDNS OPT parse zero length");

	get_opt_data(ROPT(1), &data, &data_len);
	ret = knot_edns_opt_cookie_parse(data, data_len, &cc, &cc_len, &sc, &sc_len);
	ok(ret == KNOT_EMALF, "cookies: EDNS OPT parse 1B (short) cookie");

	get_opt_data(ROPT(2), &data, &data_len);
	ret = knot_edns_opt_cookie_parse(data, data_len, &cc, &cc_len, &sc, &sc_len);
	ok(ret == KNOT_EMALF, "cookies: EDNS OPT parse 7B (short) cookie");

	get_opt_data(ROPT(3), &data, &data_len);
	ret = knot_edns_opt_cookie_parse(data, data_len, &cc, &cc_len, &sc, &sc_len);
	ok(ret == KNOT_EMALF, "cookies: EDNS OPT parse 9B (short) cookie");

	get_opt_data(ROPT(4), &data, &data_len);
	ret = knot_edns_opt_cookie_parse(data, data_len, &cc, &cc_len, &sc, &sc_len);
	ok(ret == KNOT_EMALF, "cookies: EDNS OPT parse 15B (short) cookie");

	get_opt_data(ROPT(5), &data, &data_len);
	ret = knot_edns_opt_cookie_parse(data, data_len, &cc, &cc_len, &sc, &sc_len);
	ok(ret == KNOT_EMALF, "cookies: EDNS OPT parse 41B (long) cookie");

	get_opt_data(ROPT(5), &data, &data_len);
	ret = knot_edns_opt_cookie_parse(data, data_len, &cc, &cc_len, &sc, &sc_len);
	ok(ret == KNOT_EMALF, "cookies: EDNS OPT parse 41B (long) cookie");

	/* Testing combination of output parameters. */

	cc = sc = NULL;
	cc_len = sc_len = 0;
	get_opt_data(ROPT(7), &data, &data_len);
	ret = knot_edns_opt_cookie_parse(data, data_len, &cc, &cc_len, NULL, NULL);
	ok(ret == KNOT_EOK && cc != NULL && cc_len == 8, "cookies: EDNS OPT parse client cookie");

	cc = sc = NULL;
	cc_len = sc_len = 0;
	get_opt_data(ROPT(7), &data, &data_len);
	ret = knot_edns_opt_cookie_parse(data, data_len, NULL, NULL, &sc, &sc_len);
	ok(ret == KNOT_EOK && sc != NULL && sc_len == 8, "cookies: EDNS OPT parse server cookie");

	/* Valid cookies. */

#define DUMMYPTR ((void *)0x01)
#define DUMMYVAL 1

	cc = sc = DUMMYPTR;
	cc_len = sc_len = DUMMYVAL;
	get_opt_data(ROPT(6), &data, &data_len);
	ret = knot_edns_opt_cookie_parse(data, data_len, &cc, &cc_len, &sc, &sc_len);
	ok(ret == KNOT_EOK &&
	   cc != NULL && cc != DUMMYPTR && cc_len == 8 &&
	   sc == NULL && sc_len == 0, "cookies: EDNS OPT parse 8B cookie");

	cc = sc = DUMMYPTR;
	cc_len = sc_len = DUMMYVAL;
	get_opt_data(ROPT(7), &data, &data_len);
	ret = knot_edns_opt_cookie_parse(data, data_len, &cc, &cc_len, &sc, &sc_len);
	ok(ret == KNOT_EOK &&
	    cc != NULL && cc != DUMMYPTR && cc_len == 8 &&
	    sc != NULL && sc != DUMMYPTR && sc_len == 8, "cookies: EDNS OPT parse 16B cookie");

	cc = sc = DUMMYPTR;
	cc_len = sc_len = DUMMYVAL;
	get_opt_data(ROPT(8), &data, &data_len);
	ret = knot_edns_opt_cookie_parse(data, data_len, &cc, &cc_len, &sc, &sc_len);
	ok(ret == KNOT_EOK &&
	   cc != NULL && cc != DUMMYPTR && cc_len == 8 &&
	   sc != NULL && sc != DUMMYPTR && sc_len == 32, "cookies: EDNS OPT parse 40B cookie");

	/* Client cookie hash algorithm. */

	ret = knot_cc_alg_fnv64.gen_func(NULL, hash, &hash_len);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie no input");

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = NULL;
	cc_in.srvr_sockaddr = NULL;
	cc_in.secret_data = NULL;
	cc_in.secret_len = 0;
	hash_len = HASH_MAX;
	ret = knot_cc_alg_fnv64.gen_func(&cc_in, hash, &hash_len);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie input no data");

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s4_sa;
	cc_in.secret_data = NULL;
	cc_in.secret_len = 0;
	hash_len = HASH_MAX;
	ret = knot_cc_alg_fnv64.gen_func(&cc_in, hash, &hash_len);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie input no secret");

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = NULL;
	cc_in.srvr_sockaddr = NULL;
	cc_in.secret_data = secret;
	cc_in.secret_len = SECRET_LEN;
	hash_len = HASH_MAX;
	ret = knot_cc_alg_fnv64.gen_func(&cc_in, hash, &hash_len);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie input no socket");

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s4_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = SECRET_LEN;
	hash_len = HASH_MAX;
	ret = knot_cc_alg_fnv64.gen_func(&cc_in, NULL, NULL);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie output no hash");

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s4_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = SECRET_LEN;
	hash_len = 1;
	ret = knot_cc_alg_fnv64.gen_func(&cc_in, hash, &hash_len);
	ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie hash no space");

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s4_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = SECRET_LEN;
	hash_len = HASH_MAX;
	ret = knot_cc_alg_fnv64.gen_func(&cc_in, hash, &hash_len);
	ok(ret == KNOT_EOK && hash_len == knot_cc_alg_fnv64.cc_size, "cookies: FNV64 client cookie output");
	{
#define EXPECTED_LEN 8
		uint8_t expected[EXPECTED_LEN] = { 0x74, 0x31, 0xf9, 0xa8, 0x03, 0xef, 0x15, 0xb1 };

		ok(EXPECTED_LEN == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 client cookie content");
#undef EXPECTED_LEN
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = NULL;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s4_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = SECRET_LEN;
	hash_len = HASH_MAX;
	ret = knot_cc_alg_fnv64.gen_func(&cc_in, hash, &hash_len);
	ok(ret == KNOT_EOK && hash_len == knot_cc_alg_fnv64.cc_size, "cookies: FNV64 client cookie output");
	{
#define EXPECTED_LEN 8
		uint8_t expected[EXPECTED_LEN] = { 0x7c, 0x62, 0x25, 0xd2, 0x43, 0xdd, 0x09, 0xe7 };

		ok(EXPECTED_LEN == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 client cookie content");
#undef EXPECTED_LEN
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	cc_in.srvr_sockaddr = NULL;
	cc_in.secret_data = secret;
	cc_in.secret_len = SECRET_LEN;
	hash_len = HASH_MAX;
	ret = knot_cc_alg_fnv64.gen_func(&cc_in, hash, &hash_len);
	ok(ret == KNOT_EOK && hash_len == knot_cc_alg_fnv64.cc_size, "cookies: FNV64 client cookie output");
	{
#define EXPECTED_LEN 8
		uint8_t expected[EXPECTED_LEN] = { 0x05, 0xa9, 0xd1, 0x08, 0x1b, 0x98, 0xe0, 0xaa };

		ok(EXPECTED_LEN == hash_len && 0 == memcmp(expected, hash, hash_len), "cookies: FNV64 client cookie content");
#undef EXPECTED_LEN
	}

	/* Client cookie check. */

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s6_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = SECRET_LEN;
	{
		ret = knot_cc_check(NULL, 0, &cc_in, &knot_cc_alg_fnv64);
		ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie check no cookie");
	}

	{
#define COOKIE_LEN 8
		uint8_t cookie[COOKIE_LEN] = { 0x33, 0x0c, 0xa6, 0x80, 0x94, 0x17, 0xe5, 0xaf };

		ret = knot_cc_check(cookie, COOKIE_LEN, NULL, &knot_cc_alg_fnv64);
		ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie check no input");
#undef COOKIE_LEN
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s6_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = SECRET_LEN;
	{
#define COOKIE_LEN 8
		uint8_t cookie[COOKIE_LEN] = { 0x33, 0x0c, 0xa6, 0x80, 0x94, 0x17, 0xe5, 0xaf };

		ret = knot_cc_check(NULL, 0, &cc_in, &knot_cc_alg_fnv64);
		ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie check no algorithm");
#undef COOKIE_LEN
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s6_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = SECRET_LEN;
	{
#define COOKIE_LEN 8
		uint8_t cookie[COOKIE_LEN] = { 0x33, 0x0c, 0xa6, 0x80, 0x94, 0x17, 0xe5, 0xaf };

		ret = knot_cc_check(cookie, COOKIE_LEN, &cc_in, &knot_cc_alg_fnv64);
		ok(ret == KNOT_EOK, "cookies: FNV64 client good cookie check");
#undef COOKIE_LEN
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s6_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = SECRET_LEN;
	{
#define COOKIE_LEN 8
		uint8_t cookie[COOKIE_LEN] = { 0x33, 0x0c, 0xa6, 0x80, 0x94, 0x17, 0xe5, 0xaf };

		ret = knot_cc_check(cookie, COOKIE_LEN - 1, &cc_in, &knot_cc_alg_fnv64);
		ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie check invalid length");
#undef COOKIE_LEN
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s6_sa;
	cc_in.secret_data = secret;
	cc_in.secret_len = SECRET_LEN;
	{
#define COOKIE_LEN 8
		uint8_t cookie[COOKIE_LEN] = { 0x33, 0x0c, 0xa6, 0x80, 0x94, 0x17, 0xe5, 0xae };

		ret = knot_cc_check(cookie, COOKIE_LEN, &cc_in, &knot_cc_alg_fnv64);
		ok(ret == KNOT_EINVAL, "cookies: FNV64 client cookie check invalid cookie");
#undef COOKIE_LEN
	}

	return 0;
}
