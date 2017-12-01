/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tap/basic.h>

#include "contrib/endian.h"
#include "contrib/openbsd/siphash.h"
#include "contrib/sockaddr.h"
#include "libknot/consts.h"
#include "libknot/cookies/server.h"
#include "libknot/cookies/server.c"
#include "libknot/errcode.h"
#include "libknot/rrtype/opt.h"
#include "libknot/rrtype/opt-cookie.h"

const char *cookie_opts[] = {
	"\x00\x0a" "\x00\x10" "\x00\x01\x02\x03\x04\x05\x06\x07" "\x19\x99\xc3\xbc\x4e\x95\xd9\xdf", /* 8 octets long wrong server cookie. */
	"\x00\x0a" "\x00\x10" "\x00\x01\x02\x03\x04\x05\x06\x07" "\x69\xf4\xac\x05\x90\x6c\xac\x33", /* 8 octets long OK server cookie. */
	"\x00\x0a" "\x00\x18" "\x00\x01\x02\x03\x04\x05\x06\x07" "\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x39\x88\x78\x19\xec\xdb\xbd\xbf", /* 8B nonce 8B hash long wrong server cookie. */
	"\x00\x0a" "\x00\x18" "\x00\x01\x02\x03\x04\x05\x06\x07" "\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\xc5\xe0\x47\x89\xe9\x77\x32\xd2"/* 8B nonce 8B hash long OK server cookie. */
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

int main(int argc, char *argv[])
{
	plan_lazy();

	int ret;

	const uint8_t sc0[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	const uint8_t sc1[] = { 0, 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17 };

	const uint8_t cc[] = { 0, 1, 2, 3, 4, 5, 6, 7 };

	SIPHASH_KEY secret = {
		.k0 = htole64(0xDEADBEEFFACE),
		.k1 = htole64(0xFACEDEADBEEF)
	};

	SIPHASH_KEY empty = { 0 };

	const uint8_t nonce[] = { 10, 11, 12, 13, 14, 15, 16, 17 };

	uint64_t hash;

	struct knot_sc_content sc_content;

	struct knot_sc_private srvr_data = { 0 };
	struct knot_sc_input sc_in = { 0 };

	struct sockaddr_storage unspec_sa = { 0 };

	struct sockaddr_storage c4_sa = { 0 };
	struct sockaddr_storage s4_sa = { 0 };
	sockaddr_set(&c4_sa, AF_INET, "127.0.0.1", 0);
	sockaddr_set(&s4_sa, AF_INET, "10.0.0.1", 0);

	struct sockaddr_storage c6_sa = { 0 };
	struct sockaddr_storage s6_sa = { 0 };
	sockaddr_set(&c6_sa, AF_INET6, "2001:db8:8714:3a90::12", 0);
	sockaddr_set(&s6_sa, AF_INET6, "::1", 0);

	struct knot_dns_cookies cookies;

	/* Server cookie hash algorithm. */

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	srvr_data.secret = secret;
	sc_in.cc = cc;
	sc_in.cc_len = sizeof(cc);
	sc_in.nonce = nonce;
	sc_in.nonce_len = sizeof(nonce);
	sc_in.srvr_data = &srvr_data;
	hash = generate_server_cookie(&sc_in);
	{
		uint64_t expected = 0xbb08ce797dade217;
		ok(0 == memcmp(&expected, &hash, SERVER_HASH_LEN), "cookies: SipHash server cookie content");
	}

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret = secret;
	sc_in.cc = cc;
	sc_in.cc_len = sizeof(cc);
	sc_in.nonce = nonce;
	sc_in.nonce_len = sizeof(nonce);
	sc_in.srvr_data = &srvr_data;
	hash = generate_server_cookie(&sc_in);
	{
		uint64_t expected = 0xd23277e98947e0c5;
		ok(0 == memcmp(&expected, &hash, SERVER_HASH_LEN), "cookies: SipHash server cookie content");
	}

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret = secret;
	sc_in.cc = cc;
	sc_in.cc_len = sizeof(cc);
	sc_in.nonce = NULL;
	sc_in.nonce_len = 0;
	sc_in.srvr_data = &srvr_data;
	hash = generate_server_cookie(&sc_in);
	{
		uint64_t expected = 0x33ac6c9005acf469;
		ok(0 == memcmp(&expected, &hash, SERVER_HASH_LEN), "cookies: SipHash server cookie content");
	}

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&unspec_sa;
	srvr_data.secret = secret;
	sc_in.cc = cc;
	sc_in.cc_len = sizeof(cc);
	sc_in.nonce = nonce;
	sc_in.nonce_len = sizeof(nonce);
	sc_in.srvr_data = &srvr_data;
	hash = generate_server_cookie(&sc_in);
	{
		uint64_t expected = 0x5732e9d1127281e9;
		ok(0 == memcmp(&expected, &hash, SERVER_HASH_LEN), "cookies: SipHash server cookie content");
	}

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&unspec_sa;
	srvr_data.secret = secret;
	sc_in.cc = cc;
	sc_in.cc_len = sizeof(cc) - 1;
	sc_in.nonce = nonce;
	sc_in.nonce_len = sizeof(nonce);
	sc_in.srvr_data = &srvr_data;
	hash = generate_server_cookie(&sc_in);
	{
		uint64_t expected = 0x98a4bf0c9fb53340;
		ok(0 == memcmp(&expected, &hash, SERVER_HASH_LEN), "cookies: SipHash server cookie content");
	}

	memset(&sc_in, 0, sizeof(sc_in));
	srvr_data.clnt_sockaddr = (struct sockaddr *)&unspec_sa;
	srvr_data.secret = secret;
	sc_in.cc = cc;
	sc_in.cc_len = sizeof(cc);
	sc_in.nonce = nonce;
	sc_in.nonce_len = sizeof(nonce) - 1;
	sc_in.srvr_data = &srvr_data;
	hash = generate_server_cookie(&sc_in);
	{
		uint64_t expected = 0xdb33fa2bb43d9ac5;
		ok(0 == memcmp(&expected, &hash, SERVER_HASH_LEN), "cookies: SipHash server cookie content");
	}

	/* Server cookie parse. */

	const void *DUMMYPTR = (void *)1;
	const int DUMMYVAL = 1;

	ret = knot_sc_parse(0, NULL, 0, &sc_content);
	is_int(KNOT_EINVAL, ret, "cookies: parse server cookie no cookie");

	ret = knot_sc_parse(0, sc0, sizeof(sc0), NULL);
	is_int(KNOT_EINVAL, ret, "cookies: parse server cookie no content");

	ret = knot_sc_parse(sizeof(sc0), sc0, sizeof(sc0), &sc_content);
	is_int(KNOT_EINVAL, ret, "cookies: parse server cookie too large nonce");

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
	srvr_data.secret = secret;
	ret = knot_sc_check(1, &cookies, &srvr_data);
	is_int(KNOT_EINVAL, ret, "cookies: SipHash server cookie check - wrong nonce length");

	get_opt_cookies(ROPT(1), &cookies);
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret = secret;
	ret = knot_sc_check(17, &cookies, &srvr_data);
	is_int(KNOT_EINVAL, ret, "cookies: SipHash server cookie check - too long nonce");

	get_opt_cookies(ROPT(1), &cookies);
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret = secret;
	ret = knot_sc_check(0, NULL, &srvr_data);
	is_int(KNOT_EINVAL, ret, "cookies: SipHash server cookie check - no cookies");

	get_opt_cookies(ROPT(1), &cookies);
	cookies.cc = NULL;
	cookies.cc_len = 0;
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret = secret;
	ret = knot_sc_check(0, NULL, &srvr_data);
	is_int(KNOT_EINVAL, ret, "cookies: SipHash server cookie check - no client cookie");

	get_opt_cookies(ROPT(1), &cookies);
	cookies.sc = NULL;
	cookies.sc_len = 0;
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret = secret;
	ret = knot_sc_check(0, NULL, &srvr_data);
	is_int(KNOT_EINVAL, ret, "cookies: SipHash server cookie check - no server cookie");

	get_opt_cookies(ROPT(1), &cookies);
	srvr_data.clnt_sockaddr = NULL;
	srvr_data.secret = secret;
	ret = knot_sc_check(0, NULL, &srvr_data);
	is_int(KNOT_EINVAL, ret, "cookies: SipHash server cookie check - no socket address");

	get_opt_cookies(ROPT(1), &cookies);
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret = empty;
	ret = knot_sc_check(0, &cookies, &srvr_data);
	is_int(KNOT_EINVAL, ret, "cookies: SipHash server cookie check - no secret");

	get_opt_cookies(ROPT(0), &cookies);
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret = secret;
	ret = knot_sc_check(0, &cookies, &srvr_data);
	is_int(KNOT_EINVAL, ret, "cookies: SipHash server cookie check - bad server cookie");

	get_opt_cookies(ROPT(1), &cookies);
	srvr_data.clnt_sockaddr = (struct sockaddr *)&unspec_sa;
	srvr_data.secret = secret;
	ret = knot_sc_check(0, &cookies, &srvr_data);
	is_int(KNOT_EINVAL, ret, "cookies: SipHash server cookie check - bad socket");

	get_opt_cookies(ROPT(1), &cookies);
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret = secret;
	ret = knot_sc_check(0, &cookies, &srvr_data);
	is_int(KNOT_EOK, ret, "cookies: SipHash server cookie check");

	get_opt_cookies(ROPT(2), &cookies);
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret = secret;
	ret = knot_sc_check(8, &cookies, &srvr_data);
	is_int(KNOT_EINVAL, ret, "cookies: SipHash server cookie check - bad server cookie");

	get_opt_cookies(ROPT(3), &cookies);
	srvr_data.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	srvr_data.secret = secret;
	ret = knot_sc_check(8, &cookies, &srvr_data);
	is_int(KNOT_EOK, ret, "cookies: SipHash server cookie check");

	return 0;
}
