/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdlib.h>
#include <string.h>
#include <tap/basic.h>

#include "libknot/cookies.h"
#include "libknot/endian.h"
#include "libknot/errcode.h"
#include "contrib/sockaddr.h"

static void client_generate(struct sockaddr_storage *c_addr, struct sockaddr_storage *s_addr,
                            const uint8_t *secret, const char *msg, int code, uint64_t le_cc)
{
	knot_edns_cookie_params_t params = {
		.client_addr = (struct sockaddr *)c_addr,
		.server_addr = (struct sockaddr *)s_addr,
	};
	memcpy(params.secret, secret, sizeof(params.secret));

	knot_edns_cookie_t cc;
	int ret = knot_edns_cookie_client_generate(&cc, &params);
	is_int(ret, code, "client_generate ret: %s", msg);
	if (ret == KNOT_EOK) {
		uint64_t ref = le64toh(le_cc);
		ok(cc.len == sizeof(ref) && memcmp(cc.data, &ref, cc.len) == 0,
		   "client_generate value: %s", msg);
	}
}

static void server_generate(struct sockaddr_storage *c_addr, const uint8_t *secret,
                            const knot_edns_cookie_t *cc, const char *msg, int code,
                            uint64_t le_sc)
{
	knot_edns_cookie_params_t params = {
		.client_addr = (struct sockaddr *)c_addr,
	};
	memcpy(params.secret, secret, sizeof(params.secret));

	knot_edns_cookie_t sc;
	int ret = knot_edns_cookie_server_generate(&sc, cc, &params);
	is_int(ret, code, "server_generate ret: %s", msg);
	if (ret == KNOT_EOK) {
		uint64_t ref = le64toh(le_sc);
		ok(sc.len == sizeof(ref) && memcmp(sc.data, &ref, sc.len) == 0,
		   "server_generate value: %s", msg);
	}
}

static void client_check(struct sockaddr_storage *c_addr, struct sockaddr_storage *s_addr,
                         const uint8_t *secret, const char *msg, uint16_t le_cc_len,
                         uint64_t le_cc, int code)
{
	knot_edns_cookie_params_t params = {
		.client_addr = (struct sockaddr *)c_addr,
		.server_addr = (struct sockaddr *)s_addr,
	};
	if (secret != NULL) {
		memcpy(params.secret, secret, sizeof(params.secret));
	}

	uint64_t ref = le64toh(le_cc);
	knot_edns_cookie_t cc = {
		.len = le_cc_len
	};
	memcpy(cc.data, &ref, le_cc_len);

	int ret = knot_edns_cookie_client_check(&cc, &params);
	is_int(ret, code, "client_check ret: %s", msg);
}

static void server_check(struct sockaddr_storage *c_addr, const uint8_t *secret,
                         const char *msg, uint16_t le_cc_len, uint64_t le_cc,
                         uint16_t le_sc_len, uint64_t le_sc, int code)
{
	knot_edns_cookie_params_t params = {
		.client_addr = (struct sockaddr *)c_addr,
	};
	if (secret != NULL) {
		memcpy(params.secret, secret, sizeof(params.secret));
	}

	uint64_t ref = le64toh(le_cc);
	knot_edns_cookie_t cc = {
		.len = le_cc_len
	};
	memcpy(cc.data, &ref, le_cc_len);

	ref = le64toh(le_sc);
	knot_edns_cookie_t sc = {
		.len = le_sc_len
	};
	memcpy(sc.data, &ref, le_sc_len);

	int ret = knot_edns_cookie_server_check(&sc, &cc, &params);
	is_int(ret, code, "server_check ret: %s", msg);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	const uint8_t secret[] = "\xCE\xFA\xEF\xBE\xAD\xDE\x00\x00\xEF\xBE\xAD\xDE\xCE\xFA\x00\x00";

	struct sockaddr_storage unspec_sa = { 0 };

	struct sockaddr_storage c4_sa = { 0 };
	struct sockaddr_storage s4_sa = { 0 };
	sockaddr_set(&c4_sa, AF_INET, "127.0.0.1", 0);
	sockaddr_set(&s4_sa, AF_INET, "10.0.0.1", 0);

	struct sockaddr_storage c6_sa = { 0 };
	struct sockaddr_storage s6_sa = { 0 };
	sockaddr_set(&c6_sa, AF_INET6, "2001:db8:8714:3a90::12", 0);
	sockaddr_set(&s6_sa, AF_INET6, "::1", 0);

	/* Client cookie generate. */
	client_generate(NULL,       &s4_sa,     secret, "NULL, IPv4",   KNOT_EINVAL, 0);
	client_generate(&c4_sa,     NULL,       secret, "IPv4, NULL",   KNOT_EINVAL, 0);
	client_generate(&c4_sa,     &s4_sa,     secret, "IPv4, IPv4",   KNOT_EOK, 0xde3832f4f59bf5ab);
	client_generate(&unspec_sa, &s4_sa,     secret, "unspec, IPv4", KNOT_EOK, 0x6b636ff225a1b340);
	client_generate(&c4_sa,     &unspec_sa, secret, "IPv4, unspec", KNOT_EOK, 0xd713ab1a81179bb3);

	/* Client cookie check. */
	client_check(NULL,   &s6_sa, secret, "no client addr",    8, 0xf99dbd02b69ab3c2, KNOT_EINVAL);
	client_check(&c6_sa, NULL,   secret, "no server addr",    8, 0xf99dbd02b69ab3c2, KNOT_EINVAL);
	client_check(&c6_sa, &s6_sa, NULL,   "no secret",         8, 0xf99dbd02b69ab3c2, KNOT_EINVAL);
	client_check(&c6_sa, &s6_sa, secret, "no cookie",         0, 0,                  KNOT_EINVAL);
	client_check(&c6_sa, &s6_sa, secret, "bad cookie length", 7, 0xf99dbd02b69ab3c2, KNOT_EINVAL);
	client_check(&c6_sa, &s6_sa, secret, "invalid cookie",    8, 0,                  KNOT_EINVAL);
	client_check(&c6_sa, &s6_sa, secret, "good cookie",       8, 0xf99dbd02b69ab3c2, KNOT_EOK);

	const knot_edns_cookie_t cc = {
		.data = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 },
		.len = 8
	};

	/* Server cookie generate. */
	knot_edns_cookie_t cc_part = cc; cc_part.len--;
	server_generate(NULL,       secret, &cc,      "NULL",        KNOT_EINVAL, 0);
	server_generate(&c4_sa,     secret, &cc_part, "cookie part", KNOT_EINVAL, 0);
	server_generate(&c4_sa,     secret, &cc,      "IPv4",        KNOT_EOK, 0x52f86bfcc98ded6);
	server_generate(&c6_sa,     secret, &cc,      "IPv6",        KNOT_EOK, 0x33ac6c9005acf469);
	server_generate(&unspec_sa, secret, &cc,      "unspec",      KNOT_EOK, 0x96df9dbf28f0f59e);

	/* Server cookie check. */
	server_check(NULL,   secret, "no addr",           8, 0x0706050403020100,
	                                                  8, 0x33ac6c9005acf469, KNOT_EINVAL);
	server_check(&c6_sa, NULL,   "no secret",         8, 0x0706050403020100,
	                                                  8, 0x33ac6c9005acf469, KNOT_EINVAL);
	server_check(&c6_sa, secret, "no client cookie",  0, 0,
	                                                  8, 0x33ac6c9005acf469, KNOT_EINVAL);
	server_check(&c6_sa, secret, "no server cookie",  8, 0x0706050403020100,
	                                                  0, 0,                  KNOT_EINVAL);
	server_check(&c6_sa, secret, "bad client cookie", 8, 0,
	                                                  8, 0x33ac6c9005acf469, KNOT_EINVAL);
	server_check(&c6_sa, secret, "bad server cookie", 8, 0x0706050403020100,
	                                                  8, 0,                  KNOT_EINVAL);
	server_check(&c6_sa, secret, "good cookie 1",     8, 0x0706050403020100,
	                                                  8, 0x33ac6c9005acf469, KNOT_EOK);

	return 0;
}
