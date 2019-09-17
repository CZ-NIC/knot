/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <time.h>

#include "libknot/cookies.h"
#include "libknot/endian.h"
#include "libknot/errcode.h"
#include "contrib/sockaddr.h"

static knot_edns_cookie_t client_generate(
	struct sockaddr_storage *s_addr, const uint8_t *c_secret,
	const char *msg, int code, const char *ref)
{
	knot_edns_cookie_params_t params = {
		.version = KNOT_EDNS_COOKIE_VERSION,
		.server_addr = s_addr,
	};
	memcpy(params.secret, c_secret, sizeof(params.secret));

	knot_edns_cookie_t cc;
	int ret = knot_edns_cookie_client_generate(&cc, &params);
	is_int(ret, code, "client_generate ret: %s", msg);
	if (ret == KNOT_EOK) {
		ok(cc.len == KNOT_EDNS_COOKIE_CLNT_SIZE && memcmp(cc.data, ref, cc.len) == 0,
		   "client_generate value: %s", msg);
	}
	return cc;
}

static knot_edns_cookie_t server_generate(
	struct sockaddr_storage *c_addr, const uint8_t *s_secret, uint32_t timestamp,
	const knot_edns_cookie_t *cc, const char *msg, int code, const char *ref)
{
	knot_edns_cookie_params_t params = {
		.version = KNOT_EDNS_COOKIE_VERSION,
		.timestamp = timestamp,
		.client_addr = c_addr,
	};
	memcpy(params.secret, s_secret, sizeof(params.secret));

	knot_edns_cookie_t sc;
	int ret = knot_edns_cookie_server_generate(&sc, cc, &params);
	is_int(ret, code, "server_generate ret: %s", msg);
	if (ret == KNOT_EOK) {
		ok(sc.len == 16 && memcmp(sc.data, ref, sc.len) == 0,
		   "server_generate value: %s", msg);
	}
	return sc;
}

static void client_check(struct sockaddr_storage *c_addr, struct sockaddr_storage *s_addr,
                         const uint8_t *secret, const char *msg, uint16_t le_cc_len,
                         uint64_t le_cc, int code)
{
	knot_edns_cookie_params_t params = {
		.client_addr = c_addr,
		.server_addr = s_addr,
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
		.client_addr = c_addr,
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

	knot_edns_cookie_t cc;

	const uint8_t c_secret1[] = "\x3F\x66\x51\xC9\x81\xC1\xD7\x3E\x58\x79\x25\xD2\xF9\x98\x5F\x08";
	const uint8_t s_secret1[] = "\xE5\xE9\x73\xE5\xA6\xB2\xA4\x3F\x48\xE7\xDC\x84\x9E\x37\xBF\xCF";

	struct sockaddr_storage c4_sa = { 0 };
	struct sockaddr_storage s4_sa = { 0 };
	sockaddr_set(&c4_sa, AF_INET, "198.51.100.100", 0);
	sockaddr_set(&s4_sa, AF_INET, "192.0.2.53", 0);

	cc = client_generate(&s4_sa, c_secret1, "IPv4", KNOT_EOK,
	                     "\x24\x64\xC4\xAB\xCF\x10\xC9\x57");
	server_generate(&c4_sa, s_secret1, 1559731985, &cc, "IPv4", KNOT_EOK,
	                "\x01\x00\x00\x00\x5C\xF7\x9F\x11\x1F\x81\x30\xC3\xEE\xE2\x94\x80");
	server_generate(&c4_sa, s_secret1, 1559734385, &cc, "IPv4", KNOT_EOK,
	                "\x01\x00\x00\x00\x5C\xF7\xA8\x71\xD4\xA5\x64\xA1\x44\x2A\xCA\x77");

	/*
	sockaddr_set(&c4_sa, AF_INET, "203.0.113.203", 0);

	cc = client_generate(&s4_sa, c_secret, "IPv4", KNOT_EOK,
	                     "\xFC\x93\xFC\x62\x80\x7D\xDB\x86");
//	server_generate(&c4_sa, s_secret, 1559731985, &cc, "IPv4", KNOT_EOK,
//	                "\x01\x00\x00\x00\x5C\xF7\x9F\x11\x1F\x81\x30\xC3\xEE\xE2\x94\x80");
*/


	struct sockaddr_storage c6_sa = { 0 };
	struct sockaddr_storage s6_sa = { 0 };
	sockaddr_set(&c6_sa, AF_INET6, "2001:db8:220:1:59de:d0f4:8769:82b8", 0);
	sockaddr_set(&s6_sa, AF_INET6, "2001:db8:8f::53", 0);

	const uint8_t c_secret6[] = "\x3B\x49\x5B\xA6\xA5\xB7\xFD\x87\x73\x5B\xD5\x8F\x1E\xF7\x26\x1D";
	const uint8_t s_secret6[] = "\xDD\x3B\xDF\x93\x44\xB6\x78\xB1\x85\xA6\xF5\xCB\x60\xFC\xA7\x15";
	const uint8_t s_secret7[] = "\x44\x55\x36\xBC\xD2\x51\x32\x98\x07\x5A\x5D\x37\x96\x63\xC9\x62";

	cc = client_generate(&s6_sa, c_secret6, "IPv6", KNOT_EOK,
	                     "\x22\x68\x1A\xB9\x7D\x52\xC2\x98");
	server_generate(&c6_sa, s_secret7, 1559741961, &cc, "IPv6", KNOT_EOK,
	                "\x01\x00\x00\x00\x5C\xF7\xC6\x09\xA6\xBB\x79\xD1\x66\x25\x50\x7A");


#if 0
	/* Client cookie generate. */
	/*
	client_generate(&s4_sa,     secret, "IPv4",   KNOT_EINVAL, 0);
	client_generate(NULL,       secret, "NULL",   KNOT_EINVAL, 0);
	client_generate(&s4_sa,     secret, "IPv4",   KNOT_EOK, 0xde3832f4f59bf5ab);
	*/
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
#endif
	return 0;
}
