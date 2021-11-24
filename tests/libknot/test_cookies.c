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
		.server_addr = s_addr,
	};
	memcpy(params.secret, c_secret, sizeof(params.secret));

	knot_edns_cookie_t cc;
	int ret = knot_edns_cookie_client_generate(&cc, &params);
	is_int(code, ret, "client_generate ret: %s", msg);
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
	is_int(code, ret, "server_generate ret: %s", msg);
	if (ret == KNOT_EOK) {
		ok(sc.len == 16 && memcmp(sc.data, ref, sc.len) == 0,
		   "server_generate value: %s", msg);
	}
	return sc;
}

static void client_check(
	struct sockaddr_storage *s_addr, const uint8_t *secret,
	knot_edns_cookie_t *cc, const char *msg, int code)
{
	knot_edns_cookie_params_t params = {
		.server_addr = s_addr,
	};
	memcpy(params.secret, secret, sizeof(params.secret));

	int ret = knot_edns_cookie_client_check(cc, &params);
	is_int(code, ret, "client_check ret: %s", msg);
}

static void server_check(
	struct sockaddr_storage *c_addr, const uint8_t *secret,
	knot_edns_cookie_t *sc, knot_edns_cookie_t *cc, uint32_t timestamp,
	const char *msg, int code)
{
	knot_edns_cookie_params_t params = {
		.version = KNOT_EDNS_COOKIE_VERSION,
		.timestamp = timestamp,
		.lifetime_before = 3600,
		.lifetime_after = 300,
		.client_addr = c_addr,
	};
	memcpy(params.secret, secret, sizeof(params.secret));

	int ret = knot_edns_cookie_server_check(sc, cc, &params);
	is_int(code, ret, "server_check ret: %s", msg);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	knot_edns_cookie_t cc;
	knot_edns_cookie_t sc;

	const uint8_t c_secret1[] = "\x3F\x66\x51\xC9\x81\xC1\xD7\x3E\x58\x79\x25\xD2\xF9\x98\x5F\x08";
	const uint8_t c_secret2[] = "\x4C\x31\x15\x17\xFA\xB6\xBF\xE2\xE1\x49\xAB\x74\xEC\x1B\xC9\xA0";
	const uint8_t s_secret1[] = "\xE5\xE9\x73\xE5\xA6\xB2\xA4\x3F\x48\xE7\xDC\x84\x9E\x37\xBF\xCF";

	struct sockaddr_storage c4_sa1 = { 0 };
	struct sockaddr_storage c4_sa2 = { 0 };
	struct sockaddr_storage s4_sa = { 0 };
	sockaddr_set(&c4_sa1,  AF_INET, "198.51.100.100", 0);
	sockaddr_set(&c4_sa2, AF_INET, "203.0.113.203", 0);
	sockaddr_set(&s4_sa,  AF_INET, "192.0.2.53", 0);

	struct sockaddr_storage c6_sa = { 0 };
	struct sockaddr_storage s6_sa = { 0 };
	sockaddr_set(&c6_sa, AF_INET6, "2001:db8:220:1:59de:d0f4:8769:82b8", 0);
	sockaddr_set(&s6_sa, AF_INET6, "2001:db8:8f::53", 0);

	const uint8_t c_secret6[] = "\x3B\x49\x5B\xA6\xA5\xB7\xFD\x87\x73\x5B\xD5\x8F\x1E\xF7\x26\x1D";
	const uint8_t s_secret6[] = "\xDD\x3B\xDF\x93\x44\xB6\x78\xB1\x85\xA6\xF5\xCB\x60\xFC\xA7\x15";
	const uint8_t s_secret7[] = "\x44\x55\x36\xBC\xD2\x51\x32\x98\x07\x5A\x5D\x37\x96\x63\xC9\x62";

	// Learning a new Server Cookie

	cc = client_generate(&s4_sa, c_secret1, "IPv4", KNOT_EOK,
	                     "\x24\x64\xC4\xAB\xCF\x10\xC9\x57");
	client_check(&s4_sa, c_secret1, &cc, "IPv4", KNOT_EOK);
	sc = server_generate(&c4_sa1, s_secret1, 1559731985, &cc, "IPv4", KNOT_EOK,
	                     "\x01\x00\x00\x00\x5C\xF7\x9F\x11\x1F\x81\x30\xC3\xEE\xE2\x94\x80");
	server_check(&c4_sa1, s_secret1, &sc, &cc, 1559731985, "IPv4", KNOT_EOK);

	// The same client learning a renewed (fresh) Server Cookie

	server_generate(&c4_sa1, s_secret1, 1559734385, &cc, "IPv4", KNOT_EOK,
	                "\x01\x00\x00\x00\x5C\xF7\xA8\x71\xD4\xA5\x64\xA1\x44\x2A\xCA\x77");

	// Another client learning a renewed Server Cookie

	cc = client_generate(&s4_sa, c_secret2, "IPv4", KNOT_EOK,
	                     "\xFC\x93\xFC\x62\x80\x7D\xDB\x86");
	char *sc_reserved = "\x01\xAB\xCD\xEF\x5C\xF7\x8F\x71\xA3\x14\x22\x7B\x66\x79\xEB\xF5";
	memcpy(sc.data, sc_reserved, strlen(sc_reserved));
	server_check(&c4_sa2, s_secret1, &sc, &cc, 1559727985, "IPv4", KNOT_EOK);

	// Version check

	sc.data[0] = 10;
	server_check(&c4_sa2, s_secret1, &sc, &cc, 1559727985, "version", KNOT_ENOTSUP);

	// IPv6 query with rolled over secret

	cc = client_generate(&s6_sa, c_secret6, "IPv6", KNOT_EOK,
	                     "\x22\x68\x1A\xB9\x7D\x52\xC2\x98");
	client_check(&s6_sa, c_secret6, &cc, "IPv6", KNOT_EOK);
	sc = server_generate(&c6_sa, s_secret6, 1559741817, &cc, "IPv6", KNOT_EOK,
	                     "\x01\x00\x00\x00\x5C\xF7\xC5\x79\x26\x55\x6B\xD0\x93\x4C\x72\xF8");
	server_check(&c6_sa, s_secret6, &sc, &cc, 1559741961, "IPv6", KNOT_EOK);
	sc = server_generate(&c6_sa, s_secret7, 1559741961, &cc, "IPv6", KNOT_EOK,
	                     "\x01\x00\x00\x00\x5C\xF7\xC6\x09\xA6\xBB\x79\xD1\x66\x25\x50\x7A");

	// Past lifetime check

	server_check(&c6_sa, s_secret7, &sc, &cc, 1559741961 + 3600, "last old", KNOT_EOK);
	server_check(&c6_sa, s_secret7, &sc, &cc, 1559741961 + 3601, "too old", KNOT_ERANGE);

	// Future lifetime check

	server_check(&c6_sa, s_secret7, &sc, &cc, 1559741961 - 300, "last new", KNOT_EOK);
	server_check(&c6_sa, s_secret7, &sc, &cc, 1559741961 - 301, "too new", KNOT_ERANGE);

	return 0;
}
