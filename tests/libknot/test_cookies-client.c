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
#include "libknot/cookies/client.h"
#include "libknot/cookies/client.c"
#include "libknot/errcode.h"

int main(int argc, char *argv[])
{
	plan_lazy();

	int ret;

	SIPHASH_KEY secret = {
		.k0 = htole64(0xDEADBEEFFACE),
		.k1 = htole64(0xFACEDEADBEEF)
	};

	uint64_t hash;


	struct knot_cc_input cc_in = { 0 };

	struct sockaddr_storage unspec_sa = { 0 };

	struct sockaddr_storage c4_sa = { 0 };
	struct sockaddr_storage s4_sa = { 0 };
	sockaddr_set(&c4_sa, AF_INET, "127.0.0.1", 0);
	sockaddr_set(&s4_sa, AF_INET, "10.0.0.1", 0);

	struct sockaddr_storage c6_sa = { 0 };
	struct sockaddr_storage s6_sa = { 0 };
	sockaddr_set(&c6_sa, AF_INET6, "2001:db8:8714:3a90::12", 0);
	sockaddr_set(&s6_sa, AF_INET6, "::1", 0);

	/* Client cookie hash algorithm. */

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s4_sa;
	cc_in.secret = secret;
	hash = generate_client_cookie(&cc_in);
	{
		uint64_t expected = 0xde3832f4f59bf5ab;
		ok(hash == expected, "cookies: SipHash client cookie content");
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = NULL;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s4_sa;
	cc_in.secret = secret;
	hash = generate_client_cookie(&cc_in);
	{
		uint64_t expected = 0x6b636ff225a1b340;
		ok(hash == expected, "cookies: SipHash client cookie content");
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&unspec_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s4_sa;
	cc_in.secret = secret;
	hash = generate_client_cookie(&cc_in);
	{
		uint64_t expected = 0x6b636ff225a1b340;
		ok(hash == expected, "cookies: SipHash client cookie content");
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	cc_in.srvr_sockaddr = NULL;
	cc_in.secret = secret;
	hash = generate_client_cookie(&cc_in);
	{
		uint64_t expected = 0xd713ab1a81179bb3;
		ok(hash == expected, "cookies: SipHash client cookie content");
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c4_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&unspec_sa;
	cc_in.secret = secret;
	hash = generate_client_cookie(&cc_in);
	{
		uint64_t expected = 0xd713ab1a81179bb3;
		ok(hash == expected, "cookies: SipHash client cookie content");
	}

	/* Client cookie check. */

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s6_sa;
	cc_in.secret = secret;
	{
		ret = knot_cc_check(NULL, 0, &cc_in);
		is_int(KNOT_EINVAL, ret, "cookies: SipHash client cookie check no cookie");
	}

	{
		uint8_t cookie[] = { 0xaf, 0xe5, 0x17, 0x94, 0x80, 0xa6, 0x0c, 0x33 };
		ret = knot_cc_check(cookie, sizeof(cookie), NULL);
		is_int(KNOT_EINVAL, ret, "cookies: SipHash client cookie check no input");
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s6_sa;
	cc_in.secret = secret;
	{
		uint64_t cookie = 0xf99dbd02b69ab3c2;
		ret = knot_cc_check((const uint8_t *)&cookie, sizeof(cookie), &cc_in);
		is_int(KNOT_EOK, ret, "cookies: SipHash client good cookie check");
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s6_sa;
	cc_in.secret = secret;
	{
		uint64_t cookie = 0xf99dbd02b69ab3c2;
		ret = knot_cc_check((const uint8_t *)&cookie, sizeof(cookie) - 1, &cc_in);
		is_int(KNOT_EINVAL, ret, "cookies: SipHash client cookie check invalid length");
	}

	memset(&cc_in, 0, sizeof(cc_in));
	cc_in.clnt_sockaddr = (struct sockaddr *)&c6_sa;
	cc_in.srvr_sockaddr = (struct sockaddr *)&s6_sa;
	cc_in.secret = secret;
	{
		uint8_t cookie[] = { 0xaf, 0xe5, 0x17, 0x94, 0x80, 0xa6, 0x0c, 0x32 };
		ret = knot_cc_check((const uint8_t *)&cookie, sizeof(cookie), &cc_in);
		is_int(KNOT_EINVAL, ret, "cookies: SipHash client cookie check invalid cookie");
	}
}
