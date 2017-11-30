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

#include <assert.h>
#include <string.h>

#include "libknot/attribute.h"
#include "libknot/cookies/client.h"
#include "libknot/errcode.h"
#include "libknot/rrtype/opt-cookie.h"
#include "contrib/string.h"
#include "contrib/sockaddr.h"

_public_
bool knot_cc_input_is_valid(const struct knot_cc_input *input)
{
	/*
	 * RFC7873 4.1 -- Client cookie should be generated from
	 * client IP address, server IP address and a secret quantity.
	 */

	return input && (input->clnt_sockaddr || input->srvr_sockaddr);
}

static uint64_t generate_client_cookie(const struct knot_cc_input *input)
{
	SIPHASH_CTX ctx;
	SipHash24_Init(&ctx, &input->secret);

	if (input->clnt_sockaddr) {
		size_t addr_len = 0;
		void *addr = sockaddr_raw(input->clnt_sockaddr, &addr_len);
		SipHash24_Update(&ctx, addr, addr_len);
	}

	if (input->srvr_sockaddr) {
		size_t addr_len = 0;
		void *addr = sockaddr_raw(input->srvr_sockaddr, &addr_len);
		SipHash24_Update(&ctx, addr, addr_len);
	}

	return SipHash24_End(&ctx);
}

_public_
int knot_cc_check(const uint8_t *cc, uint16_t cc_len,
                  const struct knot_cc_input *input)
{
	if (!cc || cc_len != KNOT_OPT_COOKIE_CLNT || !knot_cc_input_is_valid(input)) {
		return KNOT_EINVAL;
	}

	uint64_t generated_cc = generate_client_cookie(input);
	assert(sizeof(generated_cc) == KNOT_OPT_COOKIE_CLNT);

	int ret = const_time_memcmp(cc, &generated_cc, KNOT_OPT_COOKIE_CLNT);
	if (ret != 0) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}
