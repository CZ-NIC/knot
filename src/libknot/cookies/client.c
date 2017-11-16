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

#include <string.h>

#include "libknot/attribute.h"
#include "libknot/cookies/client.h"
#include "libknot/errcode.h"
#include "libknot/rrtype/opt-cookie.h"
#include "contrib/string.h"

_public_
bool knot_cc_input_is_valid(const struct knot_cc_input *input)
{
	/*
	 * RFC7873 4.1 -- Client cookie should be generated from
	 * client IP address, server IP address and a secret quantity.
	 */

	return input && (input->clnt_sockaddr || input->srvr_sockaddr) &&
	       input->secret_data && input->secret_len > 0;
}

_public_
int knot_cc_check(const uint8_t *cc, uint16_t cc_len,
                  const struct knot_cc_input *input,
                  const struct knot_cc_alg *cc_alg)
{
	if (!cc || cc_len == 0 || !input ||
	    !cc_alg || !cc_alg->cc_size || !cc_alg->gen_func) {
		return KNOT_EINVAL;
	}

	if (cc_alg->cc_size > KNOT_OPT_COOKIE_CLNT) {
		return KNOT_EINVAL;
	}

	uint8_t generated_cc[KNOT_OPT_COOKIE_CLNT] = { 0 };
	uint16_t generated_cc_len = KNOT_OPT_COOKIE_CLNT;

	generated_cc_len = cc_alg->gen_func(input, generated_cc, generated_cc_len);
	if (generated_cc_len != cc_len) {
		return KNOT_EINVAL;
	}

	int ret = const_time_memcmp(cc, generated_cc, generated_cc_len);
	if (ret != 0) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}
