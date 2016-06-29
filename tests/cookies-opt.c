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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tap/basic.h>

#include "libknot/consts.h"
#include "libknot/errcode.h"
#include "libknot/rrtype/opt.h"
#include "libknot/rrtype/opt-cookie.h"

const char *cookie_opts[] = {
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
	plan_lazy();

	uint16_t code;
	uint16_t data_len;
	const uint8_t *data;
	int ret;

	const uint8_t *cc, *sc;
	uint16_t cc_len, sc_len;

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

	const void *DUMMYPTR = (void *)1;
	const int DUMMYVAL = 1;

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

	return 0;
}
