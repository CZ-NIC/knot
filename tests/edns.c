/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <config.h>
#include <tap/basic.h>

#include "common/errcode.h"
#include "libknot/edns.h"

static const uint16_t EDNS_FLAGS = KNOT_EDNS_FLAGS_DO;
static const uint16_t E_MAX_PLD = 10000;
static const uint8_t E_VERSION = 1;
static const char *E_NSID_STR = "FooBar";
static const uint16_t E_NSID_LEN = strlen(E_NSID_STR);

static bool opt_rr_ok(knot_rrset_t *opt_rr, knot_edns_params_t *params)
{
	/* TODO */
	return true;
}

int main(int argc, char *argv[])
{
	plan(5);

	/* Creating EDNS params structure with given data. */

	knot_edns_params_t *edns_params =
		knot_edns_new_params(E_MAX_PLD, E_VERSION, E_FLAGS, E_NSID_LEN,
	                             E_NSID_STR);
	ok(edns_params != NULL, "EDNS params: new");

	/* Check that all parameters are properly set. */
	ok(edns_params->payload == E_MAX_PLD
	   && edns_params->version == E_VERSION
	   && edns_params->flags == E_FLAGS
	   && edns_params->nsid_len == E_NSID_LEN
	   && memcmp(edns_params->nsid, E_NSID_STR, E_NSID_LEN) == 0,
	   "EDNS params: parameter values");

	/* Creating OPT RR from params. */
	knot_rrset_t *opt_rr = NULL;
	ret = knot_edns_init_from_params(opt_rr, edns_params, true, NULL);
	ok(ret == KNOT_EOK, "OPT RR: init from params");

	ok(opt_rr_ok(opt_rr, edns_params), "OPT RR: initialized values");

	/* Getters / setters */
	/* TODO */

	/* Adding option */


	/* Free the parameters. */
	knot_edns_free_params(&edns_params);
	ok(edns_params == NULL, "EDNS params: free");


	return 0;
}
