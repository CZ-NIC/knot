/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdlib.h>				// EXIT_FAILURE

#include "dnssec/crypto.h"			// dnssec_crypto_init
#include "libknot/errcode.h"			// KNOT_EOK
#include "utils/nsupdate/nsupdate_exec.h"	// host_exec
#include "utils/nsupdate/nsupdate_params.h"	// params_t

int main(int argc, char *argv[])
{

	int ret = EXIT_SUCCESS;

	nsupdate_params_t params;
	if (nsupdate_parse(&params, argc, argv) == KNOT_EOK) {
		dnssec_crypto_init();
		if (!params.stop && nsupdate_exec(&params) != KNOT_EOK) {
			ret = EXIT_FAILURE;
		}
		dnssec_crypto_cleanup();
	} else {
		ret = EXIT_FAILURE;
	}

	nsupdate_clean(&params);
	return ret;
}
