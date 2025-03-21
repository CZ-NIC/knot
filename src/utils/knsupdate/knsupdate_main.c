/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdlib.h>

#include "libdnssec/crypto.h"
#include "utils/knsupdate/knsupdate_exec.h"
#include "utils/knsupdate/knsupdate_params.h"
#include "libknot/libknot.h"

int main(int argc, char *argv[])
{

	int ret = EXIT_SUCCESS;

	tzset();

	knsupdate_params_t params;
	if (knsupdate_parse(&params, argc, argv) == KNOT_EOK) {
		if (!params.stop) {
			dnssec_crypto_init();
			if (knsupdate_exec(&params) != KNOT_EOK) {
				ret = EXIT_FAILURE;
			}
			dnssec_crypto_cleanup();
		}
	} else {
		ret = EXIT_FAILURE;
	}

	knsupdate_clean(&params);
	return ret;
}
