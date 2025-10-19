/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdlib.h>

#include "libknot/dnssec/crypto.h"
#include "utils/kdig/kdig_params.h"
#include "utils/kdig/kdig_exec.h"
#include "libknot/libknot.h"

int main(int argc, char *argv[])
{
	int ret = EXIT_SUCCESS;

	tzset();

	kdig_params_t params;
	if (kdig_parse(&params, argc, argv) == KNOT_EOK) {
		if (!params.stop) {
			dnssec_crypto_init();
			if (kdig_exec(&params) != KNOT_EOK) {
				ret = EXIT_FAILURE;
			}
			dnssec_crypto_cleanup();
		}
	} else {
		ret = EXIT_FAILURE;
	}

	kdig_clean(&params);
	return ret;
}
