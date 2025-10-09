/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "libdnssec/crypto.h"
#include "utils/kdig_qtest/qtest_kdig_params.h"
#include "utils/kdig_qtest/qtest_kdig_exec.h"
#include "libknot/libknot.h"

static void  null_test_success(void **state) {
	(void) state;
}

int main(int argc, char *argv[]) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(null_test_success),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);

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

