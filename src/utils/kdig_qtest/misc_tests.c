/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <ngtcp2/ngtcp2.h>

#include "contrib/net.h"
#include "contrib/ucw/lists.h"
#include "knot/server/handler.h"
#include "libknot/errcode.h"
#include "utils/kdig_qtest/qtest_quic.h"
#include "utils/common/msg.h"
#include "utils/kdig_qtest/qtest_kdig_params.h"
#include "utils/kdig_qtest/qtest_params.h"


int increment_blank_conns(void)
{
	list_t *conns = NULL;
	init_list(conns);

	if (!conns) {
		return KNOT_ERROR;
	}

	size_t conn_count = 0;
	while (true) {
		size_t i = 0;
		for (; i < conn_count; i++) {
			/* ping and fetch */
		}

		/* create new conn and check if succesfull, here
		 * we will eventually reach the limit of conns.
		 * At that point if all the continually pinged conns
		 * are still alive and the next conn fails to be created
		 * the attack has either been successfull, or the server
		 * refused to open other conns from our address.
		 * The latter would be a somewhat good protection
		 * agains this attack. */
	}
}
