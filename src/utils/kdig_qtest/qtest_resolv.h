/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "utils/kdig_qtest/qtest_netio.h"
#include "contrib/ucw/lists.h"

srv_info_t* parse_nameserver(const char *str, const char *def_port);

void get_nameservers(list_t *servers, const char *def_port);

