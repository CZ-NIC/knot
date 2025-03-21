/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "utils/kdig/kdig_params.h"

int khost_parse(kdig_params_t *params, int argc, char *argv[]);
void khost_clean(kdig_params_t *params);
