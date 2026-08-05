/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libknot/dnssec/sample_keys.h"
#include "utils/keymgr/functions.h"

extern const key_parameters_t *KEYS[];

int keymgr_keystore_test(const char *keystore_id, keymgr_list_params_t *params);

int keymgr_keystore_bench(const char *keystore_id, keymgr_list_params_t *params,
                          uint16_t threads, int algorithm);
