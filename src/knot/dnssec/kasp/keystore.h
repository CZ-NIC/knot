/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libdnssec/keystore.h"

int keystore_load(const char *config, unsigned backend,
                  const char *kasp_base_path, dnssec_keystore_t **keystore);
