/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "./kru.inc.c"

const struct kru_api KRU_GENERIC = KRU_API_INITIALIZER;
struct kru_api KRU = KRU_API_INITIALIZER; // generic version is the default
