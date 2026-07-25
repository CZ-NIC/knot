/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdbool.h>
#include <stdio.h>

int mdb_dump(const char *db_path, FILE *out, bool alldbs);
