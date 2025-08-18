/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#define RDB_E(str)	("ERR " # str)

#define RDB_EALLOC	RDB_E("failed to allocate memory")
#define RDB_ECOMPAT	RDB_E("incompatible module version")
#define RDB_EINST	RDB_E("invalid instance")
#define RDB_EMALF	RDB_E("malformed data")
#define RDB_ERANGE	RDB_E("value out of range")
#define RDB_ETXN	RDB_E("invalid transaction")
