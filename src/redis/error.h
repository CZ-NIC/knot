/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#define RDB_E(str)	("ERR " str)

#define RDB_EALLOC	RDB_E("failed to allocate memory")
#define RDB_ECOMPAT	RDB_E("incompatible module version")
#define RDB_ECORRUPTED	RDB_E("corrupted metadata")
#define RDB_EEVENT	RDB_E("failed to emit event")
#define RDB_EINST	RDB_E("invalid instance")
#define RDB_EMALF	RDB_E("malformed data")
#define RDB_ENOSOA	RDB_E("missing SOA")
#define RDB_EPARSE	RDB_E("failed to parse")
#define RDB_ESEMCHECK	RDB_E("semantic check failed")
#define RDB_ETXN	RDB_E("invalid transaction")
#define RDB_ETXN_MANY	RDB_E("too many transactions")
#define RDB_EZONE	RDB_E("unknown zone")
