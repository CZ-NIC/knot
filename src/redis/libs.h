/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: LGPL-2.1-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libknot/attribute.h"
#undef _public_
#define _public_ _hidden_

#include "contrib/base32hex.c"
#include "contrib/base64.c"
#include "contrib/mempattern.c"
#include "contrib/musl/inet_ntop.c"
#include "contrib/openbsd/strlcat.c"
#include "contrib/openbsd/strlcpy.c"
#include "contrib/sockaddr.c"
#include "contrib/string.c"
#include "contrib/time.c"
#include "contrib/ucw/mempool.c"
#include "libknot/codes.c"
#include "libknot/descriptor.c"
#include "libknot/dname.c"
#include "libknot/mm_ctx.h"
#include "libknot/rdataset.c"
#include "libknot/rrset-dump.c"
#include "libknot/rrset.c"
#include "libknot/rrtype/naptr.c"
#include "libknot/rrtype/opt.c"
#include "libknot/rrtype/soa.h"
#include "libzscanner/error.c"
#include "libzscanner/functions.c"
#include "libzscanner/scanner.c.t0"

// Add a dummy symbol for unused but called function in rrset-dump.c.
int dnssec_keytag(const dnssec_binary_t *rdata, uint16_t *keytag)
{
	return KNOT_ENOTSUP;
}
