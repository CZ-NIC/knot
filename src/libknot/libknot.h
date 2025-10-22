/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \brief Convenience header for including whole library.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

#include "libknot/version.h"
#include "libknot/attribute.h"
#include "libknot/cookies.h"
#include "libknot/codes.h"
#include "libknot/consts.h"
#include "libknot/descriptor.h"
#include "libknot/dname.h"
#include "libknot/dynarray.h"
#include "libknot/endian.h"
#include "libknot/errcode.h"
#include "libknot/error.h"
#include "libknot/lookup.h"
#include "libknot/mm_ctx.h"
#include "libknot/rdata.h"
#include "libknot/rdataset.h"
#include "libknot/rrset-dump.h"
#include "libknot/rrset.h"
#include "libknot/tsig-op.h"
#include "libknot/tsig.h"
#include "libknot/control/control.h"
#include "libknot/db/db.h"
#include "libknot/db/db_lmdb.h"
#include "libknot/db/db_trie.h"
#include "libknot/dnssec/binary.h"
#include "libknot/dnssec/crypto.h"
#include "libknot/dnssec/digest.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/keyid.h"
#include "libknot/dnssec/keystore.h"
#include "libknot/dnssec/keytag.h"
#include "libknot/dnssec/nsec.h"
#include "libknot/dnssec/pem.h"
#include "libknot/dnssec/random.h"
#include "libknot/dnssec/sign.h"
#include "libknot/dnssec/tsig.h"
#include "libknot/packet/compr.h"
#include "libknot/packet/pkt.h"
#include "libknot/packet/rrset-wire.h"
#include "libknot/packet/wire.h"
#include "libknot/probe/data.h"
#include "libknot/probe/probe.h"
#include "libknot/rrtype/dnskey.h"
#include "libknot/rrtype/ds.h"
#include "libknot/rrtype/naptr.h"
#include "libknot/rrtype/nsec.h"
#include "libknot/rrtype/nsec3.h"
#include "libknot/rrtype/nsec3param.h"
#include "libknot/rrtype/opt.h"
#include "libknot/rrtype/rdname.h"
#include "libknot/rrtype/rrsig.h"
#include "libknot/rrtype/soa.h"
#include "libknot/rrtype/svcb.h"
#include "libknot/rrtype/tsig.h"
#include "libknot/rrtype/zonemd.h"
#include "libknot/wire.h"

/*! @} */
