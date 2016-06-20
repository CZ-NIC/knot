/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
#include "libknot/binary.h"
#include "libknot/codes.h"
#include "libknot/consts.h"
#include "libknot/descriptor.h"
#include "libknot/dname.h"
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
#include "libknot/packet/compr.h"
#include "libknot/packet/pkt.h"
#include "libknot/packet/rrset-wire.h"
#include "libknot/packet/wire.h"
#include "libknot/rrtype/aaaa.h"
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
#include "libknot/rrtype/tsig.h"
#include "libknot/rrtype/txt.h"

/*! @} */
