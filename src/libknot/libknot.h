/*!
 * \file libknot.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Convenience header for including whole library.
 *
 * \addtogroup libknot
 * @{
 */
/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "libknot/consts.h"
#include "libknot/dname.h"
#include "libknot/descriptor.h"
#include "libknot/errcode.h"
#include "libknot/mempattern.h"
#include "libknot/rrtype/opt.h"
#include "libknot/packet/wire.h"
#include "libknot/packet/compr.h"
#include "libknot/packet/pkt.h"
#include "libknot/rdataset.h"
#include "libknot/rrset.h"
#include "libknot/rrset-dump.h"
#include "libknot/rrtype/rdname.h"
#include "libknot/rrtype/dnskey.h"
#include "libknot/rrtype/nsec3.h"
#include "libknot/rrtype/nsec3param.h"
#include "libknot/rrtype/nsec5.h"
#include "libknot/rrtype/nsec5key.h"
#include "libknot/rrtype/nsec.h"
#include "libknot/rrtype/rrsig.h"
#include "libknot/rrtype/soa.h"
#include "libknot/rrtype/tsig.h"
#include "libknot/tsig-op.h"
#include "libknot/util/tolower.h"
#include "libknot/util/utils.h"

/*! @} */
