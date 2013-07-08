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

#ifndef _KNOT_LIBKNOT_H_
#define _KNOT_LIBKNOT_H_

#include "consts.h"
#include "dname.h"
#include "edns.h"
#include "nsec3.h"
#include "packet/packet.h"
#include "packet/query.h"
#include "packet/response.h"
#include "rrset.h"
#include "rrset-dump.h"
#include "sign/key.h"
#include "sign/sig0.h"
#include "tsig.h"
#include "tsig-op.h"
#include "util/tolower.h"
#include "util/utils.h"
#include "util/wire.h"
#include "zone/node.h"
#include "zone/zone.h"
#include "zone/zonedb.h"

#endif

/*! @} */
