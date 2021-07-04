/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*!
 * \file
 *
 * \brief Convenience header for including XDP-related stuff.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

#if ENABLE_XDP
#include "libknot/xdp/xdp.h"
#include "libknot/xdp/bpf-consts.h"
#include "libknot/xdp/eth.h"
#include "libknot/xdp/tcp.h"
#endif

/*! @} */
