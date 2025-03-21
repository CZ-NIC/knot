/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
