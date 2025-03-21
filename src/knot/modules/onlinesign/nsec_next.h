/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libknot/dname.h"

/*!
 * \brief Get the very next possible name in NSEC chain.
 *
 * \param dname  Current dname in the NSEC chain.
 * \param apex   Zone apex name, used when we reach the end of the chain.
 *
 * \return Successor of dname in the NSEC chain.
 */
knot_dname_t *online_nsec_next(const knot_dname_t *dname, const knot_dname_t *apex);
