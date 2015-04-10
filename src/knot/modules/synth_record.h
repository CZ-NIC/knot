/*!
 * \file synth_record.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Synthetic records module
 *
 * Accepted configurations:
 *  * "forward <prefix> <ttl> <address>/<netblock>"
 *  * "reverse <prefix> <zone> <ttl> <address>/<netblock>"
 *
 * Module synthetises forward/reverse records based on a template when
 * the queried record can't be found in the zone contents.
 *
 * \addtogroup query_processing
 * @{
 */
/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/nameserver/query_module.h"

/*! \brief Module scheme. */
#define C_MOD_SYNTH_RECORD "\x10""mod-synth-record"
extern const yp_item_t scheme_mod_synth_record[];

/*! \brief Module interface. */
int synth_record_load(struct query_plan *plan, struct query_module *self);
int synth_record_unload(struct query_module *self);

/*! @} */
