/*!
 * \file rosedb.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Static resource records
 *
 * Accepted configurations:
 *  * "<path_to_database>"
 *
 * The module provides a mean to override responses for certain queries before
 * the record is searched in the available zones.
 *
 * \addtogroup query_processing
 * @{
 */
/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/*! \brief Module interface. */
int rosedb_load(struct query_plan *plan, struct query_module *self);
int rosedb_unload(struct query_module *self);

/*! @} */
