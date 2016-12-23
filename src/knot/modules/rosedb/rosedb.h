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
 * The module provides a mean to override responses for certain queries before
 * the record is searched in the available zones.
 */

#pragma once

#include "knot/nameserver/query_module.h"

/*! \brief Module scheme. */
#define C_MOD_ROSEDB "\x0A""mod-rosedb"
extern const yp_item_t scheme_mod_rosedb[];
int check_mod_rosedb(conf_check_t *args);

/*! \brief Module interface. */
int rosedb_load(struct query_module *self);
void rosedb_unload(struct query_module *self);
