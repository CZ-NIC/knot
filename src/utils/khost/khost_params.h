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
/*!
 * \file khost_params.h
 *
 * \author Daniel Salzman <daniel.salzman@nic.cz>
 *
 * \brief khost command line parameters.
 *
 * \addtogroup knot_utils
 * @{
 */

#pragma once

#include "utils/kdig/kdig_params.h"

int khost_parse(kdig_params_t *params, int argc, char *argv[]);
void khost_clean(kdig_params_t *params);

/*! @} */
