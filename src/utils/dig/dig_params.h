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
 * \file dig_params.h
 *
 * \author Daniel Salzman <daniel.salzman@nic.cz>
 *
 * \brief Dig command line parameters.
 *
 * \addtogroup knot_utils
 * @{
 */

#ifndef _DIG__DIG_PARAMS_H_
#define _DIG__DIG_PARAMS_H_

#include "utils/common/params.h"	// params_t

/*! \brief dig-specific params data. */
typedef struct {
} dig_params_t;
#define DIG_PARAM(p) ((dig_params_t*)p->d)

int host_params_parse(params_t *params, int argc, char *argv[]);
void host_params_clean(params_t *params);

#endif // _DIG__DIG_PARAMS_H_

/*! @} */
