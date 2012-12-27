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
 * \file host_exec.h
 *
 * \author Daniel Salzman <daniel.salzman@nic.cz>
 *
 * \brief
 *
 * \addtogroup knot_utils
 * @{
 */

#ifndef _HOST__HOST_EXEC_H_
#define _HOST__HOST_EXEC_H_

#include <stdbool.h>			// bool
#include <stdint.h>			// uint16_t

#include "utils/host/host_params.h"

int host_exec(const host_params_t *params);

#endif // _HOST__HOST_EXEC_H_

/*! @} */
