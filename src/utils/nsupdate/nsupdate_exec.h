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
 * \file nsupdate_exec.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief
 *
 * \addtogroup knot_utils
 * @{
 */

#ifndef _NSUPDATE__NSUPDATE_EXEC_H_
#define _NSUPDATE__NSUPDATE_EXEC_H_

#include "utils/nsupdate/nsupdate_params.h"	// nsupdate_params_t

int nsupdate_exec(nsupdate_params_t *params);

#endif // _NSUPDATE__NSUPDATE_EXEC_H_

/*! @} */
