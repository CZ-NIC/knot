/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
* \file
*
* \brief Error codes and function for getting error message.
*
* \addtogroup libknot
* @{
*/

#pragma once

#include "libknot/errcode.h"

/*!
 * \brief Returns error message for the given error code.
 *
 * \param code Error code.
 *
 * \return String containing the error message.
 */
const char *knot_strerror(int code);

/*! @} */
