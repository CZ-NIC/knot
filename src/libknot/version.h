/*!
 * \file libknot.h
 *
 * \author Ondřej Surý <ondrej.sury@nic.cz>
 *
 * \brief Convenience header with version number
 *
 * \addtogroup libknot
 * @{
 */
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

#pragma once

/* Version information.  This gets parsed by build scripts as well as
 * gcc so each #define line in this group must also be splittable on
 * whitespace, take the form LIBKNOT_*_VERSION and contain the magical
 * trailing comment. */
#define LIBKNOT_VERSION_MAJOR    2
#define LIBKNOT_VERSION_MINOR    1
#define LIBKNOT_VERSION_PATCH    0
#define LIBKNOT_VERSION_EXTRA    "-dev"

#define LIBKNOT_VERSION_HEX  ((LIBKNOT_VERSION_MAJOR << 16) | \
			      (LIBKNOT_VERSION_MINOR <<  8) | \
			      (LIBKNOT_VERSION_PATCH))
/* End parsable section. */

/*! @} */
