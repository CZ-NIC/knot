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
 * \file prng.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Pseudo-random number generator interface.
 *
 * Interface for accessing underlying PRNG.
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef _KNOTD_PRNG_H_
#define _KNOTD_PRNG_H_

/*!
 * \brief Get pseudorandom number from PRNG initialized in thread-local storage.
 *
 * No need for initialization, TLS will take care of it.
 *
 * \retval Pseudorandom number.
 */
double tls_rand();

#endif //_KNOTD_ACL_H_

/*! @} */
