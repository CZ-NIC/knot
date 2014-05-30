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
/*!
 * \file crypto.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief Cryptographic backend initialization and clean up.
 *
 * \addtogroup dnssec
 * @{
 */

#pragma once

/*!
 * \brief Initialize cryptographic backend.
 */
void knot_crypto_init(void);

/*!
 * \brief Clean up data allocated by cryptographic backend.
 */
void knot_crypto_cleanup(void);

/*!
 * \brief Clean up thread specific data allocated by cryptographic backend.
 */
void knot_crypto_cleanup_thread(void);

/*!
 * \brief Initialize data required for thread-safety of cryptographic backend.
 *
 * \note Does not include actions performed by knot_crypto_init().
 */
void knot_crypto_init_threads(void);

/*!
 * \brief Clean up allocated data required for thread-safety of crypto backend.
 */
void knot_crypto_cleanup_threads(void);

/*!
 * \brief Load pluggable crypto engines.
 */
void knot_crypto_load_engines(void);

/*!
 * \brief Unload pluggable crypto engines.
 */
void knot_crypto_unload_engines(void);

/*! @} */
