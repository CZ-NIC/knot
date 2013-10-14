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
 * \file cleanup.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief DNSSEC deinitialization
 *
 * \addtogroup dnssec
 * @{
 */

#ifndef _KNOT_DNSSEC_CLEANUP_H_
#define _KNOT_DNSSEC_CLEANUP_H_

#include <openssl/err.h>
#include <openssl/evp.h>

/*!
 * \brief Deinitialize OpenSSL library thread specific data.
 */
static inline void knot_dnssec_thread_cleanup(void)
{
	ERR_remove_state(0);
}

/*!
 * \brief Deinitialize OpenSSL library.
 */
static inline void knot_dnssec_cleanup(void)
{
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();

	knot_dnssec_thread_cleanup();
}

#endif // _KNOT_DNSSEC_CLEANUP_H_

/*! @} */
