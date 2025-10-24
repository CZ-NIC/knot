/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \addtogroup crypto
 *
 * \brief Cryptographic backend initialization.
 *
 * For most cryptographic operations, the library requires global
 * initialization. Also, if the application creates a subprocess, the
 * library has to be reinitialized in the child process after \c fork().
 *
 * @{
 */

#pragma once

/*!
 * Initialize cryptographic backend.
 */
void dnssec_crypto_init(void);

/*!
 * Reinitialize cryptographic backend.
 *
 * Must be called after fork() by the child.
 */
void dnssec_crypto_reinit(void);

/*!
 * Deinitialize cryptographic backend.
 *
 * Should be called when terminating the application.
 */
void dnssec_crypto_cleanup(void);

/*! @} */
