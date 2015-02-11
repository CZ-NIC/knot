/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \file
 *
 * Cryptographic backend initialization.
 *
 * \defgroup crypto Crypto
 *
 * Cryptographic backend initialization.
 *
 * For most cryptographic operations, the library requires global
 * initialization. Also, if the application creates a subprocess, the
 * library has to be reinitialized in the child process after \c fork().
 *
 * ~~~~~ {.c}
 * int main(void)
 * {
 *     int exit_code = 0;
 *
 *     dnssec_crypto_init();
 *
 *     pid_t child_pid = fork();
 *     if (child_pid < 0) {
 *         perror("fork");
 *         exit_code = 1;
 *     } else if (child_pid == 0) {
 *         dnssec_crypto_reinit();
 *         exit_code = child();
 *     } else {
 *         exit_code = parent();
 *     }
 *
 *     dnssec_crypto_cleanup();
 *     return exit_code;
 * }
 * ~~~~~
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
