/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

/*!
 * Initialize PKCS11 global context.
 */
int p11_init(void);

/*!
 * Reinitialize PKCS11 global context after fork().
 */
int p11_reinit(void);

/*!
 * Load PKCS11 module unless the module was already loaded.
 *
 * Duplicates are detected based on the module path.
 */
int p11_load_module(const char *name);

/*!
 * Cleanup PKCS11 global context.
 *
 * Should be called when the library is deinitialized to prevent memory leaks.
 */
void p11_cleanup(void);
