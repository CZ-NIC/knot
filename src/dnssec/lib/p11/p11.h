/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/*!
 * Load PKCS11 module unless the module was already loaded.
 *
 * Duplicates are detected based on the module path.
 */
int p11_load_module(const char *name);

/*!
 * Clenaup list of loaded modules.
 *
 * Should be called when the library is deinitialized to prevent memory leaks.
 */
void p11_cleanup(void);
