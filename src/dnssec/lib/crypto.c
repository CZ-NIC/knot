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

#include <gnutls/gnutls.h>
#include <gnutls/pkcs11.h>

#include "crypto.h"
#include "p11/p11.h"
#include "shared.h"

_public_
void dnssec_crypto_init(void)
{
	p11_init();
	gnutls_global_init();
}

_public_
void dnssec_crypto_cleanup(void)
{
	gnutls_global_deinit();
	p11_cleanup();
}

_public_
void dnssec_crypto_reinit(void)
{
	p11_reinit();
}
