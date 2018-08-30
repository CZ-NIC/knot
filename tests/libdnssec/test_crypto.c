/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <tap/basic.h>

#include "crypto.h"

int main(void)
{
	plan_lazy();

	// not much we can test

	dnssec_crypto_init();
	ok(1, "dnssec_crypto_init() didn't crash");

	dnssec_crypto_reinit();
	ok(1, "dnssec_crypto_reinit() didn't crash");

	dnssec_crypto_cleanup();
	ok(1, "dnssec_crypto_cleanup() didn't crash");

	return 0;
}
