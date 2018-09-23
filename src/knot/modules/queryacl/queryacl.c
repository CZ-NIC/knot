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

#include "knot/include/module.h"
#include "contrib/sockaddr.h"

#define MOD_ADDRESS		"\x07""address"
#define MOD_INTERFACE	"\x09""interface"

const yp_item_t queryacl_conf[] = {
	{ MOD_ADDRESS,   YP_TNET, YP_VNONE, YP_FMULTI },
	{ MOD_INTERFACE, YP_TNET, YP_VNONE, YP_FMULTI },
	{ NULL }
};

int queryacl_load(knotd_mod_t *mod)
{
	return KNOT_EOK;
}

void queryacl_unload(knotd_mod_t *mod)
{

}

KNOTD_MOD_API(queryacl, KNOTD_MOD_FLAG_SCOPE_ANY,
              queryacl_load, queryacl_unload, queryacl_conf, NULL);
