/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>

#include "knot/common/log.h"
#include "knot/modules/online_sign/module.h"
#include "knot/nameserver/process_query.h"

const yp_item_t scheme_mod_online_sign[] = {
	{ C_ID, YP_TSTR, YP_VNONE },
	{ NULL }
};

int online_sign_load(struct query_plan *plan, struct query_module *module,
                     const knot_dname_t *zone)
{
	assert(plan);
	assert(module);
	assert(zone);

	log_zone_info(zone, "online signing initialized");

	return KNOT_EOK;
}

int online_sign_unload(struct query_module *module)
{
	assert(module);

	return KNOT_EOK;
}
