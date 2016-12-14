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

#include "knot/modules/noudp/noudp.h"

const yp_item_t scheme_mod_noudp[] = {
	{ C_ID, YP_TSTR, YP_VNONE },
	{ NULL }
};

static bool is_udp(struct query_data *qdata)
{
	return qdata->param->proc_flags & NS_QUERY_LIMIT_SIZE;
}

int noudp_begin(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	assert(pkt && qdata);

	if (is_udp(qdata)) {
		knot_wire_set_tc(pkt->wire);
		return KNOT_STATE_DONE;
	}

	return state;
}

int noudp_load(struct query_plan *plan, struct query_module *self,
               const knot_dname_t *zone)
{
	query_plan_step(plan, QPLAN_BEGIN, noudp_begin, NULL);

	return KNOT_EOK;
}

void noudp_unload(struct query_module *self)
{
	return;
}
