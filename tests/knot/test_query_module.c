/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>
#include <string.h>
#include <stdlib.h>

#include "libknot/libknot.h"
#include "knot/nameserver/query_module.h"
#include "libknot/packet/pkt.h"
#include "contrib/mempattern.h"
#include "contrib/ucw/mempool.h"

/* Universal processing stage. */
unsigned state_visit(unsigned state, knot_pkt_t *pkt, knotd_qdata_t *qdata,
                     knotd_mod_t *mod)
{
	/* Visit current state */
	bool *state_map = (bool *)mod;
	state_map[state] = true;

	return state + 1;
}

int main(int argc, char *argv[])
{
	plan_lazy();

	/* Create processing context. */
	knot_mm_t mm;
	mm_ctx_mempool(&mm, MM_DEFAULT_BLKSIZE);

	/* Create a map of expected steps. */
	bool state_map[KNOTD_STAGES] = { false };

	/* Prepare query plan. */
	struct query_plan *plan = query_plan_create(&mm);
	ok(plan != NULL, "query_plan: create");

	/* Register all stage visits. */
	int ret = KNOT_EOK;
	for (unsigned stage = KNOTD_STAGE_BEGIN; stage < KNOTD_STAGES; ++stage) {
		ret = query_plan_step(plan, stage, state_visit, state_map);
		if (ret != KNOT_EOK) {
			break;
		}
	}
	is_int(KNOT_EOK, ret, "query_plan: planned all steps");

	/* Execute the plan. */
	int state = 0, next_state = 0;
	for (unsigned stage = KNOTD_STAGE_BEGIN; stage < KNOTD_STAGES; ++stage) {
		struct query_step *step = NULL;
		WALK_LIST(step, plan->stage[stage]) {
			next_state = step->process(state, NULL, NULL, step->ctx);
			if (next_state != state + 1) {
				break;
			}
			state = next_state;
		}
	}
	ok(state == KNOTD_STAGES, "query_plan: executed all steps");

	/* Verify if all steps executed their callback. */
	for (state = 0; state < KNOTD_STAGES; ++state) {
		if (state_map[state] == false) {
			break;
		}
	}
	ok(state == KNOTD_STAGES, "query_plan: executed all callbacks");

	/* Free the query plan. */
	query_plan_free(plan);

	/* Cleanup. */
	mp_delete((struct mempool *)mm.ctx);

	return 0;
}
