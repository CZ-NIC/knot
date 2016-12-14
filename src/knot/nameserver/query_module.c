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

#include <assert.h>

#include "knot/nameserver/query_module.h"
#include "contrib/mempattern.h"

#include "knot/modules/rrl/rrl.h"
#include "knot/modules/stats/stats.h"
#include "knot/modules/synth_record/synth_record.h"
#include "knot/modules/dnsproxy/dnsproxy.h"
#include "knot/modules/online_sign/online_sign.h"
#ifdef HAVE_ROSEDB
#include "knot/modules/rosedb/rosedb.h"
#endif
#if USE_DNSTAP
#include "knot/modules/dnstap/dnstap.h"
#endif
#include "knot/modules/whoami/whoami.h"
#include "knot/modules/noudp/noudp.h"

/*! \note All modules should be dynamically loaded later on. */
static_module_t MODULES[] = {
	{ C_MOD_RRL,          &rrl_load,          &rrl_unload,          MOD_SCOPE_ANY },
	{ C_MOD_SYNTH_RECORD, &synth_record_load, &synth_record_unload, MOD_SCOPE_ANY },
	{ C_MOD_DNSPROXY,     &dnsproxy_load,     &dnsproxy_unload,     MOD_SCOPE_ANY },
	{ C_MOD_ONLINE_SIGN,  &online_sign_load,  &online_sign_unload,  MOD_SCOPE_ZONE, true },
	{ C_MOD_STATS,        &stats_load,        &stats_unload,        MOD_SCOPE_ANY, true },
#ifdef HAVE_ROSEDB
	{ C_MOD_ROSEDB,       &rosedb_load,       &rosedb_unload,       MOD_SCOPE_ANY },
#endif
#if USE_DNSTAP
	{ C_MOD_DNSTAP,       &dnstap_load,       &dnstap_unload,       MOD_SCOPE_ANY },
#endif
	{ C_MOD_WHOAMI,       &whoami_load,       &whoami_unload,       MOD_SCOPE_ANY, true },
	{ C_MOD_NOUDP,        &noudp_load,        &noudp_unload,        MOD_SCOPE_ANY, true },
	{ NULL }
};

struct query_plan *query_plan_create(knot_mm_t *mm)
{
	struct query_plan *plan = mm_alloc(mm, sizeof(struct query_plan));
	if (plan == NULL) {
		return NULL;
	}

	plan->mm = mm;
	for (unsigned i = 0; i < QUERY_PLAN_STAGES; ++i) {
		init_list(&plan->stage[i]);
	}

	return plan;
}

void query_plan_free(struct query_plan *plan)
{
	if (plan == NULL) {
		return;
	}

	for (unsigned i = 0; i < QUERY_PLAN_STAGES; ++i) {
		struct query_step *step = NULL, *next = NULL;
		WALK_LIST_DELSAFE(step, next, plan->stage[i]) {
			mm_free(plan->mm, step);
		}
	}

	mm_free(plan->mm, plan);
}

static struct query_step *make_step(knot_mm_t *mm, qmodule_process_t process,
                                    void *ctx)
{
	struct query_step *step = mm_alloc(mm, sizeof(struct query_step));
	if (step == NULL) {
		return NULL;
	}

	memset(step, 0, sizeof(struct query_step));
	step->process = process;
	step->ctx = ctx;

	return step;
}

int query_plan_step(struct query_plan *plan, int stage, qmodule_process_t process,
                    void *ctx)
{
	struct query_step *step = make_step(plan->mm, process, ctx);
	if (step == NULL) {
		return KNOT_ENOMEM;
	}

	add_tail(&plan->stage[stage], &step->node);

	return KNOT_EOK;
}

int mod_stats_add(struct query_module *module, const char *name, uint32_t count,
                  mod_idx_to_str_f idx)
{
	if (module == NULL || count < 1) {
		return KNOT_EINVAL;
	}

	mod_ctr_t *stats = NULL;
	if (module->stats == NULL) {
		assert(module->stats_count == 0);
		stats = mm_alloc(module->mm, sizeof(*stats));
		if (stats == NULL) {
			return KNOT_ENOMEM;
		}
		module->stats = stats;
	} else {
		assert(module->stats_count > 0);
		size_t old_size = module->stats_count * sizeof(*stats);
		size_t new_size = old_size + sizeof(*stats);
		stats = mm_realloc(module->mm, module->stats, new_size, old_size);
		if (stats == NULL) {
			mod_stats_free(module);
			return KNOT_ENOMEM;
		}
		module->stats = stats;
		stats += module->stats_count;
	}

	module->stats_count++;

	if (count > 1) {
		size_t size = count * sizeof(((mod_ctr_t *)0)->counter);
		stats->counters = mm_alloc(module->mm, size);
		if (stats->counters == NULL) {
			mod_stats_free(module);
			return KNOT_ENOMEM;
		}
		memset(stats->counters, 0, size);
		stats->idx_to_str = idx;
	}
	stats->name = name;
	stats->count = count;

	return KNOT_EOK;
}

void mod_stats_free(struct query_module *module)
{
	if (module == NULL || module->stats == NULL) {
		return;
	}

	for (int i = 0; i < module->stats_count; i++) {
		if (module->stats[i].count > 1) {
			mm_free(module->mm, module->stats[i].counters);
		}
	}

	mm_free(module->mm, module->stats);
}

static_module_t *find_module(const yp_name_t *name)
{
	/* Search for the module by name. */
	static_module_t *module = NULL;
	for (unsigned i = 0; MODULES[i].name != NULL; ++i) {
		if (name[0] == MODULES[i].name[0] &&
		    memcmp(name + 1, MODULES[i].name + 1, name[0]) == 0) {
			module = &MODULES[i];
			break;
		}
	}

	return module;
}

struct query_module *query_module_open(conf_t *config, conf_mod_id_t *mod_id,
                                       knot_mm_t *mm)
{
	if (config == NULL || mod_id == NULL) {
		return NULL;
	}

	/* Locate the module. */
	static_module_t *found = find_module(mod_id->name);
	if (found == NULL) {
		return NULL;
	}

	/* Create query module. */
	struct query_module *module = mm_alloc(mm, sizeof(struct query_module));
	if (module == NULL) {
		return NULL;
	}
	memset(module, 0, sizeof(struct query_module));

	module->mm = mm;
	module->config = config;
	module->id = mod_id;
	module->load = found->load;
	module->unload = found->unload;
	module->scope = found->scope;

	return module;
}

void query_module_close(struct query_module *module)
{
	if (module == NULL) {
		return;
	}

	mod_stats_free(module);
	conf_free_mod_id(module->id);
	mm_free(module->mm, module);
}
