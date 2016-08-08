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
/*!
 * \file
 *
 * \brief Query module interface
 *
 * The concept of query plan is simple - each query requires a finite
 * number of steps to be solved. For example IN query needs to find an answer and
 * based on the result, process authority and maybe supply additional records.
 * This can be represented by a query plan:
 * answer => { find_answer },
 * authority => { process_authority },
 * additional => { process_additional }
 *
 * The example is obvious, but if a state is passed between the callbacks,
 * same principle applies for every query processing.
 * This file provides an interface for basic query plan and more importantly
 * dynamically loaded modules that can alter query plans.
 * For a default internet zone query plan, see \file internet.h
 *
 * \addtogroup query_processing
 * @{
 */

#pragma once

#include "libknot/libknot.h"
#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/conf/tools.h"
#include "knot/nameserver/process_query.h"
#include "knot/nameserver/internet.h"
#include "contrib/ucw/lists.h"

#define MODULE_ERR(mod, msg, ...) \
	log_error("module '%.*s', " msg, mod[0], mod + 1, ##__VA_ARGS__)

#define MODULE_ZONE_ERR(mod, zone, msg, ...) \
	log_zone_error(zone, "module '%.*s', " msg, mod[0], mod + 1, ##__VA_ARGS__)

/* Query module instance scopes. */
enum {
	MOD_SCOPE_GLOBAL = 1 << 0, /* Global quering (all zones). */
	MOD_SCOPE_ZONE   = 1 << 1, /* Specific zone quering. */
	MOD_SCOPE_ANY    = MOD_SCOPE_GLOBAL | MOD_SCOPE_ZONE
};

/* Query module processing stages. */
enum query_stage {
	QPLAN_BEGIN  = 0, /* Before query processing. */
	QPLAN_STAGE  = 1, /* Class-specific processing stages. */
	QPLAN_ANSWER = QPLAN_STAGE + KNOT_ANSWER, /* Answer section processing. */
	QPLAN_AUTHORITY,  /* Authority section processing. */
	QPLAN_ADDITIONAL, /* Additional section processing. */
	QPLAN_END         /* After query processing. */
};

#define QUERY_PLAN_STAGES (QPLAN_END + 1)

/* Forward declarations. */
struct query_data;
struct query_module;
struct query_plan;

/* Module callback required API. */
typedef int (*qmodule_load_t)(struct query_plan *plan, struct query_module *self, const knot_dname_t *zone);
typedef int (*qmodule_unload_t)(struct query_module *self);
typedef int (*qmodule_process_t)(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx);

typedef struct static_module {
	const yp_name_t *name;
	qmodule_load_t load;
	qmodule_unload_t unload;
	unsigned scope;
	bool opt_conf;
} static_module_t;

typedef char* (*mod_idx_to_str_f)(uint32_t idx, uint32_t count);

typedef struct {
	const char *name;
	union {
		uint64_t counter;
		struct {
			uint64_t *counters;
			mod_idx_to_str_f idx_to_str;
		};
	};
	uint32_t count;
} mod_ctr_t;

/*!
 * Query module is a dynamically loadable unit that can alter query processing plan.
 * Module requires load and unload callback handlers and is provided with a context
 * and configuration string.
 */
struct query_module {
	node_t node;
	knot_mm_t *mm;
	void *ctx;
	conf_t *config;
	conf_mod_id_t *id;
	qmodule_load_t load;
	qmodule_unload_t unload;
	mod_ctr_t *stats;
	uint32_t stats_count;
	unsigned scope;
};

int mod_stats_add(struct query_module *module, const char *name, uint32_t count,
                  mod_idx_to_str_f idx);

void mod_stats_free(struct query_module *module);

inline static void mod_ctr_incr(mod_ctr_t *stats, uint32_t idx, uint64_t val)
{
	mod_ctr_t *ctr = stats + idx;
	assert(ctr->count == 1);

	__sync_fetch_and_add(&ctr->counter, val);
}

inline static void mod_ctr_decr(mod_ctr_t *stats, uint32_t idx, uint64_t val)
{
	mod_ctr_t *ctr = stats + idx;
	assert(ctr->count == 1);

	__sync_fetch_and_sub(&ctr->counter, val);
}

inline static void mod_ctrs_incr(mod_ctr_t *stats, uint32_t idx, uint32_t offset, uint64_t val)
{
	mod_ctr_t *ctr = stats + idx;
	assert(ctr->count > 1);

	// Increment the last counter if offset overflows.
	if (offset < ctr->count) {
		__sync_fetch_and_add(&ctr->counters[offset], val);
	} else {
		__sync_fetch_and_add(&ctr->counters[ctr->count - 1], val);
	}
}

inline static void mod_ctrs_decr(mod_ctr_t *stats, uint32_t idx, uint32_t offset, uint64_t val)
{
	mod_ctr_t *ctr = stats + idx;
	assert(ctr->count > 1);

	// Increment the last counter if offset overflows.
	if (offset < ctr->count) {
		__sync_fetch_and_sub(&ctr->counters[offset], val);
	} else {
		__sync_fetch_and_sub(&ctr->counters[ctr->count - 1], val);
	}
}

/*! \brief Single processing step in query processing. */
struct query_step {
	node_t node;
	void *ctx;
	qmodule_process_t process;
};

/*! Query plan represents a sequence of steps needed for query processing
 *  divided into several stages, where each stage represents a current response
 *  assembly phase, for example 'before processing', 'answer section' and so on.
 */
struct query_plan {
	knot_mm_t *mm;
	list_t stage[QUERY_PLAN_STAGES];
};

static_module_t *find_module(const yp_name_t *name);

/*! \brief Create an empty query plan. */
struct query_plan *query_plan_create(knot_mm_t *mm);

/*! \brief Free query plan and all planned steps. */
void query_plan_free(struct query_plan *plan);

/*! \brief Plan another step for given stage. */
int query_plan_step(struct query_plan *plan, int stage, qmodule_process_t process,
                    void *ctx);

/*! \brief Open query module identified by name. */
struct query_module *query_module_open(conf_t *config, conf_mod_id_t *mod_id,
                                       knot_mm_t *mm);

/*! \brief Close query module. */
void query_module_close(struct query_module *module);

/*! @} */
