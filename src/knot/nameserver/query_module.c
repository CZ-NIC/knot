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

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libknot/attribute.h"
#include "knot/common/log.h"
#include "knot/conf/module.h"
#include "knot/conf/tools.h"
#include "knot/nameserver/query_module.h"
#include "knot/nameserver/process_query.h"
#include "contrib/mempattern.h"

#ifdef HAVE_ATOMIC
 #define ATOMIC_ADD(dst, val) __atomic_add_fetch(&(dst), (val), __ATOMIC_RELAXED)
 #define ATOMIC_SUB(dst, val) __atomic_sub_fetch(&(dst), (val), __ATOMIC_RELAXED)
 #define ATOMIC_SET(dst, val) __atomic_store_n(&(dst), (val), __ATOMIC_RELAXED)
#else
 #warning "Statistics data can be inaccurate if configured with multiple udp/tcp workers"
 #define ATOMIC_ADD(dst, val) ((dst) += (val))
 #define ATOMIC_SUB(dst, val) ((dst) -= (val))
 #define ATOMIC_SET(dst, val) ((dst) = (val))
#endif

_public_
int knotd_conf_check_ref(knotd_conf_check_args_t *args)
{
	return check_ref(args);
}

struct query_plan *query_plan_create(knot_mm_t *mm)
{
	struct query_plan *plan = mm_alloc(mm, sizeof(struct query_plan));
	if (plan == NULL) {
		return NULL;
	}

	plan->mm = mm;
	for (unsigned i = 0; i < KNOTD_STAGES; ++i) {
		init_list(&plan->stage[i]);
	}

	return plan;
}

void query_plan_free(struct query_plan *plan)
{
	if (plan == NULL) {
		return;
	}

	for (unsigned i = 0; i < KNOTD_STAGES; ++i) {
		struct query_step *step = NULL, *next = NULL;
		WALK_LIST_DELSAFE(step, next, plan->stage[i]) {
			mm_free(plan->mm, step);
		}
	}

	mm_free(plan->mm, plan);
}

static struct query_step *make_step(knot_mm_t *mm, query_step_process_f process,
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

int query_plan_step(struct query_plan *plan, knotd_stage_t stage,
                    query_step_process_f process, void *ctx)
{
	struct query_step *step = make_step(plan->mm, process, ctx);
	if (step == NULL) {
		return KNOT_ENOMEM;
	}

	add_tail(&plan->stage[stage], &step->node);

	return KNOT_EOK;
}

_public_
int knotd_mod_hook(knotd_mod_t *mod, knotd_stage_t stage, knotd_mod_hook_f hook)
{
	if (stage != KNOTD_STAGE_BEGIN && stage != KNOTD_STAGE_END) {
		return KNOT_EINVAL;
	}

	return query_plan_step(mod->plan, stage, hook, mod);
}

_public_
int knotd_mod_in_hook(knotd_mod_t *mod, knotd_stage_t stage, knotd_mod_in_hook_f hook)
{
	if (stage == KNOTD_STAGE_BEGIN || stage == KNOTD_STAGE_END) {
		return KNOT_EINVAL;
	}

	return query_plan_step(mod->plan, stage, hook, mod);
}

knotd_mod_t *query_module_open(conf_t *conf, conf_mod_id_t *mod_id,
                               struct query_plan *plan, const knot_dname_t *zone,
                               knot_mm_t *mm)
{
	if (conf == NULL || mod_id == NULL || plan == NULL) {
		return NULL;
	}

	/* Locate the module. */
	const module_t *mod = conf_mod_find(conf, mod_id->name + 1,
	                                    mod_id->name[0], false);
	if (mod == NULL) {
		return NULL;
	}

	/* Create query module. */
	knotd_mod_t *module = mm_alloc(mm, sizeof(knotd_mod_t));
	if (module == NULL) {
		return NULL;
	}
	memset(module, 0, sizeof(knotd_mod_t));

	module->plan = plan;
	module->mm = mm;
	module->config = conf;
	module->zone = zone;
	module->id = mod_id;
	module->api = mod->api;

	return module;
}

void query_module_close(knotd_mod_t *module)
{
	if (module == NULL) {
		return;
	}

	knotd_mod_stats_free(module);
	conf_free_mod_id(module->id);
	mm_free(module->mm, module);
}

_public_
void *knotd_mod_ctx(knotd_mod_t *mod)
{
	return (mod != NULL) ? mod->ctx : NULL;
}

_public_
void knotd_mod_ctx_set(knotd_mod_t *mod, void *ctx)
{
	if (mod != NULL) mod->ctx = ctx;
}

_public_
const knot_dname_t *knotd_mod_zone(knotd_mod_t *mod)
{
	return (mod != NULL) ? mod->zone : NULL;
}

_public_
void knotd_mod_log(knotd_mod_t *mod, int priority, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	knotd_mod_vlog(mod, priority, fmt, args);
	va_end(args);
}

_public_
void knotd_mod_vlog(knotd_mod_t *mod, int priority, const char *fmt, va_list args)
{
	if (mod == NULL || fmt == NULL) {
		return;
	}

	char msg[512];

	if (vsnprintf(msg, sizeof(msg), fmt, args) < 0) {
		msg[0] = '\0';
	}

	#define LOG_ARGS(mod_id, msg) "module '%s%s%.*s', %s", \
		mod_id->name + 1, (mod_id->len > 0) ? "/" : "", (int)mod_id->len, \
		mod_id->data, msg

	if (mod->zone == NULL) {
		log_fmt(priority, LOG_SOURCE_SERVER, LOG_ARGS(mod->id, msg));
	} else {
		log_fmt_zone(priority, LOG_SOURCE_ZONE, mod->zone,
		             LOG_ARGS(mod->id, msg));
	}

	#undef LOG_ARGS
}

_public_
int knotd_mod_stats_add(knotd_mod_t *mod, const char *ctr_name, uint32_t idx_count,
                        knotd_mod_idx_to_str_f idx_to_str)
{
	if (mod == NULL || idx_count == 0) {
		return KNOT_EINVAL;
	}

	mod_ctr_t *stats = NULL;
	if (mod->stats == NULL) {
		assert(mod->stats_count == 0);
		stats = mm_alloc(mod->mm, sizeof(*stats));
		if (stats == NULL) {
			return KNOT_ENOMEM;
		}
		mod->stats = stats;
	} else {
		assert(mod->stats_count > 0);
		size_t old_size = mod->stats_count * sizeof(*stats);
		size_t new_size = old_size + sizeof(*stats);
		stats = mm_realloc(mod->mm, mod->stats, new_size, old_size);
		if (stats == NULL) {
			knotd_mod_stats_free(mod);
			return KNOT_ENOMEM;
		}
		mod->stats = stats;
		stats += mod->stats_count;
	}

	mod->stats_count++;

	if (idx_count > 1) {
		size_t size = idx_count * sizeof(((mod_ctr_t *)0)->counter);
		stats->counters = mm_alloc(mod->mm, size);
		if (stats->counters == NULL) {
			knotd_mod_stats_free(mod);
			return KNOT_ENOMEM;
		}
		memset(stats->counters, 0, size);
		stats->idx_to_str = idx_to_str;
	}
	stats->name = ctr_name;
	stats->count = idx_count;

	return KNOT_EOK;
}

_public_
void knotd_mod_stats_free(knotd_mod_t *mod)
{
	if (mod == NULL || mod->stats == NULL) {
		return;
	}

	for (int i = 0; i < mod->stats_count; i++) {
		if (mod->stats[i].count > 1) {
			mm_free(mod->mm, mod->stats[i].counters);
		}
	}

	mm_free(mod->mm, mod->stats);
}

#define STATS_BODY(OPERATION) { \
	if (mod == NULL) return; \
	\
	mod_ctr_t *ctr = mod->stats + ctr_id; \
	if (ctr->count == 1) { \
		assert(idx == 0); \
		OPERATION(ctr->counter, val); \
	} else { \
		assert(idx < ctr->count); \
		OPERATION(ctr->counters[idx], val); \
	} \
}

_public_
void knotd_mod_stats_incr(knotd_mod_t *mod, uint32_t ctr_id, uint32_t idx, uint64_t val)
{
	STATS_BODY(ATOMIC_ADD)
}

_public_
void knotd_mod_stats_decr(knotd_mod_t *mod, uint32_t ctr_id, uint32_t idx, uint64_t val)
{
	STATS_BODY(ATOMIC_SUB)
}

_public_
void knotd_mod_stats_store(knotd_mod_t *mod, uint32_t ctr_id, uint32_t idx, uint64_t val)
{
	STATS_BODY(ATOMIC_SET)
}

_public_
knotd_conf_t knotd_conf_env(knotd_mod_t *mod, knotd_conf_env_t env)
{
	static const char *version = "Knot DNS " PACKAGE_VERSION;

	knotd_conf_t out = { { 0 } };

	if (mod == NULL) {
		return out;
	}

	conf_t *config = (mod->config != NULL) ? mod->config : conf();

	switch (env) {
	case KNOTD_CONF_ENV_VERSION:
		out.single.string = version;
		break;
	case KNOTD_CONF_ENV_HOSTNAME:
		out.single.string = config->hostname;
		break;
	case KNOTD_CONF_ENV_WORKERS_UDP:
		out.single.integer = conf_udp_threads(config);
		break;
	case KNOTD_CONF_ENV_WORKERS_TCP:
		out.single.integer = conf_tcp_threads(config);
		break;
	default:
		return out;
	}

	out.count = 1;

	return out;
}

static void set_val(yp_type_t type, knotd_conf_val_t *item, conf_val_t *val)
{
	switch (type) {
	case YP_TINT:
		item->integer = conf_int(val);
		break;
	case YP_TBOOL:
		item->boolean = conf_bool(val);
		break;
	case YP_TOPT:
		item->option = conf_opt(val);
		break;
	case YP_TSTR:
		item->string = conf_str(val);
		break;
	case YP_TDNAME:
		item->dname = conf_dname(val);
		break;
	case YP_TADDR:
		item->addr = conf_addr(val, NULL);
		break;
	case YP_TNET:
		item->addr = conf_addr_range(val, &item->addr_max,
		                             &item->addr_mask);
		break;
	case YP_TREF:
		if (val->code == KNOT_EOK) {
			conf_val(val);
			item->data_len = val->len;
			item->data = val->data;
		}
		break;
	case YP_THEX:
	case YP_TB64:
		item->data = conf_bin(val, &item->data_len);
		break;
	case YP_TDATA:
		item->data = conf_data(val, &item->data_len);
		break;
	default:
		return;
	}
}

static void set_conf_out(knotd_conf_t *out, conf_val_t *val)
{
	if (!(val->item->flags & YP_FMULTI)) {
		out->count = (val->code == KNOT_EOK) ? 1 : 0;
		set_val(val->item->type, &out->single, val);
	} else {
		size_t count = conf_val_count(val);
		if (count == 0) {
			return;
		}

		out->multi = malloc(count * sizeof(*out->multi));
		if (out->multi == NULL) {
			return;
		}
		memset(out->multi, 0, count * sizeof(*out->multi));

		for (size_t i = 0; i < count; i++) {
			set_val(val->item->type, &out->multi[i], val);
			conf_val_next(val);
		}
		out->count = count;
	}
}

_public_
knotd_conf_t knotd_conf(knotd_mod_t *mod, const yp_name_t *section_name,
                        const yp_name_t *item_name, const knotd_conf_t *id)
{
	knotd_conf_t out = { { 0 } };

	if (mod == NULL || section_name == NULL || item_name == NULL) {
		return out;
	}

	conf_t *config = (mod->config != NULL) ? mod->config : conf();

	const uint8_t *raw_id = (id != NULL) ? id->single.data : NULL;
	size_t raw_id_len = (id != NULL) ? id->single.data_len : 0;
	conf_val_t val = conf_rawid_get(config, section_name, item_name,
	                                raw_id, raw_id_len);

	set_conf_out(&out, &val);

	return out;
}

_public_
knotd_conf_t knotd_conf_mod(knotd_mod_t *mod, const yp_name_t *item_name)
{
	knotd_conf_t out = { { 0 } };

	if (mod == NULL || item_name == NULL) {
		return out;
	}

	conf_t *config = (mod->config != NULL) ? mod->config : conf();

	conf_val_t val = conf_mod_get(config, item_name, mod->id);
	if (val.item == NULL) {
		return out;
	}

	set_conf_out(&out, &val);

	return out;
}

_public_
knotd_conf_t knotd_conf_zone(knotd_mod_t *mod, const yp_name_t *item_name,
                             const knot_dname_t *zone)
{
	knotd_conf_t out = { { 0 } };

	if (mod == NULL || item_name == NULL || zone == NULL) {
		return out;
	}

	conf_t *config = (mod->config != NULL) ? mod->config : conf();

	conf_val_t val = conf_zone_get(config, item_name, zone);

	set_conf_out(&out, &val);

	return out;
}

_public_
knotd_conf_t knotd_conf_check_item(knotd_conf_check_args_t *args,
                                   const yp_name_t *item_name)
{
	knotd_conf_t out = { { 0 } };

	conf_val_t val = conf_rawid_get_txn(args->extra->conf, args->extra->txn,
	                                    args->item->name, item_name,
	                                    args->id, args->id_len);

	set_conf_out(&out, &val);

	return out;
}

_public_
void knotd_conf_free(knotd_conf_t *conf)
{
	if (conf == NULL) {
		return;
	}

	if (conf->count > 0 && conf->multi != NULL) {
		memset(conf->multi, 0, conf->count * sizeof(*conf->multi));
		free(conf->multi);
	}
	memset(conf, 0, sizeof(*conf));
}

_public_
const knot_dname_t *knotd_qdata_zone_name(knotd_qdata_t *qdata)
{
	if (qdata == NULL || qdata->extra->zone == NULL) {
		return NULL;
	}

	return qdata->extra->zone->name;
}

_public_
knot_rrset_t knotd_qdata_zone_apex_rrset(knotd_qdata_t *qdata, uint16_t type)
{
	if (qdata == NULL || qdata->extra->zone == NULL ||
	    qdata->extra->zone->contents == NULL) {
		return node_rrset(NULL, type);
	}

	return node_rrset(qdata->extra->zone->contents->apex, type);
}
