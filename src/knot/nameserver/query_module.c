/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "contrib/sockaddr.h"
#include "libknot/attribute.h"
#include "libknot/probe/data.h"
#include "libknot/xdp.h"
#include "knot/common/log.h"
#include "knot/conf/module.h"
#include "knot/conf/tools.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/nameserver/query_module.h"
#include "knot/nameserver/process_query.h"

#ifdef HAVE_ATOMIC
 #define ATOMIC_ADD(dst, val) __atomic_add_fetch(&(dst), (val), __ATOMIC_RELAXED)
 #define ATOMIC_SUB(dst, val) __atomic_sub_fetch(&(dst), (val), __ATOMIC_RELAXED)
 #define ATOMIC_SET(dst, val) __atomic_store_n(&(dst), (val), __ATOMIC_RELAXED)
#else
 #warning "Statistics data can be inaccurate"
 #define ATOMIC_ADD(dst, val) ((dst) += (val))
 #define ATOMIC_SUB(dst, val) ((dst) -= (val))
 #define ATOMIC_SET(dst, val) ((dst) = (val))
#endif

_public_
int knotd_conf_check_ref(knotd_conf_check_args_t *args)
{
	return check_ref(args);
}

struct query_plan *query_plan_create(void)
{
	struct query_plan *plan = malloc(sizeof(struct query_plan));
	if (plan == NULL) {
		return NULL;
	}

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
		struct query_step *step, *next;
		WALK_LIST_DELSAFE(step, next, plan->stage[i]) {
			free(step);
		}
	}

	free(plan);
}

static struct query_step *make_step(query_step_process_f process, void *ctx)
{
	struct query_step *step = calloc(1, sizeof(struct query_step));
	if (step == NULL) {
		return NULL;
	}

	step->process = process;
	step->ctx = ctx;

	return step;
}

int query_plan_step(struct query_plan *plan, knotd_stage_t stage,
                    query_step_process_f process, void *ctx)
{
	struct query_step *step = make_step(process, ctx);
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

knotd_mod_t *query_module_open(conf_t *conf, server_t *server, conf_mod_id_t *mod_id,
                               struct query_plan *plan, const knot_dname_t *zone)
{
	if (conf == NULL || server == NULL || mod_id == NULL || plan == NULL) {
		return NULL;
	}

	/* Locate the module. */
	const module_t *mod = conf_mod_find(conf, mod_id->name + 1,
	                                    mod_id->name[0], false);
	if (mod == NULL) {
		return NULL;
	}

	/* Create query module. */
	knotd_mod_t *module = calloc(1, sizeof(knotd_mod_t));
	if (module == NULL) {
		return NULL;
	}

	module->plan = plan;
	module->config = conf;
	module->server = server;
	module->zone = zone;
	module->id = mod_id;
	module->api = mod->api;

	return module;
}

static void module_reset(conf_t *conf, knotd_mod_t *module, struct query_plan *new_plan)
{
	// Keep ->node
	module->config = conf;
	// Keep ->server
	// Keep ->id
	module->plan = new_plan;
	// Keep ->zone
	// Keep ->api

	// Reset DNSSEC
	zone_sign_ctx_free(module->sign_ctx);
	free_zone_keys(module->keyset);
	free(module->keyset);
	if (module->dnssec != NULL) {
		kdnssec_ctx_deinit(module->dnssec);
		free(module->dnssec);
	}
	module->dnssec = NULL;
	module->keyset = NULL;
	module->sign_ctx = NULL;

	// Reset statistics
	knotd_mod_stats_free(module);
	module->stats_info = NULL;
	module->stats_vals = NULL;
	module->stats_count = 0;

	// Keep ->ctx
}

void query_module_close(knotd_mod_t *module)
{
	if (module == NULL) {
		return;
	}

	module_reset(NULL, module, NULL);
	conf_free_mod_id(module->id);
	free(module);
}

void query_module_reset(conf_t *conf, knotd_mod_t *module, struct query_plan *new_plan)
{
	if (module == NULL) {
		return;
	}

	module_reset(conf, module, new_plan);
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
		log_fmt_zone(priority, LOG_SOURCE_ZONE, mod->zone, NULL,
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

	unsigned threads = knotd_mod_threads(mod);

	mod_ctr_t *stats = NULL;
	uint32_t offset = 0;
	if (mod->stats_info == NULL) {
		assert(mod->stats_count == 0);
		stats = malloc(sizeof(*stats));
		if (stats == NULL) {
			return KNOT_ENOMEM;
		}
		mod->stats_info = stats;

		assert(mod->stats_vals == NULL);
		mod->stats_vals = calloc(threads, sizeof(*mod->stats_vals));
		if (mod->stats_vals == NULL) {
			knotd_mod_stats_free(mod);
			return KNOT_ENOMEM;
		}

		for (unsigned i = 0; i < threads; i++) {
			mod->stats_vals[i] = calloc(idx_count, sizeof(**mod->stats_vals));
			if (mod->stats_vals[i] == NULL) {
				knotd_mod_stats_free(mod);
				return KNOT_ENOMEM;
			}
		}
	} else {
		for (uint32_t i = 0; i < mod->stats_count; i++) {
			offset += mod->stats_info[i].count;
		}
		assert(offset == mod->stats_info[mod->stats_count - 1].offset +
		                 mod->stats_info[mod->stats_count - 1].count);

		assert(mod->stats_count > 0);
		size_t old_size = mod->stats_count * sizeof(*stats);
		size_t new_size = old_size + sizeof(*stats);
		stats = realloc(mod->stats_info, new_size);
		if (stats == NULL) {
			knotd_mod_stats_free(mod);
			return KNOT_ENOMEM;
		}
		mod->stats_info = stats;
		stats += mod->stats_count;

		for (unsigned i = 0; i < threads; i++) {
			uint64_t *new_vals = realloc(mod->stats_vals[i],
			                             (offset + idx_count) * sizeof(*new_vals));
			if (new_vals == NULL) {
				knotd_mod_stats_free(mod);
				return KNOT_ENOMEM;
			}
			mod->stats_vals[i] = new_vals;
			new_vals += offset;
			for (uint32_t j = 0; j < idx_count; j++) {
				*new_vals++ = 0;
			}
		}
	}

	stats->name = ctr_name;
	stats->count = idx_count;
	stats->idx_to_str = idx_to_str;
	stats->offset = offset;

	mod->stats_count++;

	return KNOT_EOK;
}

_public_
void knotd_mod_stats_free(knotd_mod_t *mod)
{
	if (mod == NULL || mod->stats_info == NULL) {
		return;
	}

	if (mod->stats_vals != NULL) {
		unsigned threads = knotd_mod_threads(mod);
		for (unsigned i = 0; i < threads; i++) {
			free(mod->stats_vals[i]);
		}
	}

	free(mod->stats_vals);
	free(mod->stats_info);
}

#define STATS_BODY(OPERATION) { \
	if (mod == NULL) return; \
	\
	mod_ctr_t *ctr = mod->stats_info + ctr_id; \
	assert(idx < ctr->count); \
	OPERATION(mod->stats_vals[thr_id][ctr->offset + idx], val); \
}

_public_
void knotd_mod_stats_incr(knotd_mod_t *mod, unsigned thr_id, uint32_t ctr_id,
                          uint32_t idx, uint64_t val)
{
	STATS_BODY(ATOMIC_ADD)
}

_public_
void knotd_mod_stats_decr(knotd_mod_t *mod, unsigned thr_id, uint32_t ctr_id,
                          uint32_t idx, uint64_t val)
{
	STATS_BODY(ATOMIC_SUB)
}

_public_
void knotd_mod_stats_store(knotd_mod_t *mod, unsigned thr_id, uint32_t ctr_id,
                           uint32_t idx, uint64_t val)
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
		out.single.integer = config->cache.srv_udp_threads;
		break;
	case KNOTD_CONF_ENV_WORKERS_TCP:
		out.single.integer = config->cache.srv_tcp_threads;
		break;
	case KNOTD_CONF_ENV_WORKERS_XDP:
		out.single.integer = config->cache.srv_xdp_threads;
		break;
	default:
		return out;
	}

	out.count = 1;

	return out;
}

_public_
unsigned knotd_mod_threads(knotd_mod_t *mod)
{
	knotd_conf_t udp = knotd_conf_env(mod, KNOTD_CONF_ENV_WORKERS_UDP);
	knotd_conf_t xdp = knotd_conf_env(mod, KNOTD_CONF_ENV_WORKERS_XDP);
	knotd_conf_t tcp = knotd_conf_env(mod, KNOTD_CONF_ENV_WORKERS_TCP);
	return udp.single.integer + xdp.single.integer + tcp.single.integer;
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

	conf_val_t val;
	if (id != NULL) {
		val = conf_rawid_get(config, section_name, item_name,
		                     id->single.data, id->single.data_len);
	} else {
		val = conf_get(config, section_name, item_name);
	}

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
bool knotd_conf_addr_range_match(const knotd_conf_t *range,
                                 const struct sockaddr_storage *addr)
{
	if (range == NULL || addr == NULL) {
		return false;
	}

	for (size_t i = 0; i < range->count; i++) {
		knotd_conf_val_t *val = &range->multi[i];
		if (val->addr_max.ss_family == AF_UNSPEC) {
			if (sockaddr_net_match(addr, &val->addr, val->addr_mask)) {
				return true;
			}
		} else {
			if (sockaddr_range_match(addr, &val->addr, &val->addr_max)) {
				return true;
			}
		}
	}

	return false;
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
const struct sockaddr_storage *knotd_qdata_local_addr(knotd_qdata_t *qdata,
                                                      struct sockaddr_storage *buff)
{
	if (qdata == NULL) {
		return NULL;
	}

	if (qdata->params->xdp_msg != NULL) {
#ifdef ENABLE_XDP
		return (struct sockaddr_storage *)&qdata->params->xdp_msg->ip_to;
#else
		assert(0);
		return NULL;
#endif
	} else {
		socklen_t buff_len = sizeof(*buff);
		if (getsockname(qdata->params->socket, (struct sockaddr *)buff,
		                &buff_len) != 0) {
			return NULL;
		}
		return buff;
	}
}

_public_
const struct sockaddr_storage *knotd_qdata_remote_addr(knotd_qdata_t *qdata)
{
	if (qdata == NULL) {
		return NULL;
	}

	if (qdata->params->xdp_msg != NULL) {
#ifdef ENABLE_XDP
		return (struct sockaddr_storage *)&qdata->params->xdp_msg->ip_from;
#else
		assert(0);
		return NULL;
#endif
	} else {
		return qdata->params->remote;
	}
}

_public_
uint32_t knotd_qdata_rtt(knotd_qdata_t *qdata)
{
	if (qdata == NULL) {
		return 0;
	}

	switch (qdata->params->proto) {
	case KNOTD_QUERY_PROTO_TCP:
		if (qdata->params->xdp_msg != NULL) {
#ifdef ENABLE_XDP
			return qdata->params->measured_rtt;
#else
			assert(0);
			return 0;
#endif
		} else {
			return knot_probe_tcp_rtt(qdata->params->socket);
		}
	case KNOTD_QUERY_PROTO_QUIC:
		return qdata->params->measured_rtt;
	case KNOTD_QUERY_PROTO_UDP:
	default:
		return 0;
	}
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
	if (qdata == NULL || qdata->extra->contents == NULL) {
		return node_rrset(NULL, type);
	}

	return node_rrset(qdata->extra->contents->apex, type);
}

_public_
int knotd_mod_dnssec_init(knotd_mod_t *mod)
{
	if (mod == NULL || mod->dnssec != NULL) {
		return KNOT_EINVAL;
	}

	knot_lmdb_db_t *kaspdb = &mod->server->kaspdb;
	kasp_db_ensure_init(kaspdb, mod->config); // probably redundant

	mod->dnssec = calloc(1, sizeof(*(mod->dnssec)));
	if (mod->dnssec == NULL) {
		return KNOT_ENOMEM;
	}

	conf_val_t conf = conf_zone_get(mod->config, C_DNSSEC_SIGNING, mod->zone);
	int ret = kdnssec_ctx_init(mod->config, mod->dnssec, mod->zone, kaspdb,
	                           conf_bool(&conf) ? NULL : mod->id);
	if (ret != KNOT_EOK) {
		free(mod->dnssec);
		mod->dnssec = NULL;
		return ret;
	}

	return KNOT_EOK;
}

_public_
int knotd_mod_dnssec_load_keyset(knotd_mod_t *mod, bool verbose)
{
	if (mod == NULL || mod->dnssec == NULL) {
		return KNOT_EINVAL;
	}

	mod->keyset = calloc(1, sizeof(*(mod->keyset)));
	if (mod->keyset == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = load_zone_keys(mod->dnssec, mod->keyset, verbose);
	if (ret != KNOT_EOK) {
		free(mod->keyset);
		mod->keyset = NULL;
		return ret;
	}

	mod->sign_ctx = zone_sign_ctx(mod->keyset, mod->dnssec);
	if (mod->sign_ctx == NULL) {
		free_zone_keys(mod->keyset);
		free(mod->keyset);
		mod->keyset = NULL;
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

_public_
void knotd_mod_dnssec_unload_keyset(knotd_mod_t *mod)
{
	if (mod != NULL && mod->keyset != NULL) {
		zone_sign_ctx_free(mod->sign_ctx);
		mod->sign_ctx = NULL;

		free_zone_keys(mod->keyset);
		free(mod->keyset);
		mod->keyset = NULL;
	}
}

_public_
int knotd_mod_dnssec_sign_rrset(knotd_mod_t *mod, knot_rrset_t *rrsigs,
                                const knot_rrset_t *rrset, knot_mm_t *mm)
{
	if (mod == NULL || rrsigs == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	return knot_sign_rrset2(rrsigs, rrset, mod->sign_ctx, mm);
}
