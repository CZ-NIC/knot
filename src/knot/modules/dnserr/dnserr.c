/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <pthread.h>
#include <netinet/in.h>

#include "contrib/atomic.h"
#include "contrib/sockaddr.h"
#include "contrib/strtonum.h"
#include "contrib/time.h"
#include "contrib/wire_ctx.h"
#include "knot/include/module.h"
#include "libknot/descriptor.h"

#define MOD_CHANNEL		"\x0e""report-channel"
#define MOD_AGENT		"\x05""agent"
#define MOD_CACHESIZE		"\x0a""cache-size"
#define MOD_CACHELIFETIME	"\x0e""cache-lifetime"

#define RESPONSE	"\x0f""Report received"

const yp_item_t dnserr_conf[] = {
	{ MOD_CHANNEL,       YP_TDNAME, YP_VNONE },
	{ MOD_AGENT,         YP_TBOOL,  YP_VNONE },
	{ MOD_CACHESIZE,     YP_TINT,   YP_VINT =  { 1, INT32_MAX, 1000 }},
	{ MOD_CACHELIFETIME, YP_TINT,   YP_VINT =  { 1, 36 * 24 * 3600, 10, YP_STIME }},
	{ NULL }
};

typedef struct {
	uint16_t qtypes[32];
	const uint8_t *record;
	const uint8_t *record_end;
	uint16_t err;
	uint8_t qtypes_cnt;
} dnserr_parsed_t;

typedef struct {
	uint16_t err;
	uint16_t qtype;
	knot_dname_storage_t record;
	sockaddr_t addr;
	bool used;
} log_tuple_t;

typedef struct {
	pthread_rwlock_t lock;
	log_tuple_t data;
} log_set_el_t;

typedef struct {
	pthread_rwlock_t clean_lock;
	size_t size;
	log_set_el_t *table;
} log_set_t;

typedef struct {
	log_set_t cache;
	knot_atomic_uint64_t last_cleanup;
	const knot_dname_t *channel;
	uint32_t lifetime;
	uint8_t channel_size;
	uint8_t zone_labels;
	bool agent;
} dnserr_ctx_t;

int dnserr_conf_check(knotd_conf_check_args_t *args)
{
	knotd_conf_t conf_agent = knotd_conf_check_item(args, MOD_AGENT);
	if (!conf_agent.single.boolean) {
		knotd_conf_t conf_channel = knotd_conf_check_item(args, MOD_CHANNEL);
		if (conf_channel.count == 0 || conf_channel.single.dname[0] == '\0') {
			args->err_str = "no valid report channel specified";
			return KNOT_EINVAL;
		}
	}

	return KNOT_EOK;
}

static uint64_t log_tuple_hash(const log_tuple_t *val)
{
	if (val == NULL) {
		return 0;
	}

	const uint64_t *h = (const uint64_t *)val;
	// Fast hash by XOR qtype, error and first 20 chars of record
	return h[0] ^ h[1] ^ h[2];
}

static bool log_tuple_eq(const log_tuple_t *a, const log_tuple_t *b)
{
	return a->err == b->err &&
	       a->qtype == b->qtype &&
	       knot_dname_is_equal((const knot_dname_t *)&a->record,
	                           (const knot_dname_t *)&b->record) &&
	       sockaddr_cmp((struct sockaddr_storage *)&a->addr,
	                    (struct sockaddr_storage *)&b->addr, true) == 0;
}

static int hashset_add(log_set_t *set, const log_tuple_t *val)
{
	/* NOTE: After some testing, limit 10 ought to be enough
	 * A larger number of iterations (search depth) is a waste of CPU time
	 * and has no real impact on HIT/MISS (except for disproportionately large
	 * tables, where a lot of iterations help).
	 */
	pthread_rwlock_rdlock(&set->clean_lock);
	static const size_t JUMP_LIMIT = 10;
	uint64_t h = log_tuple_hash(val);
	int i = 1;
	while (i < JUMP_LIMIT) {
		uint64_t idx = h % set->size;
		log_set_el_t *it = set->table + idx;

		pthread_rwlock_rdlock(&it->lock);
		if (!it->data.used) {
			pthread_rwlock_unlock(&it->lock);
			pthread_rwlock_wrlock(&it->lock);
			// NOTE: have to check empty space with RW lock acquired
			if (it->data.used) {
				pthread_rwlock_unlock(&it->lock);
				continue;
			}
			memcpy(&it->data, val, sizeof(*val));
			pthread_rwlock_unlock(&it->lock);
			pthread_rwlock_unlock(&set->clean_lock);
			return KNOT_EOK;
		}
		bool equals = log_tuple_eq(val, &it->data);
		pthread_rwlock_unlock(&it->lock);
		if (equals) {
			pthread_rwlock_unlock(&set->clean_lock);
			return KNOT_EEXIST;
		}

		// Quadratic probing
		h += i * i;
		++i;
	}
	pthread_rwlock_unlock(&set->clean_lock);
	return KNOT_ELIMIT;
}

static void hashset_clean(log_set_t *set)
{
	pthread_rwlock_wrlock(&set->clean_lock);
	for (log_set_el_t *el = set->table; el != set->table + set->size; ++el) {
		pthread_rwlock_wrlock(&el->lock);
		el->data.used = false;
		pthread_rwlock_unlock(&el->lock);
	}
	pthread_rwlock_unlock(&set->clean_lock);
}

static bool equal_label(const knot_dname_t *a, const knot_dname_t *b)
{
	return a[0] == b[0] && memcmp(&a[1], &b[1], a[0]) == 0;
}

static void incr_label(const knot_dname_t **label)
{
	*label += 1 + (*label)[0];
}

static bool parse_qtype_label(dnserr_parsed_t *out, const uint8_t *label)
{
	assert(label[0] != '\0'); // Ensured by the label count check.

	out->qtypes_cnt = 0; // Cannot overflow as there can be up to 63 label chars.
	bool empty = true;
	unsigned val = 0;
	for (int i = 1; i <= label[0]; i++) {
		if (label[i] == '-') {
			if (i == 1 || i == label[0] || empty) {
				return false;
			}
			out->qtypes[out->qtypes_cnt++] = val;
			val = 0;
			empty = true;
			continue;
		} else if (label[i] < '0' || label[i] > '9') {
			return false;
		}
		val *= 10;
		val += label[i] - '0';
		if (val == 0 || val > UINT16_MAX) {
			return false;
		}
		empty = false;
	}
	out->qtypes[out->qtypes_cnt++] = val;
	return true;
}

static bool parse_err_label(dnserr_parsed_t *out, const uint8_t *label)
{
	assert(label[0] != '\0'); // Ensured by the label count check.

	unsigned val = 0;
	for (int i = 1; i <= label[0]; i++) {
		if (label[i] < '0' || label[i] > '9') {
			return false;
		}
		val *= 10;
		val += label[i] - '0';
		if (val > UINT16_MAX) { // val = 0 is valid error
			return false;
		}
	}
	out->err = val;
	return true;
}

static int report_query(dnserr_parsed_t *out, uint8_t zone_labels, const knot_dname_t *qname)
{
	static const uint8_t ER_LABEL[4] = "\x03""_er";

	// Check leading _er label.
	const knot_dname_t *label = qname;
	if (!equal_label(label, ER_LABEL)) {
		return KNOT_ENOENT;
	}
	incr_label(&label);

	// Check enough labels.
	size_t labels = knot_dname_labels(qname, NULL);
	if (labels < 5 + zone_labels) {
		return KNOT_EMALF;
	}

	// Parse QTYPEs label.
	if (!parse_qtype_label(out, label)) {
		return KNOT_EMALF;
	}
	incr_label(&label);

	// Find owner labels.
	uint8_t record_labels = labels - zone_labels - 4;
	out->record = label;
	for (int i = 0; i < record_labels; i++) {
		incr_label(&label);
	}
	out->record_end = label;

	// Parse error code label.
	if (!parse_err_label(out, label)) {
		return KNOT_EMALF;
	}
	incr_label(&label);

	// Check trailing _er label.
	if (!equal_label(label, ER_LABEL)) {
		return KNOT_EMALF;
	}

	return KNOT_EOK;
}

static knotd_in_state_t handle_report(knotd_in_state_t state, knot_pkt_t *pkt,
                                      knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	dnserr_ctx_t *ctx = knotd_mod_ctx(mod);
	assert(ctx->agent);

	dnserr_parsed_t parsed;
	const uint16_t qtype = knot_pkt_qtype(qdata->query);
	const uint16_t qclass = knot_pkt_qclass(qdata->query);
	if (qclass != KNOT_CLASS_IN || qtype != KNOT_RRTYPE_TXT) {
		return state;
	}

	int ret = report_query(&parsed, ctx->zone_labels, qdata->name);
	if (ret == KNOT_EMALF) {
		qdata->rcode = KNOT_RCODE_FORMERR;
		return KNOTD_IN_STATE_ERROR;
	} else if (ret != KNOT_EOK) {
		return state;
	}

	if ((qdata->params->proto == KNOTD_QUERY_PROTO_UDP) &&
	    (qdata->params->flags & KNOTD_QUERY_FLAG_COOKIE) == 0) {
		knot_wire_set_aa(pkt->wire);
		knot_wire_set_tc(pkt->wire);
		return KNOTD_IN_STATE_TRUNC;
	}

	knot_rrset_t *rr = knot_rrset_new(qdata->name, KNOT_RRTYPE_TXT,
	                                  KNOT_CLASS_IN, ctx->lifetime, &pkt->mm);
	if (rr == NULL) {
		return KNOTD_IN_STATE_ERROR;
	}
	if (knot_rrset_add_rdata(rr, (uint8_t *)RESPONSE, sizeof(RESPONSE) - 1,
	                         &pkt->mm) != KNOT_EOK) {
		knot_rrset_free(rr, &pkt->mm);
		return KNOTD_IN_STATE_ERROR;
	}
	if (knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, rr, KNOT_PF_FREE) != KNOT_EOK) {
		knot_rrset_free(rr, &pkt->mm);
		return KNOTD_IN_STATE_ERROR;
	}

	uint64_t last, now;
	do {
		last = ATOMIC_GET(ctx->last_cleanup);
		now = knot_millis_now();

		if (now - last <= ctx->lifetime * 1000) {
			break;
		}
	} while (!ATOMIC_CMPXCHG(ctx->last_cleanup, last, now));
	if (now - last > ctx->lifetime * 1000) {
		hashset_clean(&ctx->cache);
	}

	log_tuple_t ev = {
		.err = parsed.err,
		.used = true
	};
	memcpy(&ev.addr, knotd_qdata_remote_addr(qdata), sizeof(ev.addr));
	sockaddr_port_set((struct sockaddr_storage *)&ev.addr, 0); // Ignore source port.
	memcpy(ev.record, parsed.record, parsed.record_end - parsed.record);
	ev.record[parsed.record_end - parsed.record] = '\0';

	// For each QTYPE store one event into hashset
	for (int idx = 0; idx < parsed.qtypes_cnt; ++idx) {
		ev.qtype = parsed.qtypes[idx];
		int op = hashset_add(&ctx->cache, &ev);
		if (op != KNOT_EOK) {
			continue;
		}

		char addr_str[SOCKADDR_STRLEN];
		char owner_str[KNOT_DNAME_TXT_MAXLEN];
		char qtype_str[32];
		if (sockaddr_tostr(addr_str, sizeof(addr_str), (struct sockaddr_storage *)&ev.addr) > 0 &&
		    knot_dname_to_str(owner_str, ev.record, sizeof(owner_str)) != NULL &&
		    knot_rrtype_to_string(ev.qtype, qtype_str, sizeof(qtype_str))) {
			knotd_mod_log(mod, LOG_NOTICE, "report, qname '%s', qtype %s, error %u, client %s",
			              owner_str, qtype_str, ev.err, addr_str);
		} else {
			knotd_mod_log(mod, LOG_ERR, "failed to log report");
		}
	}

	return KNOTD_IN_STATE_HIT;
}

static knotd_in_state_t report_channel(knotd_in_state_t state, knot_pkt_t *pkt,
                                       knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	dnserr_ctx_t *ctx = knotd_mod_ctx(mod);
	assert(!ctx->agent);

	if (knot_rrset_empty(&qdata->opt_rr)) {
		return state;
	}

	// Best effort.
	if (knot_pkt_reserve(pkt, KNOT_EDNS_OPTION_HDRLEN + ctx->channel_size) == KNOT_EOK) {
		(void)knot_edns_add_option(&qdata->opt_rr, KNOT_EDNS_OPTION_REPORT_CHANNEL,
		                           ctx->channel_size, ctx->channel, qdata->mm);
	}

	return state;
}

int dnserr_load(knotd_mod_t *mod)
{
	dnserr_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	knotd_conf_t conf_log = knotd_conf_mod(mod, MOD_AGENT);
	ctx->agent = conf_log.single.boolean;

	if (ctx->agent) {
		knotd_conf_t conf_cachesize = knotd_conf_mod(mod, MOD_CACHESIZE);
		ctx->cache.size = conf_cachesize.single.integer;
		ctx->cache.table = calloc(ctx->cache.size, sizeof(log_set_el_t));
		if (ctx->cache.table == NULL) {
			return KNOT_ENOMEM;
		}

		pthread_rwlock_init(&ctx->cache.clean_lock, NULL);
		for (int i = 0; i < ctx->cache.size; ++i) {
			pthread_rwlock_init(&ctx->cache.table[i].lock, NULL);
		}

		ctx->zone_labels = knot_dname_labels(knotd_mod_zone(mod), NULL);
		knotd_conf_t conf_lifetime = knotd_conf_mod(mod, MOD_CACHELIFETIME);
		ctx->lifetime = conf_lifetime.single.integer;
	} else {
		knotd_conf_t conf_agent = knotd_conf_mod(mod, MOD_CHANNEL);
		ctx->channel = conf_agent.single.dname;
		ctx->channel_size = knot_dname_size(ctx->channel);
	}

	knotd_mod_ctx_set(mod, ctx);

	if (ctx->agent) {
		return knotd_mod_in_hook(mod, KNOTD_STAGE_PREANSWER, handle_report);
	} else {
		return knotd_mod_in_hook(mod, KNOTD_STAGE_ANSWER, report_channel);
	}
}

void dnserr_unload(knotd_mod_t *mod)
{
	dnserr_ctx_t *ctx = knotd_mod_ctx(mod);

	if (ctx->agent) {
		pthread_rwlock_wrlock(&ctx->cache.clean_lock);
		for (int i = 0; i < ctx->cache.size; ++i) {
			pthread_rwlock_destroy(&ctx->cache.table[i].lock);
		}
		pthread_rwlock_unlock(&ctx->cache.clean_lock);
		pthread_rwlock_destroy(&ctx->cache.clean_lock);
		free(ctx->cache.table);
	}
	free(ctx);
}

KNOTD_MOD_API(dnserr, KNOTD_MOD_FLAG_SCOPE_ZONE,
              dnserr_load, dnserr_unload, dnserr_conf, dnserr_conf_check);
