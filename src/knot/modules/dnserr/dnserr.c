/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <pthread.h>
#include <netinet/in.h>

#include "contrib/atomic.h"
#include "contrib/sockaddr.h"
#include "contrib/time.h"
#include "contrib/wire_ctx.h"
#include "knot/include/module.h"
#include "libknot/descriptor.h"

#define MOD_CHANNEL	"\x0e""report-channel"
#define MOD_AGENT	"\x05""agent"
#define MOD_CACHESIZE	"\x0e""log-cache-size"
#define MOD_TIMEOUT	"\x0b""log-timeout"

#define RESPONSE        "\x0f""Report received"

const yp_item_t dnserr_conf[] = {
	{ MOD_CHANNEL,    YP_TDNAME, YP_VNONE },
	{ MOD_AGENT,      YP_TBOOL,  YP_VNONE },
	{ MOD_CACHESIZE,  YP_TINT,   YP_VINT =  { 1, INT32_MAX, 1000 }},
	{ MOD_TIMEOUT,    YP_TINT,   YP_VINT =  { 1, 36*24*3600, 10, YP_STIME }},
	{ NULL }
};

typedef struct {
	uint16_t err;
	uint16_t qtype;
	knot_dname_storage_t record;
	struct sockaddr_storage addr;
} log_tuple_t;

enum state {
	EMPTY = 0,
	RESERVED = 1,
	FULL = 2
};

typedef struct {
	pthread_rwlock_t lock;
	log_tuple_t data;
} log_set_el_t;

typedef struct {
	pthread_rwlock_t flush_lock;
	size_t size;
	log_set_el_t *table;
} log_set_t;

typedef struct {
	log_set_t log_cache;
	knot_atomic_millis_t last_flush;
	const knot_dname_t *report_channel;
	int timeout;
	uint8_t report_channel_size;
	bool agent;
} dnserr_ctx_t;

typedef struct {
	uint16_t qtypes[32];
	const uint8_t *record;
	const uint8_t *record_end;
	int err;
	uint8_t qtypes_cnt;
} dnserr_parsed_t;

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
	if (val == NULL || val->err == 0) {
		return 0;
	}

	const uint64_t *h = (const uint64_t *)val;
	// Fast hash by XOR qtype, error and first 20 chars of record
	return h[0] ^ h[1] ^ h[2];
}

static bool log_tuple_eq(const log_tuple_t *a, const log_tuple_t *b)
{
	return a->err == b->err && \
	       a->qtype == b->qtype && \
	       knot_dname_is_equal((const knot_dname_t *)&a->record,
	                           (const knot_dname_t *)&b->record);
}

static int hashset_add(log_set_t *set, const log_tuple_t *val)
{
	/* NOTE: After some testing, limit 10 ought to be enough
	 * A larger number of iterations (search depth) is a waste of CPU time
	 * and has no real impact on HIT/MISS (except for disproportionately large
	 * tables, where a lot of iterations help).
	 */
	pthread_rwlock_rdlock(&set->flush_lock);
	static const size_t JUMP_LIMIT = 10;
	uint64_t h = log_tuple_hash(val);
	int i = 1;
	while (i < JUMP_LIMIT) {
		uint64_t idx = h % set->size;
		log_set_el_t *it = set->table + idx;

		pthread_rwlock_rdlock(&it->lock);
		if (it->data.err == 0) {
			pthread_rwlock_unlock(&it->lock);
			pthread_rwlock_wrlock(&it->lock);
			// NOTE: have to check empty space with RW lock acquired
			if (it->data.err != 0) {
				pthread_rwlock_unlock(&it->lock);
				continue;
			}
			memcpy(&it->data, val, sizeof(*val));
			pthread_rwlock_unlock(&it->lock);
			pthread_rwlock_unlock(&set->flush_lock);
			return KNOT_EOK;
		}
		bool equals = log_tuple_eq(val, &it->data);
		pthread_rwlock_unlock(&it->lock);
		if (equals) {
			pthread_rwlock_unlock(&set->flush_lock);
			return KNOT_EEXIST;
		}

		// Quadratic probing
		h += i * i;
		++i;
	}
	pthread_rwlock_unlock(&set->flush_lock);
	return KNOT_ENOMEM;
}

static void flush_set(knotd_mod_t *mod, log_set_t *set)
{
	char addr_str[SOCKADDR_STRLEN];
	char owner_str[KNOT_DNAME_TXT_MAXLEN];
	char qtype_str[32];

	pthread_rwlock_wrlock(&set->flush_lock);
	for (log_set_el_t *el = set->table; el != set->table + set->size; ++el) {
		pthread_rwlock_wrlock(&el->lock);
		if (el->data.err == 0) {
			pthread_rwlock_unlock(&el->lock);
			continue;
		}

		if (sockaddr_tostr(addr_str, sizeof(addr_str), &el->data.addr) > 0 &&
		    knot_dname_to_str(owner_str, el->data.record, sizeof(owner_str)) != NULL &&
		    knot_rrtype_to_string(el->data.qtype, qtype_str, sizeof(qtype_str))) {
			knotd_mod_log(mod, LOG_NOTICE, "report, qname '%s', qtype %s, error %u, client %s",
			              owner_str, qtype_str, el->data.err, addr_str);
		} else {
			knotd_mod_log(mod, LOG_ERR, "failed to log report");
		}

		pthread_rwlock_unlock(&el->lock);
	}
	pthread_rwlock_unlock(&set->flush_lock);
}

static int parse_int_label(const uint8_t *dname)
{
	size_t size;
	int out = 0;
	for (size = *(dname++); size > 0; --size, ++dname) {
		if (*dname < '0' || *dname > '9') {
			return KNOT_EMALF;
		}
		out *= 10;
		out += *dname - '0';
	}
	if (size != 0) {
		return KNOT_EMALF;
	}
	return out;
}

static char *str_next_int(char *in)
{
	assert(in != NULL);

	char *ptr = in;
	while(*ptr >= '0' && *ptr <= '9') {
		ptr++;
	}
	return ptr;
}

int parse_report_query(dnserr_parsed_t *output, const knot_dname_t *dname)
{
	assert(output != NULL && dname != NULL);

	static const uint8_t ER_LABEL[] = "\x03""_er";
	const uint8_t *ptr = dname;
	if (memcmp(ptr, ER_LABEL, sizeof(ER_LABEL) - 1) != 0) {
		return KNOT_EMALF;
	}
	ptr += sizeof(ER_LABEL) - 1;
	if (*ptr == '\x00') {
		return KNOT_EMALF;
	}

	output->qtypes_cnt = 0;
	char *token = (char *)ptr;
	char *qtypes_end = token + 1 + *ptr;
	while (token != NULL && token < qtypes_end) {
		int token_int = atoi(++token);
		if (token_int <= 0 || token_int > UINT16_MAX) {
			return KNOT_EMALF;
		}
		output->qtypes[output->qtypes_cnt++] = token_int;
		token = str_next_int(token);
		if (*token != '-') {
			break;
		}
	}
	if (output->qtypes_cnt == 0 || token != qtypes_end) {
		return KNOT_EMALF;
	}
	ptr = (const uint8_t *)qtypes_end;
	if (*ptr == '\x00') {
		return KNOT_EMALF;
	}

	output->record = ptr;
	output->record_end = NULL;
	const uint8_t *errno_label_ptr = ptr;
	const uint8_t *final_label_ptr = ptr + *ptr + 1;
	while ((*final_label_ptr) != '\x00') {
		if (memcmp(final_label_ptr, ER_LABEL, sizeof(ER_LABEL) - 1) == 0) {
			output->record_end = errno_label_ptr;
			break;
		}
		errno_label_ptr = final_label_ptr;
		final_label_ptr += *final_label_ptr + 1;
	}
	if (output->record_end == NULL || output->record == output->record_end) {
		return KNOT_EMALF;
	}

	if ((output->err = parse_int_label(errno_label_ptr)) < KNOT_EOK) {
		return KNOT_EMALF;
	}

	return KNOT_EOK;
}

static knotd_in_state_t dnserr_query(knotd_in_state_t state, knot_pkt_t *pkt,
                                     knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	dnserr_ctx_t *ctx = knotd_mod_ctx(mod);

	if (ctx->agent) {
		const uint16_t qtype = knot_pkt_qtype(qdata->query);
		const uint16_t qclass = knot_pkt_qclass(qdata->query);
		if (qclass != KNOT_CLASS_IN || qtype != KNOT_RRTYPE_TXT) {
			return state;
		}

		if ((qdata->params->proto == KNOTD_QUERY_PROTO_UDP) &&
		    (qdata->params->flags & KNOTD_QUERY_FLAG_COOKIE) == 0) {
			knot_wire_set_tc(pkt->wire);
			return state;
		}

		dnserr_parsed_t parsed;
		if (parse_report_query(&parsed, qdata->name) != KNOT_EOK) {
			return KNOTD_IN_STATE_ERROR;
		}

		knot_rrset_t *rr = knot_rrset_new(qdata->name, KNOT_RRTYPE_TXT,
		                                  KNOT_CLASS_IN, ctx->timeout,
		                                  &pkt->mm);
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

		log_tuple_t ev = {
			.err = parsed.err,
			.addr = *knotd_qdata_remote_addr(qdata)
		};
		memcpy(ev.record, parsed.record, parsed.record_end - parsed.record);
		ev.record[parsed.record_end - parsed.record] = '\0';

		// For each QTYPE store one event into hashset
		for (int idx = 0; idx < parsed.qtypes_cnt; ++idx) {
			ev.qtype = parsed.qtypes[idx];
			hashset_add(&ctx->log_cache, &ev);
		}

		knot_millis_t now, last;
		bool flush;
		last = ATOMIC_GET(ctx->last_flush);
		do {
			flush = false;
			now = knot_millis_now();
			if (now - last > ctx->timeout * 1000) {
				flush = true;
			} else {
				break;
			}
		} while (ATOMIC_CMPXCHG(ctx->last_flush, last, now));
		if (flush) {
			flush_set(mod, &ctx->log_cache);
		}

		return KNOTD_IN_STATE_HIT;
	} else if (!knot_rrset_empty(&qdata->opt_rr)) {
		uint8_t *option = NULL;
		uint8_t option_size = ctx->report_channel_size;
		int ret = knot_edns_reserve_option(&qdata->opt_rr,
		                                   KNOT_EDNS_OPTION_REPORT_CHANNEL,
		                                   option_size, &option, qdata->mm);
		if (ret != KNOT_EOK) {
			return KNOTD_IN_STATE_ERROR;
		}

		ret = knot_edns_domainagent_write(option, option_size, ctx->report_channel);
		if (ret != KNOT_EOK) {
			return KNOTD_IN_STATE_ERROR;
		}

		ret = knot_pkt_reserve(pkt, KNOT_EDNS_OPTION_HDRLEN + option_size);
		if (ret != KNOT_EOK) {
			return KNOTD_IN_STATE_ERROR;
		}
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
		size_t size = conf_cachesize.single.integer;
		pthread_rwlock_init(&ctx->log_cache.flush_lock, NULL);
		ctx->log_cache.size = size;
		ctx->log_cache.table = calloc(size, sizeof(log_set_el_t));
		for (int i = 0; i < size; ++i) {
			pthread_rwlock_init(&ctx->log_cache.table[i].lock, NULL);
		}

		knotd_conf_t conf_timeout = knotd_conf_mod(mod, MOD_TIMEOUT);
		ctx->timeout = conf_timeout.single.integer;
	} else {
		knotd_conf_t conf_agent = knotd_conf_mod(mod, MOD_CHANNEL);
		ctx->report_channel = conf_agent.single.dname;
		ctx->report_channel_size = knot_dname_size(ctx->report_channel);
	}

	knotd_mod_ctx_set(mod, ctx);

	knotd_mod_in_hook(mod, KNOTD_STAGE_ANSWER, dnserr_query);

	return KNOT_EOK;
}

void dnserr_unload(knotd_mod_t *mod)
{
	dnserr_ctx_t *ctx = knotd_mod_ctx(mod);
	flush_set(mod, &ctx->log_cache);

	pthread_rwlock_destroy(&ctx->log_cache.flush_lock);
	free(ctx->log_cache.table);
	for (log_set_el_t *it = ctx->log_cache.table;
	     it != ctx->log_cache.table + ctx->log_cache.size;
	     ++it)
	{
		pthread_rwlock_destroy(&it->lock);
	}
	free(ctx);
}

KNOTD_MOD_API(dnserr, KNOTD_MOD_FLAG_SCOPE_ZONE,
              dnserr_load, dnserr_unload, dnserr_conf, dnserr_conf_check);
