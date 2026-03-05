/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <netinet/in.h>

#include "contrib/atomic.h"
#include "contrib/time.h"
#include "contrib/wire_ctx.h"
#include "knot/include/module.h"
#include "libknot/descriptor.h"

#define MOD_REPORT_CHANNEL "\x13""send-report-channel"
#define MOD_LOG_REPORTS    "\x12""log-report-channel"
#define MOD_CACHESIZE      "\x0e""log-cache-size"
#define MOD_TIMEOUT        "\x0b""log-timeout"

#define RESPONSE        "\x0f""Report received"
#define LOG_MESSAGE_FMT "client reported error with errno %d for record '%s' with type '%s'"

const yp_item_t dnserr_conf[] = {
	{ MOD_REPORT_CHANNEL, YP_TDNAME, YP_VNONE },
	{ MOD_LOG_REPORTS,    YP_TBOOL,  YP_VNONE },
	{ MOD_CACHESIZE,      YP_TINT,   YP_VINT =  { 1, INT32_MAX, 1000 }},
	{ MOD_TIMEOUT,        YP_TINT,   YP_VINT =  { 1, 36*24*3600, 10, YP_STIME }},
	{ NULL }
};

typedef struct {
	uint16_t err;
	uint16_t qtype;
	knot_dname_storage_t record;
} log_tuple_t;

enum state {
	EMPTY = 0,
	RESERVED = 1,
	FULL = 2
};

typedef struct {
	knot_atomic_uint16_t state;
	log_tuple_t data;
} log_set_el_t;

typedef struct {
	knot_atomic_bool lock;
	knot_atomic_size_t workers;
	size_t size;
	log_set_el_t *table;
} log_set_t;

typedef struct {
	log_set_t log_cache;
	struct timespec last_flush;
	const knot_dname_t *report_channel;
	int timeout;
	uint16_t report_channel_size;
	bool log;
} dnserr_ctx_t;

typedef struct {
	uint16_t qtypes[32];
	const uint8_t *record;
	const uint8_t *record_end;
	int err;
	uint8_t qtypes_cnt;
} dnserr_parsed_t;

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
	while (ATOMIC_GET(set->lock) == true) {} // HashSet is waiting to be flushed
	ATOMIC_ADD(set->workers, 1); // Register worker in HashSet

	/* NOTE: After some testing, limit 10 ought to be enough
	 * A larger number of iterations (search depth) is a waste of CPU time
	 * and has no real impact on HIT/MISS (except for disproportionately large
	 * tables, where a lot of iterations help).
	 */
	static const size_t limit = 10;
	uint64_t h = log_tuple_hash(val);
	int i = 1;
	for (; i < limit; ++i) {
		uint16_t wanted = RESERVED;
		uint_fast16_t expected = EMPTY;
		
		bool empty = false;
		while (!(empty = ATOMIC_CMPXCHG(set->table[h % set->size].state, expected, wanted))) {
			if (expected == FULL) {
				break;
			}
			expected = EMPTY;
		}
		if (empty) {
			break;
		}

		bool equals = log_tuple_eq(val, &set->table[h % set->size].data);
		if (equals) {
			ATOMIC_SUB(set->workers, 1);
			return KNOT_EEXIST;
		}

		// Quadratic probing
		h += i * i;
	}
	if (i == limit) {
		ATOMIC_SUB(set->workers, 1);
		return KNOT_ENOMEM;
	}

	memcpy(&set->table[h % set->size].data, val, sizeof(*val));
	ATOMIC_SET(set->table[h % set->size].state, FULL);
	ATOMIC_SUB(set->workers, 1);

	return KNOT_EOK;
}

static void flush_set(knotd_mod_t *mod, log_set_t *set)
{
	bool exp = false, des = true;
	while(!ATOMIC_CMPXCHG(set->lock, exp, des)) {
		exp = false;
	}
	while(ATOMIC_GET(set->workers) != 0) {}

	char record_str[KNOT_DNAME_TXT_MAXLEN];
	char qtype_str[32];
	for (log_set_el_t *el = set->table; el != set->table + set->size; ++el) {
		while (ATOMIC_GET(el->state) == RESERVED) {}
		if (ATOMIC_GET(el->state) == EMPTY) {
			continue;
		}

		knot_dname_to_str(record_str, el->data.record, KNOT_DNAME_TXT_MAXLEN);
		knot_rrtype_to_string(el->data.qtype, qtype_str, sizeof(qtype_str));

		knotd_mod_log(mod, LOG_WARNING, LOG_MESSAGE_FMT, el->data.err, record_str,
		              qtype_str);
		ATOMIC_SET(el->state, EMPTY);
	}

	ATOMIC_SET(set->lock, false);
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

	// Tests for some reason generate queries with 'qdata->opt_rr.rrs.count > 0'
	// and it breaks server... Don't know how else to fix this right now..
	if (ctx->report_channel != NULL && qdata->opt_rr.rrs.count > 0) {
		uint8_t *option = NULL;
		uint16_t option_size = ctx->report_channel_size;
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

	if (ctx->log) {
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
			.err = parsed.err
		};
		memcpy(ev.record, parsed.record, parsed.record_end - parsed.record);
		ev.record[parsed.record_end - parsed.record] = '\0';

		// For each QTYPE store one event into hashset
		for (int idx = 0; idx < parsed.qtypes_cnt; ++idx) {
			ev.qtype = parsed.qtypes[idx];
			hashset_add(&ctx->log_cache, &ev);
		}

		struct timespec now = time_now();
		if (time_diff(&ctx->last_flush, &now).tv_sec > ctx->timeout) {
			flush_set(mod, &ctx->log_cache);
			ctx->last_flush = now;
		}

		return KNOTD_IN_STATE_HIT;
	}

	return state;
}

int dnserr_load(knotd_mod_t *mod)
{
	dnserr_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	knotd_conf_t conf_agent = knotd_conf_mod(mod, MOD_REPORT_CHANNEL);
	ctx->report_channel = conf_agent.single.dname;
	ctx->report_channel_size = knot_dname_size(ctx->report_channel);
	knotd_conf_t conf_log = knotd_conf_mod(mod, MOD_LOG_REPORTS);
	ctx->log = conf_log.single.boolean;

	if (ctx->log) {
		knotd_conf_t conf_cachesize = knotd_conf_mod(mod, MOD_CACHESIZE);
		size_t size = conf_cachesize.single.integer;
		ctx->log_cache.size = size;
		ctx->log_cache.table = calloc(size, sizeof(log_set_el_t));
		ATOMIC_INIT(ctx->log_cache.lock, false);

		knotd_conf_t conf_timeout = knotd_conf_mod(mod, MOD_TIMEOUT);
		ctx->timeout = conf_timeout.single.integer;
	}

	knotd_mod_ctx_set(mod, ctx);

	knotd_mod_in_hook(mod, KNOTD_STAGE_ANSWER, dnserr_query);

	return KNOT_EOK;
}

void dnserr_unload(knotd_mod_t *mod)
{
	dnserr_ctx_t *ctx = knotd_mod_ctx(mod);
	flush_set(mod, &ctx->log_cache);
	free(ctx->log_cache.table);
	ATOMIC_DEINIT(ctx->log_cache.lock);
	free(ctx);
}

KNOTD_MOD_API(dnserr, KNOTD_MOD_FLAG_SCOPE_ZONE | KNOTD_MOD_FLAG_OPT_CONF,
              dnserr_load, dnserr_unload, dnserr_conf, NULL);
