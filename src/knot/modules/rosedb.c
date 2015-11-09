/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <lmdb.h>

#include "dnssec/random.h"
#include "knot/common/log.h"
#include "knot/modules/rosedb.h"
#include "knot/nameserver/process_query.h"
#include "libknot/libknot.h"
#include "libknot/internal/net.h"
#include "libknot/internal/utils.h"

/* Module configuration scheme. */
#define MOD_DBDIR		"\x05""dbdir"

const yp_item_t scheme_mod_rosedb[] = {
	{ C_ID,      YP_TSTR, YP_VNONE },
	{ MOD_DBDIR, YP_TSTR, YP_VNONE },
	{ C_COMMENT, YP_TSTR, YP_VNONE },
	{ NULL }
};

int check_mod_rosedb(conf_check_t *args)
{
	conf_val_t dir = conf_rawid_get_txn(args->conf, args->txn, C_MOD_ROSEDB,
	                                    MOD_DBDIR, args->id, args->id_len);
	if (dir.code != KNOT_EOK) {
		args->err_str = "no database directory specified";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

/*! \note Below is an implementation of basic RR cache in LMDB,
 *        it shall be replaced with the namedb API later, when
 *        it supports multiple dbs + the basic "node" representation,
 *        as the cache implementation requires DUPSORT.
 */

#define LMDB_MAPSIZE (100 * 1024 * 1024)

struct cache
{
	MDB_dbi dbi;
	MDB_env *env;
	mm_ctx_t *pool;
};

struct rdentry {
	uint16_t type;
	knot_rdataset_t rrs;
};

struct entry {
	struct rdentry data;
	const char *threat_code;
	const char *syslog_ip;
	MDB_cursor *cursor;
};

struct iter {
	MDB_cursor *cur;
	MDB_val key;
	MDB_val val;
};

/*                       MDB access                                           */

static int dbase_open(struct cache *cache, const char *handle)
{
	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) {
		return KNOT_EINVAL;
	}

	int ret = mdb_env_create(&cache->env);
	if (ret != 0) {
		return ret;
	}

	size_t map_size = (LMDB_MAPSIZE / page_size) * page_size;
	ret = mdb_env_set_mapsize(cache->env, map_size);
	if (ret != 0) {
		mdb_env_close(cache->env);
		return ret;
	}

	ret = mdb_env_open(cache->env, handle, 0, 0644);
	if (ret != 0) {
		mdb_env_close(cache->env);
		return ret;
	}

	MDB_txn *txn = NULL;
	ret = mdb_txn_begin(cache->env, NULL, 0, &txn);
	if (ret != 0) {
		mdb_env_close(cache->env);
		return ret;
	}

	ret = mdb_open(txn, NULL, MDB_DUPSORT, &cache->dbi);
	if (ret != 0) {
		mdb_txn_abort(txn);
		mdb_env_close(cache->env);
		return ret;
	}

	ret = mdb_txn_commit(txn);
	if (ret != 0) {
		mdb_env_close(cache->env);
		return ret;
	}

	return 0;
}

static void dbase_close(struct cache *cache)
{
	mdb_close(cache->env, cache->dbi);
	mdb_env_close(cache->env);
}

/*                       data access                                          */

static MDB_cursor *cursor_acquire(MDB_txn *txn, MDB_dbi dbi)
{
	MDB_cursor *cursor = NULL;

	int ret = mdb_cursor_open(txn, dbi, &cursor);
	if (ret != 0) {
		return NULL;
	}

	return cursor;
}

static void cursor_release(MDB_cursor *cursor)
{
	mdb_cursor_close(cursor);
}

/*                       data serialization                                   */

#define ENTRY_MAXLEN 65535
#define PACKED_LEN(str) (strlen(str) + 1) /* length of packed string including terminal byte */
static inline void pack_str(char **stream, const char *str) {
	int len = PACKED_LEN(str);
	memcpy(*stream, str, len);
	*stream += len;
}

static inline char *unpack_str(char **stream) {
	char *ret = *stream;
	*stream += PACKED_LEN(ret);
	return ret;
}

static inline void pack_bin(char **stream, const void *data, uint32_t len) {
	wire_write_u32((uint8_t *)*stream, len);
	*stream += sizeof(uint32_t);
	memcpy(*stream, data, len);
	*stream += len;
}

static inline void *unpack_bin(char **stream, uint32_t *len) {
	*len = wire_read_u32((uint8_t *)*stream);
	*stream += sizeof(uint32_t);
	void *ret = *stream;
	*stream += *len;
	return ret;
}

static MDB_val pack_key(const knot_dname_t *name)
{
	MDB_val key = { knot_dname_size(name), (void *)name };
	return key;
}

static int pack_entry(MDB_val *data, struct entry *entry)
{
	char *stream = data->mv_data;
	char *bptr = stream;
	pack_bin(&stream, &entry->data.type, sizeof(entry->data.type));
	knot_rdataset_t *rrs = &entry->data.rrs;
	pack_bin(&stream, &rrs->rr_count, sizeof(rrs->rr_count));
	pack_bin(&stream, rrs->data, knot_rdataset_size(rrs));

	pack_str(&stream, entry->threat_code);
	pack_str(&stream, entry->syslog_ip);

	data->mv_size = (stream - bptr);
	return KNOT_EOK;
}

static int unpack_entry(MDB_val *data, struct entry *entry)
{
	uint32_t len = 0;
	void *val = NULL;
	char *stream = data->mv_data;

	val = unpack_bin(&stream, &len);
	memcpy(&entry->data.type, val, sizeof(uint16_t));

	knot_rdataset_t *rrs = &entry->data.rrs;
	val = unpack_bin(&stream, &len);
	memcpy(&rrs->rr_count, val, sizeof(uint16_t));
	rrs->data = unpack_bin(&stream, &len);

	entry->threat_code = unpack_str(&stream);
	entry->syslog_ip = unpack_str(&stream);

	return KNOT_EOK;
}

static int remove_entry(MDB_cursor *cur)
{
	int ret = mdb_cursor_del(cur, MDB_NODUPDATA);
	if (ret != 0) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

/*                       database api                                   */

struct cache *cache_open(const char *handle, unsigned flags, mm_ctx_t *mm)
{
	struct cache *cache = mm_alloc(mm, sizeof(struct cache));
	if (cache == NULL) {
		return NULL;
	}
	memset(cache, 0, sizeof(struct cache));

	int ret = dbase_open(cache, handle);
	if (ret != 0) {
		mm_free(mm, cache);
		return NULL;
	}

	cache->pool = mm;
	return cache;
}

void cache_close(struct cache *cache)
{
	if (cache == NULL) {
		return;
	}

	dbase_close(cache);
	mm_free(cache->pool, cache);
}

static int cache_iter_begin(struct iter *it, const knot_dname_t *name)
{
	it->key = pack_key(name);
	it->val.mv_data = NULL;
	it->val.mv_size = 0;

	return mdb_cursor_get(it->cur, &it->key, &it->val, MDB_SET_KEY);
}

static int cache_iter_next(struct iter *it)
{
	return mdb_cursor_get(it->cur, &it->key, &it->val, MDB_NEXT_DUP);
}

static int cache_iter_val(struct iter *it, struct entry *entry)
{
	return unpack_entry(&it->val, entry);
}

static void cache_iter_free(struct iter *it)
{
	mdb_cursor_close(it->cur);
	it->cur = NULL;
}

int cache_query_fetch(MDB_txn *txn, MDB_dbi dbi, struct iter *it, const knot_dname_t *name)
{
	it->cur = cursor_acquire(txn, dbi);
	if (it->cur == NULL) {
		return KNOT_ERROR;
	}

	int ret = cache_iter_begin(it, name);
	if (ret != 0) {
		cache_iter_free(it);
		return KNOT_ENOENT;
	}

	return KNOT_EOK;
}

int cache_insert(MDB_txn *txn, MDB_dbi dbi, const knot_dname_t *name, struct entry *entry)
{
	MDB_cursor *cursor = cursor_acquire(txn, dbi);
	if (cursor == NULL) {
		return KNOT_ERROR;
	}

	MDB_val key = pack_key(name);
	MDB_val data = { 0, malloc(ENTRY_MAXLEN) };

	int ret = pack_entry(&data, entry);
	if (ret != KNOT_EOK) {
		free(data.mv_data);
		return ret;
	}

	ret = mdb_cursor_put(cursor, &key, &data, 0);
	free(data.mv_data);
	cursor_release(cursor);

	return ret;
}

int cache_remove(MDB_txn *txn, MDB_dbi dbi, const knot_dname_t *name)
{
	struct iter it;
	it.cur = cursor_acquire(txn, dbi);
	if (it.cur == NULL) {
		return KNOT_ERROR;
	}

	int ret = cache_iter_begin(&it, name);
	if (ret == 0) {
		ret = remove_entry(it.cur);
	}

	cursor_release(it.cur);
	return ret;
}

/*                       module callbacks                                   */

#define DEFAULT_PORT 514
#define SYSLOG_BUFLEN 1024 /* RFC3164, 4.1 message size. */
#define SYSLOG_FACILITY 3  /* System daemon. */

/*! \brief Safe stream skipping. */
static int stream_skip(char **stream, size_t *maxlen, int nbytes)
{
	/* Error or space limit exceeded. */
	if (nbytes < 0 || nbytes >= *maxlen) {
		return KNOT_ESPACE;
	}

	*stream += nbytes;
	*maxlen -= nbytes;
	return 0;
}

/*! \brief Stream write with constraints checks. */
#define STREAM_WRITE(stream, maxlen, fn, args, ...) \
	if (stream_skip(&(stream), (maxlen), fn(stream, *(maxlen), args, ##__VA_ARGS__)) != KNOT_EOK) { \
		return KNOT_ESPACE; \
	}

static int rosedb_log_message(char *stream, size_t *maxlen, knot_pkt_t *pkt,
                              const char *threat_code, struct query_data *qdata)
{
	char dname_buf[KNOT_DNAME_MAXLEN] = {'\0'};
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	time_t now = time(NULL);
	struct tm tm;
	gmtime_r(&now, &tm);

	/* Field 1 Timestamp (UTC). */
	STREAM_WRITE(stream, maxlen, strftime, "%Y-%m-%d %H:%M:%S\t", &tm);

	/* Field 2/3 Remote, local address. */
	const struct sockaddr *remote = (const struct sockaddr *)qdata->param->remote;
	memcpy(&addr, remote, sockaddr_len(remote));
	int client_port = sockaddr_port(&addr);
	sockaddr_port_set(&addr, 0);
	STREAM_WRITE(stream, maxlen, sockaddr_tostr, &addr);
	STREAM_WRITE(stream, maxlen, snprintf, "\t");
	getsockname(qdata->param->socket, (struct sockaddr *)&addr, &addr_len);
	int server_port = sockaddr_port(&addr);
	sockaddr_port_set(&addr, 0);
	STREAM_WRITE(stream, maxlen, sockaddr_tostr, &addr);
	STREAM_WRITE(stream, maxlen, snprintf, "\t");

	/* Field 4/5 Local, remote port. */
	STREAM_WRITE(stream, maxlen, snprintf, "%d\t%d\t", client_port, server_port);

	/* Field 6 Threat ID. */
	STREAM_WRITE(stream, maxlen, snprintf, "%s\t", threat_code);

	/* Field 7 - 13 NULL */
	STREAM_WRITE(stream, maxlen, snprintf, "\t\t\t\t\t\t\t");

	/* Field 14 QNAME */
	knot_dname_to_str(dname_buf, knot_pkt_qname(qdata->query), sizeof(dname_buf));
	STREAM_WRITE(stream, maxlen, snprintf, "%s\t", dname_buf);

	/* Field 15 Resolution (0 = local, 1 = lookup)*/
	STREAM_WRITE(stream, maxlen, snprintf, "0\t");

	/* Field 16 RDATA.
	 * - Return randomly RDATA in the answer section (probabilistic rotation).
	 * - Empty if no answer.
	 */
	const knot_pktsection_t *ans = knot_pkt_section(pkt, KNOT_ANSWER);
	if (ans->count > 0) {
		const knot_rrset_t *rr = knot_pkt_rr(ans, dnssec_random_uint16_t() % ans->count);
		int ret = knot_rrset_txt_dump_data(rr, 0, stream, *maxlen, &KNOT_DUMP_STYLE_DEFAULT);
		if (ret < 0) {
			return ret;
		}
		stream_skip(&stream, maxlen, ret);
	}
	STREAM_WRITE(stream, maxlen, snprintf, "\t");

	/* Field 17 Connection type. */
	STREAM_WRITE(stream, maxlen, snprintf, "%s\t",
	             net_is_stream(qdata->param->socket) ? "TCP" : "UDP");

	/* Field 18 Query type. */
	char type_str[16] = { '\0' };
	knot_rrtype_to_string(knot_pkt_qtype(qdata->query), type_str, sizeof(type_str));
	STREAM_WRITE(stream, maxlen, snprintf, "%s\t", type_str);

	/* Field 19 First authority. */
	const knot_pktsection_t *ns = knot_pkt_section(pkt, KNOT_AUTHORITY);
	if (ns->count > 0 && knot_pkt_rr(ns, 0)->type == KNOT_RRTYPE_NS) {
		const knot_dname_t *label = knot_ns_name(&knot_pkt_rr(ns, 0)->rrs, 0);
		memset(dname_buf, 0, sizeof(dname_buf));
		memcpy(dname_buf, label + 1, *label);
		STREAM_WRITE(stream, maxlen, snprintf, "%s", dname_buf);
	}

	return KNOT_EOK;
}

static int rosedb_send_log(int sock, struct sockaddr_storage *dst_addr, knot_pkt_t *pkt,
                           const char *threat_code, struct query_data *qdata)
{
	char buf[SYSLOG_BUFLEN];
	char *stream = buf;
	size_t maxlen = sizeof(buf);

	time_t now = time(NULL);
	struct tm tm;
	localtime_r(&now, &tm);

	/* Add facility. */
	STREAM_WRITE(stream, &maxlen, snprintf, "<%u>", SYSLOG_FACILITY);

	/* Current local time (4.3.2)*/
	STREAM_WRITE(stream, &maxlen, strftime, "%b %d %H:%M:%S ", &tm);

	/* Host name / Component. */
	conf_val_t val = conf_get(conf(), C_SRV, C_IDENT);
	if (val.code != KNOT_EOK || val.len <= 1) {
		STREAM_WRITE(stream, &maxlen, snprintf, "%s ", conf()->hostname);
	} else {
		STREAM_WRITE(stream, &maxlen, snprintf, "%s ", conf_str(&val));
	}
	STREAM_WRITE(stream, &maxlen, snprintf, "%s[%lu]: ", PACKAGE_NAME, (unsigned long) getpid());

	/* Prepare log message line. */
	int ret = rosedb_log_message(stream, &maxlen, pkt, threat_code, qdata);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Send log message line. */
	net_dgram_send(sock, (uint8_t *)buf, sizeof(buf) - maxlen, dst_addr);

	return ret;
}

static int rosedb_synth_rr(knot_pkt_t *pkt, struct entry *entry, uint16_t qtype)
{
	if (qtype != entry->data.type) {
		return KNOT_EOK; /* Ignore */
	}

	knot_rrset_t *rr = knot_rrset_new(knot_pkt_qname(pkt), entry->data.type, KNOT_CLASS_IN, &pkt->mm);
	int ret = knot_rdataset_copy(&rr->rrs, &entry->data.rrs, &pkt->mm);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, rr, KNOT_PF_FREE);

	return ret;
}

static int rosedb_synth(knot_pkt_t *pkt, const knot_dname_t *key, struct iter *it,
                        struct query_data *qdata)
{
	struct entry entry;
	int ret = KNOT_EOK;
	uint16_t qtype = knot_pkt_qtype(qdata->query);

	/* Answer section. */
	while (ret == KNOT_EOK) {
		if (cache_iter_val(it, &entry) == 0) {
			ret = rosedb_synth_rr(pkt, &entry, qtype);
		}
		if (cache_iter_next(it) != 0) {
			break;
		}
	}

	/* Authority section. */
	knot_pkt_begin(pkt, KNOT_AUTHORITY);

	/* Not found (zone cut if records exist). */
	ret = cache_iter_begin(it, key);
	while (ret == KNOT_EOK) {
		if (cache_iter_val(it, &entry) == 0) {
			ret = rosedb_synth_rr(pkt, &entry, KNOT_RRTYPE_NS);
			ret = rosedb_synth_rr(pkt, &entry, KNOT_RRTYPE_SOA);
		}
		if (cache_iter_next(it) != 0) {
			break;
		}
	}

	/* Our response is authoritative. */
	if (knot_wire_get_nscount(pkt->wire) > 0) {
		knot_wire_set_aa(pkt->wire);
		if (knot_wire_get_ancount(pkt->wire) == 0) {
			qdata->rcode = KNOT_RCODE_NXDOMAIN;
		}
	}

	/* Send message to syslog. */
	struct sockaddr_storage syslog_addr;
	if (sockaddr_set(&syslog_addr, AF_INET, entry.syslog_ip, DEFAULT_PORT) == KNOT_EOK) {
		int sock = net_unbound_socket(SOCK_DGRAM, &syslog_addr);
		if (sock > 0) {
			rosedb_send_log(sock, &syslog_addr, pkt,
			                entry.threat_code, qdata);
			close(sock);
		}
	}

	return ret;
}

static int rosedb_query_txn(MDB_txn *txn, MDB_dbi dbi, knot_pkt_t *pkt, struct query_data *qdata)
{
	struct iter it;
	int ret = KNOT_EOK;

	/* Find suffix for QNAME. */
	const knot_dname_t *qname = knot_pkt_qname(qdata->query);
	const knot_dname_t *key = qname;
	while (key) {
		ret = cache_query_fetch(txn, dbi, &it, key);
		if (ret == 0) { /* Found */
			break;
		}

		if (*key == '\0') { /* Last label, not found. */
			return KNOT_ENOENT;
		}

		key = knot_wire_next_label(key, qdata->query->wire);
	}

	/* Synthetize record to response. */
	ret = rosedb_synth(pkt, key, &it, qdata);

	cache_iter_free(&it);
	return ret;
}

static int rosedb_query(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	if (pkt == NULL || qdata == NULL || ctx == NULL) {
		return KNOT_STATE_FAIL;
	}

	struct cache *cache = ctx;

	MDB_txn *txn = NULL;
	int ret = mdb_txn_begin(cache->env, NULL, MDB_RDONLY, &txn);
	if (ret != 0) { /* Can't start transaction, ignore. */
		return state;
	}

	ret = rosedb_query_txn(txn, cache->dbi, pkt, qdata);
	if (ret != 0) { /* Can't find matching zone, ignore. */
		mdb_txn_abort(txn);
		return state;
	}

	mdb_txn_abort(txn);

	return KNOT_STATE_DONE;
}

int rosedb_load(struct query_plan *plan, struct query_module *self,
                const knot_dname_t *zone)
{
	if (plan == NULL || self == NULL) {
		return KNOT_EINVAL;
	}

	conf_val_t val = conf_mod_get(self->config, MOD_DBDIR, self->id);
	struct cache *cache = cache_open(conf_str(&val), 0, self->mm);
	if (cache == NULL) {
		MODULE_ERR(C_MOD_ROSEDB, "failed to open db '%s'", conf_str(&val));
		return KNOT_ENOMEM;
	}

	self->ctx = cache;

	return query_plan_step(plan, QPLAN_BEGIN, rosedb_query, self->ctx);
}

int rosedb_unload(struct query_module *self)
{
	if (self == NULL) {
		return KNOT_EINVAL;
	}

	cache_close(self->ctx);
	return KNOT_EOK;
}
