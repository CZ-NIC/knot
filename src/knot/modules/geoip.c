/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <maxminddb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/modules/geoip.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/process_query.h"
#include "libknot/rrtype/opt.h"

/*
 * mod-geoip:
 *   - id: default
 *     database: /usr/share/GeoLite2/GeoLite2-Country.mmdb
 *
 * template:
 *   - id: default
 *     module: mod-geoip/default
 */

#define LOG_PREFIX "GeoIP module, "
#define geoip_error(msg...) log_error(LOG_PREFIX msg)
#define geoip_info(msg...) log_info(LOG_PREFIX msg)

const yp_item_t scheme_mod_geoip[] = {
	{ C_ID,       YP_TSTR, YP_VNONE },
	{ C_GEOIP_DB, YP_TSTR, YP_VNONE },
	{ C_COMMENT,  YP_TSTR, YP_VNONE },
	{ NULL }
};

#define GEOIP_RRTYPE 65280

struct geoip_ctx {
	MMDB_s db;
};

struct qsource {
	uint8_t *ecs_wire;
	uint16_t ecs_size;
	knot_edns_client_subnet_t ecs_data;
	struct sockaddr_storage addr;
};

struct node_config {
	char *pattern;
	char *fallback;
};

static struct geoip_ctx *geoip_ctx_new(void)
{
	return calloc(1, sizeof(struct geoip_ctx));
}

static void geoip_ctx_free(struct geoip_ctx *ctx)
{
	if (!ctx) {
		return;
	}

	MMDB_close(&ctx->db);
	free(ctx);
}

static char *get_country(struct geoip_ctx *ctx, const struct sockaddr_storage *ss)
{
	assert(ctx);
	assert(ss);

	int error = 0;
	MMDB_lookup_result_s match;
	match = MMDB_lookup_sockaddr(&ctx->db, (const struct sockaddr *)ss, &error);
	if (error != MMDB_SUCCESS) {
		return NULL;
	}

	MMDB_entry_data_s entry;
	error = MMDB_get_value(&match.entry, &entry, "country", "iso_code", NULL);
	if (error != MMDB_SUCCESS) {
		return NULL;
	}

	if (!entry.has_data || entry.type != MMDB_DATA_TYPE_UTF8_STRING) {
		return NULL;
	}

	char *country = malloc(entry.data_size + 1);
	if (!country) {
		return NULL;
	}

	memcpy(country, entry.utf8_string, entry.data_size);
	country[entry.data_size] = '\0';

	return country;
}

static int get_query_source(struct qsource *src, knot_pkt_t *pkt, struct query_data *qdata)
{
	assert(pkt);
	assert(qdata);

	uint8_t *ecs = knot_edns_get_option(&qdata->opt_rr, KNOT_EDNS_OPTION_CLIENT_SUBNET);
	if (ecs == NULL) {
		src->addr = *qdata->param->remote;
		return KNOT_EOK;
	}

	src->ecs_wire = knot_edns_opt_get_data(ecs);
	src->ecs_size = knot_edns_opt_get_length(ecs);

	int r = knot_edns_client_subnet_parse(&src->ecs_data, src->ecs_wire, src->ecs_size);
	if (r != KNOT_EOK) {
		return r;
	}

	r = knot_edns_client_subnet_get_addr(&src->addr, &src->ecs_data);
	assert(r == KNOT_EOK);

	return KNOT_EOK;
}

static int write_query_scope(knot_pkt_t *pkt, struct qsource *src)
{
	if (src->ecs_wire == NULL) {
		return KNOT_EOK;
	}

	src->ecs_data.scope_len = src->ecs_data.source_len;

	uint8_t write_size = knot_edns_client_subnet_size(&src->ecs_data);
	if (write_size == 0 || write_size < src->ecs_size) {
		return KNOT_ERROR;
	}

	return knot_edns_client_subnet_write(src->ecs_wire, src->ecs_size,
	                                     &src->ecs_data);
}

static bool get_node_config(const zone_node_t *node, struct node_config *config)
{
	knot_rrset_t rrset = node_rrset(node, GEOIP_RRTYPE);
	if (knot_rrset_empty(&rrset)) {
		return false;
	}

	knot_rdata_t *rr = knot_rdataset_at(&rrset.rrs, 0);
	uint16_t raw_len = knot_rdata_rdlen(rr);

	// format "<pattern> <default>"
	const char *raw = (char *)knot_rdata_data(rr);
	const char *sep = memchr(raw, ' ', raw_len);
	const char *end = raw + raw_len;

	if (sep == NULL) {
		return false;
	}

	config->pattern =  strndup(raw, sep - raw);
	config->fallback = strndup(sep + 1, end - sep - 1);

	return true;
}

static knot_dname_t *lookup_name(const char *pattern, const char *country,
                                 const knot_dname_t *apex)
{
	if (strlen(country) != 2) {
		return NULL;
	}

	// replace %c by country code

	char *prefix = strdup(pattern);
	if (!prefix) {
		return NULL;
	}

	char *pos = strstr(prefix, "%c");
	if (pos != NULL) {
		memcpy(pos, country, 2);
	}

	// add zone apex

	knot_dname_t *result = knot_dname_from_str_alloc(prefix);
	knot_dname_to_lower(result);
	free(prefix);

	return knot_dname_cat(result, apex);
}

static void fill_from_zone(const knot_dname_t *lookup, uint16_t rrtype, knot_pkt_t *pkt,
                           struct query_data *qdata, knot_mm_t *mm)
{
	const zone_node_t *match = NULL;
	const zone_node_t *closest = NULL;
	const zone_node_t *previous = NULL;
	int r = zone_contents_find_dname(qdata->zone->contents, lookup, &match, &closest, &previous);
	if (r != ZONE_NAME_FOUND) {
		return;
	}

	knot_rrset_t rr = node_rrset(match, rrtype);
	rr.owner = (knot_dname_t *)knot_pkt_qname(qdata->query);

	knot_rrset_t *copy = knot_rrset_copy(&rr, mm);
	knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, copy, 0);
}

static int geoip_answer(int state, knot_pkt_t *pkt, struct query_data *qdata, void *_ctx)
{
	assert(pkt);
	assert(qdata);
	assert(_ctx);

	struct geoip_ctx *ctx = _ctx;

	struct qsource qsource = { 0 };
	int r = get_query_source(&qsource, pkt, qdata);
	if (r != KNOT_EOK) {
		return ERROR;
	}

	struct node_config config = { 0 };
	if (!get_node_config(qdata->node, &config)) {
		return state;
	}

	char *country = get_country(ctx, &qsource.addr);
	if (country) {
		knot_dname_t *x = lookup_name(config.pattern, country, qdata->zone->name);
		fill_from_zone(x, knot_pkt_qtype(qdata->query), pkt, qdata, &pkt->mm);
		free(x);
	}

//	knot_rrset_t *rr;
//	rr = knot_rrset_new(owner, KNOT_RRTYPE_TXT, KNOT_CLASS_IN, &pkt->mm);
//	knot_rrset_add_rdata(rr, buffer, wrote, 0, &pkt->mm);
//	knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, rr, KNOT_PF_NULL);

	// update EDNS scope

	r = write_query_scope(pkt, &qsource);
	if (r != KNOT_EOK) {
		return ERROR;
	}

	return state;
}

static bool is_configured(conf_check_t *args, const yp_name_t *option)
{
	conf_val_t database = conf_rawid_get_txn(args->conf, args->txn,
	                                         C_MOD_GEOIP, option,
	                                         args->id, args->id_len);

	return (database.code == KNOT_EOK);
}

int geoip_check(conf_check_t *args)
{
	if (!is_configured(args, C_GEOIP_DB)) {
		args->err_str = "no database specified";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int geoip_load(struct query_plan *plan, struct query_module *self,
               const knot_dname_t *zone)
{
	assert(plan);
	assert(self);

	struct geoip_ctx *ctx = geoip_ctx_new();
	if (!ctx) {
		geoip_error("failed to allocate context");
		return KNOT_ENOMEM;
	}

	conf_val_t val = conf_mod_get(self->config, C_GEOIP_DB, self->id);
	if (val.code != KNOT_EOK) {
		return KNOT_EINVAL;
	}

	const char *db_path = conf_str(&val);

	int r = MMDB_open(db_path, 0, &ctx->db);
	if (r != MMDB_SUCCESS) {
		geoip_error("failed to open database (%s)", MMDB_strerror(r));
		geoip_ctx_free(ctx);
		return KNOT_ERROR;
	}

	query_plan_step(plan, QPLAN_ANSWER, geoip_answer, ctx);

	self->ctx = ctx;

	return KNOT_EOK;
}

int geoip_unload(struct query_module *self)
{
	assert(self);

	struct geoip_ctx *ctx = self->ctx;
	assert(self->ctx);
	geoip_ctx_free(ctx);
	self->ctx = NULL;

	return KNOT_EOK;
}
