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

struct geoip_ctx {
	MMDB_s db;
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

static int geoip_addional(int state, knot_pkt_t *pkt, struct query_data *qdata, void *_ctx)
{
	assert(pkt);
	assert(qdata);
	assert(_ctx);

	struct geoip_ctx *ctx = _ctx;

	// synthesize TXT record with country of the originating query

	const knot_dname_t *owner = (uint8_t *)"\x7""country""\x5""geoip";

	char *country = get_country(ctx, qdata->param->remote);
	const char *country_write = country ? country : "unknown";

	uint8_t buffer[16] = { 0 };
	int wrote = snprintf((char *)buffer, sizeof(buffer), "%c%s",
				(int)strlen(country_write), country_write);
	free(country);
	if (wrote < 0) {
		return ERROR;
	}

	knot_rrset_t *rr;
	rr = knot_rrset_new(owner, KNOT_RRTYPE_TXT, KNOT_CLASS_IN, &pkt->mm);
	knot_rrset_add_rdata(rr, buffer, wrote, 0, &pkt->mm);
	knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, rr, KNOT_PF_NULL);

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

	query_plan_step(plan, QPLAN_ADDITIONAL, geoip_addional, ctx);

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
