/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/include/module.h"
#include "libknot/libknot.h"
#include "contrib/qp-trie/trie.h"
#include "contrib/mempattern.h"
#include "knot/conf/conf.h"
#include "contrib/ucw/lists.h"
#include "contrib/sockaddr.h"
#include "contrib/openbsd/strlcpy.h"
#include "contrib/string.h"
#include "libzscanner/scanner.h"

// Next dependecies force static module!
#include "knot/dnssec/rrset-sign.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/nameserver/query_module.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#if HAVE_MAXMINDDB
#include <maxminddb.h>
#endif

#define MOD_GEO_CONF_FILE "\x0D""geo-conf-file"
#define MOD_TTL "\x03""ttl"
#define MOD_MODE "\x04""mode"
#define MOD_GEODB_FILE "\x0A""geodb-file"

// MaxMind DB related constants.
#define ISO_CODE_LEN 2

enum operation_mode {
	MODE_SUBNET,
	MODE_GEODB
};

static const knot_lookup_t modes[] = {
	{ MODE_SUBNET, "subnet" },
	{ MODE_GEODB, "geodb" },
	{ 0, NULL }
};

const yp_item_t geoip_conf[] = {
	{ MOD_GEO_CONF_FILE, YP_TSTR, YP_VSTR = { "/etc/knot/geo.conf"} },
	{ MOD_TTL,           YP_TINT, YP_VINT = { 0, UINT32_MAX, 3600, YP_STIME } },
	{ MOD_MODE,          YP_TOPT, YP_VOPT = { modes, MODE_SUBNET } },
	{ MOD_GEODB_FILE,    YP_TSTR, YP_VSTR = { "" } },
	{ NULL }
};

typedef struct {
	enum operation_mode mode;
	uint32_t ttl;
	trie_t *geo_trie;

	bool dnssec;
	zone_keyset_t keyset;
	kdnssec_ctx_t kctx;

#if HAVE_MAXMINDDB
	MMDB_s db;
#endif
} geoip_ctx_t;

typedef struct {
	uint8_t prefix;
	in_addr_t addr;
} subnet_t;

typedef struct {
	char country_iso[3];
	char *city;
	uint16_t city_len;
} geodata_t;

typedef struct {
	subnet_t subnet;
	geodata_t geodata;
	size_t count, avail;
	knot_rrset_t *rrsets;
	knot_rrset_t *rrsigs;
} geo_view_t;

typedef struct {
	size_t count, avail;
	geo_view_t *views;
} geo_trie_val_t;

static int add_view_to_trie(knot_dname_t *owner, geo_view_t view, geoip_ctx_t *ctx)
{
	int ret = KNOT_EOK;

	// Find the node belonging to the owner.
	trie_val_t *val = trie_get_ins(ctx->geo_trie, (char *)owner, knot_dname_size(owner));
	geo_trie_val_t *cur_val = *val;
	if (cur_val == NULL) {
		// Create new node value.
		geo_trie_val_t *new_val = calloc(1, sizeof(geo_trie_val_t));
		new_val->avail = 1;
		new_val->count = 1;
		new_val->views = malloc(sizeof(geo_view_t));
		new_val->views[0] = view;

		// Add new value to trie.
		*val = new_val;
	} else {
		// Double the views array in size if necessary.
		if (cur_val->avail >= cur_val->count) {
			void *alloc_ret = realloc(cur_val->views,
			                          2 * cur_val->avail * sizeof(geo_view_t));
			if (alloc_ret == NULL) {
				return KNOT_ENOMEM;
			}
			cur_val->views = alloc_ret;
			cur_val->avail *= 2;
		}

		// Insert new element.
		cur_val->views[cur_val->count++] = view;
	}

	return ret;
}

static bool addr_in_subnet(in_addr_t addr, subnet_t subnet)
{
	uint8_t mask_data[sizeof(in_addr_t)] = { 0 };
	for (int i = 0; i < subnet.prefix / 8; i++) {
		mask_data[i] = UINT8_MAX;
	}
	if (subnet.prefix % 8 != 0) {
		mask_data[subnet.prefix / 8] = ((1 << (subnet.prefix % 8)) - 1) << (8 - subnet.prefix % 8);
	}
	in_addr_t *mask = (in_addr_t *)mask_data;
	return (addr & *mask) == subnet.addr;
}

static bool addr_in_geo(knotd_mod_t *mod, const struct sockaddr *addr, geodata_t geodata, uint16_t *netmask)
{
#if HAVE_MAXMINDDB
	geoip_ctx_t *ctx = (geoip_ctx_t *)knotd_mod_ctx(mod);

	int mmdb_error = 0;
	MMDB_lookup_result_s res;
	res = MMDB_lookup_sockaddr(&ctx->db, addr, &mmdb_error);
	if (mmdb_error != MMDB_SUCCESS) {
		knotd_mod_log(mod, LOG_ERR, "a lookup error in MMDB occured");
		return false;
	}
	if (!res.found_entry) {
		return false;
	}

	// Set netmask value.
	*netmask = res.netmask;

	MMDB_entry_data_s iso_entry;
	MMDB_entry_data_s city_entry;

	// Get remote country ISO code.
	mmdb_error = MMDB_get_value(&res.entry, &iso_entry, "country", "iso_code", NULL);
	if (mmdb_error != MMDB_SUCCESS) {
		knotd_mod_log(mod, LOG_ERR, "an error in MMDB occured (country)");
		return false;
	}
	if (!iso_entry.has_data || iso_entry.type != MMDB_DATA_TYPE_UTF8_STRING
	    || iso_entry.data_size != ISO_CODE_LEN) {
		return false;
	}

	// Get remote city name.
	mmdb_error = MMDB_get_value(&res.entry, &city_entry, "city", "names", "en", NULL);
	if (mmdb_error != MMDB_SUCCESS &&
	    mmdb_error != MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {
		knotd_mod_log(mod, LOG_ERR, "an error in MMDB occured (city)");
		return false;
	}

	// Compare geodata.
	if (memcmp(geodata.country_iso, iso_entry.utf8_string, ISO_CODE_LEN) != 0) {
		return false;
	}
	if (geodata.city == NULL) {
		return true;
	}
	if (!city_entry.has_data || city_entry.type != MMDB_DATA_TYPE_UTF8_STRING
	    || geodata.city_len != city_entry.data_size
	    || memcmp(geodata.city, city_entry.utf8_string, geodata.city_len)) {
		return false;
	}
	return true;
#endif
	return false;
}

static int finalize_geo_view(geo_view_t *view, knot_dname_t *owner, zone_key_t *key, geoip_ctx_t *ctx)
{
	if (view == NULL) {
		return KNOT_EOK;
	}

	int ret = KNOT_EOK;
	if (key != NULL) {
		view->rrsigs = malloc(sizeof(knot_rrset_t) * view->count);
		if (view->rrsigs == NULL) {
			return KNOT_ENOMEM;
		}
		for (size_t i = 0; i < view->count; i++) {
			knot_dname_t *owner_cpy = knot_dname_copy(owner, NULL);
			if (owner_cpy == NULL) {
				return KNOT_ENOMEM;
			}
			knot_rrset_init(&view->rrsigs[i], owner_cpy, KNOT_RRTYPE_RRSIG,
			                KNOT_CLASS_IN, ctx->ttl);
			ret = knot_sign_rrset(&view->rrsigs[i], &view->rrsets[i],
			                      key->key, key->ctx, &ctx->kctx, NULL);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	ret = add_view_to_trie(owner, *view, ctx);
	return ret;
}

static int init_geo_view(geo_view_t *view)
{
	if (view == NULL) {
		return KNOT_EINVAL;
	}

	view->count = 0;
	view->avail = 1;
	view->rrsigs = NULL;
	view->rrsets = malloc(sizeof(knot_rrset_t));
	if (view->rrsets == NULL) {
		return KNOT_ENOMEM;
	}
	return KNOT_EOK;
}

static void clear_geo_view(geo_view_t *view)
{
	if (view->geodata.city != NULL) {
		free(view->geodata.city);
	}
	for (int j = 0; j < view->count; j++) {
		knot_rrset_clear(&view->rrsets[j], NULL);
		if (view->rrsigs != NULL) {
			knot_rrset_clear(&view->rrsigs[j], NULL);
		}
	}
	free(view->rrsets);
	free(view->rrsigs);
}

static int geo_conf_yparse(knotd_mod_t *mod, geoip_ctx_t *ctx)
{
	int ret = KNOT_EOK;
	yp_parser_t *yp = NULL;
	zs_scanner_t *scanner = NULL;
	knot_dname_t owner_buff[KNOT_DNAME_MAXLEN];
	knot_dname_t *owner = NULL;
	geo_view_t *view = NULL;

	yp = malloc(sizeof(yp_parser_t));
	if (yp == NULL) {
		return KNOT_ENOMEM;
	}
	yp_init(yp);
	knotd_conf_t conf = knotd_conf_mod(mod, MOD_GEO_CONF_FILE);
	ret = yp_set_input_file(yp, conf.single.string);
	if (ret != KNOT_EOK) {
		knotd_mod_log(mod, LOG_ERR, "failed to load configuration file");
		goto cleanup;
	}

	scanner = malloc(sizeof(zs_scanner_t));
	if (scanner == NULL) {
		ret = KNOT_ENOMEM;
		goto cleanup;
	}
	if (zs_init(scanner, NULL, KNOT_CLASS_IN, ctx->ttl) != 0) {
		ret = KNOT_EPARSEFAIL;
		goto cleanup;
	}

	zone_key_t *key = NULL;
	if (ctx->dnssec) {
		for (size_t i = 0; i < ctx->keyset.count; i++) {
			if (ctx->keyset.keys[i].is_zsk) {
				key = &ctx->keyset.keys[i];
			}
		}
	}

	while (1) {
		ret = yp_parse(yp);
		if (ret == KNOT_EOF) {
			ret = finalize_geo_view(view, owner, key, ctx);
			goto cleanup;
		}
		if (ret != KNOT_EOK) {
			knotd_mod_log(mod, LOG_ERR, "failed to parse configuration file (%s)", knot_strerror(ret));
			goto cleanup;
		}

		if (yp->event != YP_EKEY1) {
			ret = finalize_geo_view(view, owner, key, ctx);
			if (ret != KNOT_EOK) {
				goto cleanup;
			}
		}

		if (yp->event == YP_EKEY0) {
			owner = knot_dname_from_str(owner_buff, yp->key, sizeof(owner_buff));
			if (owner == NULL) {
				ret = KNOT_EINVAL;
				knotd_mod_log(mod, LOG_ERR, "invalid domain name in config");
				goto cleanup;
			}

			char *set_origin = sprintf_alloc("$ORIGIN %s%s\n", yp->key,
			                                 (yp->key[yp->key_len-1] == '.') ? "" : ".");
			if (set_origin == NULL) {
				ret = KNOT_ENOMEM;
				goto cleanup;
			}
			knotd_mod_log(mod, LOG_DEBUG, "%s", set_origin);

			// Set owner as origin for future record parses.
			if (zs_set_input_string(scanner, set_origin, strlen(set_origin)) != 0
			    || zs_parse_record(scanner) != 0) {
				free(set_origin);
				ret = KNOT_EPARSEFAIL;
				goto cleanup;
			}
			free(set_origin);
		}

		// New geo view description starts.
		if (yp->event == YP_EID) {
			if (yp->data_len < 4 || yp->data[ISO_CODE_LEN] != ';') {
				ret = KNOT_EINVAL;
				goto cleanup;
			}

			// Initialize new geo view.
			free(view);
			view = malloc(sizeof(geo_view_t));
			if (view == NULL) {
				ret = KNOT_ENOMEM;
				goto cleanup;
			}
			ret = init_geo_view(view);
			if (ret != KNOT_EOK) {
				goto cleanup;
			}

			// Parse geodata/subnet. TODO more generally!
			if (ctx->mode == MODE_GEODB) {
				size_t copied = strlcpy(view->geodata.country_iso, yp->data, ISO_CODE_LEN + 1);
				view->geodata.city_len = yp->data_len - ISO_CODE_LEN - 1;
				if ( view->geodata.city_len == 0 ||
						(view->geodata.city_len == 1 && yp->data[ISO_CODE_LEN + 1] == '*')) {
					view->geodata.city = NULL;
				} else {
					view->geodata.city = malloc(view->geodata.city_len);
					copied = strlcpy(view->geodata.city, yp->data + ISO_CODE_LEN + 1,
													 view->geodata.city_len);
					if (copied != view->geodata.city_len) {
						ret = KNOT_EINVAL;
						goto cleanup;
					}
				}
			}

			if (ctx->mode == MODE_SUBNET) {
				char *slash = strchr(yp->data, '/');
				view->subnet.prefix = atoi(slash + 1);
				*slash = '\0';
				inet_pton(AF_INET, yp->data, &view->subnet.addr);
			}

		}

		// Next rrset of the current view.
		if (yp->event == YP_EKEY1) {
			uint16_t rr_type = KNOT_RRTYPE_A;
			if (knot_rrtype_from_string(yp->key, &rr_type) != 0) {
				knotd_mod_log(mod, LOG_ERR, "invalid RR type in config");
				ret = KNOT_EINVAL;
				goto cleanup;
			}

			knot_rrset_t *add_rr = NULL;
			for (size_t i = 0; i < view->count; i++) {
				if (view->rrsets[i].type == rr_type) {
					add_rr = &view->rrsets[i];
					break;
				}
			}

			if (add_rr == NULL) {
				if (view->count == view->avail) {
					void *alloc_ret = realloc(view->rrsets,
					                             2 * view->avail * sizeof(knot_rrset_t));
					if (alloc_ret == NULL) {
						ret = KNOT_ENOMEM;
						goto cleanup;
					}
					view->rrsets = alloc_ret;
				}
				add_rr = &view->rrsets[view->count++];
				knot_dname_t *owner_cpy = knot_dname_copy(owner, NULL);
				if (owner_cpy == NULL) {
					return KNOT_ENOMEM;
				}
				knot_rrset_init(add_rr, owner_cpy, rr_type, KNOT_CLASS_IN, ctx->ttl);
			}

			// Parse record.
			char *input_string = sprintf_alloc("@ %s %s\n", yp->key, yp->data);
			if (input_string == NULL) {
				ret = KNOT_ENOMEM;
				goto cleanup;
			}
			knotd_mod_log(mod, LOG_DEBUG, "%s", input_string);

			if (zs_set_input_string(scanner, input_string, strlen(input_string)) != 0 ||
			    zs_parse_record(scanner) != 0 ||
			    scanner->state != ZS_STATE_DATA) {
				free(input_string);
				ret = KNOT_EPARSEFAIL;
				goto cleanup;
			}
			free(input_string);

			// Add new rdata to current rrset.
			ret = knot_rrset_add_rdata(add_rr, scanner->r_data, scanner->r_data_length, NULL);
			if (ret != KNOT_EOK) {
				goto cleanup;
			}
		}
	}

	cleanup:
	if (ret != KNOT_EOK) {
		clear_geo_view(view);
	}
	free(view);
	zs_deinit(scanner);
	free(scanner);
	yp_deinit(yp);
	free(yp);
	return ret;
}

static void clear_geo_trie(trie_t *trie)
{
	trie_it_t *it = trie_it_begin(trie);
	while (!trie_it_finished(it)) {
		geo_trie_val_t *val = (geo_trie_val_t *) (*trie_it_val(it));
		for (int i = 0; i < val->count; i++) {
			clear_geo_view(&val->views[i]);
		}
		free(val->views);
		free(val);
		trie_it_next(it);
	}
	trie_it_free(it);
	trie_clear(trie);
}

void clear_geo_ctx(geoip_ctx_t *ctx)
{
	kdnssec_ctx_deinit(&ctx->kctx);
	free_zone_keys(&ctx->keyset);
#if HAVE_MAXMINDDB
	MMDB_close(&ctx->db);
#endif
	clear_geo_trie(ctx->geo_trie);
	trie_free(ctx->geo_trie);
}

static knotd_in_state_t geoip_process(knotd_in_state_t state, knot_pkt_t *pkt,
                                   knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	geoip_ctx_t *ctx = (geoip_ctx_t *)knotd_mod_ctx(mod);

	// Geolocate only A or AAAA records.
	uint16_t qtype = knot_pkt_qtype(qdata->query);
	if (qtype != KNOT_RRTYPE_A && qtype != KNOT_RRTYPE_AAAA) {
		return state;
	}

	// Check if geolocation is available for given query.
	knot_dname_t *qname = knot_pkt_qname(qdata->query);
	size_t qname_len = knot_dname_size(qname);
	trie_val_t *val = trie_get_try(ctx->geo_trie, (char *)qname, qname_len);
	if (val == NULL) {
		// Nothing to do in this module.
		return state;
	}

	geo_trie_val_t *data = *val;

	// Check if EDNS Client Subnet is available.
	const struct sockaddr_storage *remote = NULL;
	if (knot_edns_client_subnet_get_addr((struct sockaddr_storage *)remote, qdata->ecs) != KNOT_EOK) {
		remote = qdata->params->remote;
	}

	if (ctx->mode == MODE_SUBNET) {
		in_addr_t addr = ((struct sockaddr_in *)remote)->sin_addr.s_addr;

		// Check whether the remote falls into any geo subnet.
		for (int i = 0; i < data->count; i++) {
			if (addr_in_subnet(addr, data->views[i].subnet)) {
				// Update ECS if used.
				if (qdata->ecs != NULL) {
					qdata->ecs->scope_len = data->views[i].subnet.prefix;
				}

				knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, &data->views[i].rrsets[0], 0);
				if (ctx->dnssec && knot_pkt_has_dnssec(qdata->query)) {
					knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, &data->views[i].rrsigs[0], 0);
				}
				return KNOTD_IN_STATE_HIT;
			}
		}
	}

	if (ctx->mode == MODE_GEODB) {
		// Check whether the remote falls into any geo location.
		for (int i = 0; i < data->count; i++) {
			uint16_t netmask = 0;
			if (addr_in_geo(mod, (const struct sockaddr *)remote, data->views[i].geodata, &netmask)) {
				// Update ECS if used.
				if (qdata->ecs != NULL) {
					qdata->ecs->scope_len = netmask;
				}

				knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, &data->views[i].rrsets[0], 0);
				if (ctx->dnssec && knot_pkt_has_dnssec(qdata->query)) {
					knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, &data->views[i].rrsigs[0], 0);
				}
				return KNOTD_IN_STATE_HIT;
			}
		}
	}

	// Dump found rrsets for debug reasons.
	for (int i = 0; i < data->count; i++) {
		size_t dump_size = 1024;
		char *txt_dump = malloc(dump_size);
		knot_rrset_txt_dump(&data->views[i].rrsets[0], &txt_dump, &dump_size, &KNOT_DUMP_STYLE_DEFAULT);
		knotd_mod_log(mod, LOG_DEBUG, "%s", txt_dump);
		free(txt_dump);
	}

	return state;
}

int geoip_load(knotd_mod_t *mod)
{
	// Create module context.
	geoip_ctx_t *ctx = calloc(1, sizeof(geoip_ctx_t));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	knotd_conf_t conf = knotd_conf_mod(mod, MOD_TTL);
	ctx->ttl = conf.single.integer;
	conf = knotd_conf_mod(mod, MOD_MODE);
	ctx->mode = conf.single.option;

	// Initialize the dname trie.
	ctx->geo_trie = trie_create(NULL);

	int ret;

	// Initialize geodb if configured.
#if HAVE_MAXMINDDB
	if (ctx->mode == MODE_GEODB) {
		conf = knotd_conf_mod(mod, MOD_GEODB_FILE);
		ret = MMDB_open(conf.single.string, MMDB_MODE_MMAP, &ctx->db);
		if (ret != MMDB_SUCCESS) {
			knotd_mod_log(mod, LOG_ERR, "failed to open Geo DB");
			return KNOT_EINVAL;
		}
	}
#endif

	// Is DNSSEC used on this zone?
	conf = knotd_conf_zone(mod, C_DNSSEC_SIGNING, knotd_mod_zone(mod));
	ctx->dnssec = conf.single.boolean;
	if (ctx->dnssec) {
		ret = kdnssec_ctx_init(mod->config, &ctx->kctx, knotd_mod_zone(mod), NULL);
		if (ret != KNOT_EOK) {
			clear_geo_ctx(ctx);
			free(ctx);
			return ret;
		}
		ret = load_zone_keys(&ctx->kctx, &ctx->keyset, false);
		if (ret != KNOT_EOK) {
			knotd_mod_log(mod, LOG_ERR, "failed to load keys");
			clear_geo_ctx(ctx);
			free(ctx);
			return ret;
		}
	}

	// Parse geo configuration file.
	ret = geo_conf_yparse(mod, ctx);
	if (ret != KNOT_EOK) {
		knotd_mod_log(mod, LOG_ERR, "failed to load geo configuration");
		clear_geo_ctx(ctx);
		free(ctx);
		return ret;
	}

	knotd_mod_ctx_set(mod, ctx);

	return knotd_mod_in_hook(mod, KNOTD_STAGE_BEGIN, geoip_process);
}

void geoip_unload(knotd_mod_t *mod)
{
	geoip_ctx_t *ctx = knotd_mod_ctx(mod);
	if (ctx != NULL) {
		clear_geo_ctx(ctx);
	}
	free(ctx);
	assert(mod);
}

KNOTD_MOD_API(geoip, KNOTD_MOD_FLAG_SCOPE_ZONE | KNOTD_MOD_FLAG_OPT_CONF,
              geoip_load, geoip_unload, geoip_conf, NULL);
