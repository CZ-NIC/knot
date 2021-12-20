/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "knot/conf/schema.h"
#include "knot/include/module.h"
#include "knot/modules/geoip/geodb.h"
#include "libknot/libknot.h"
#include "contrib/qp-trie/trie.h"
#include "contrib/ucw/lists.h"
#include "contrib/macros.h"
#include "contrib/sockaddr.h"
#include "contrib/string.h"
#include "contrib/strtonum.h"
#include "libdnssec/random.h"
#include "libzscanner/scanner.h"

#define MOD_CONFIG_FILE	"\x0B""config-file"
#define MOD_TTL		"\x03""ttl"
#define MOD_MODE	"\x04""mode"
#define MOD_DNSSEC	"\x06""dnssec"
#define MOD_POLICY	"\x06""policy"
#define MOD_GEODB_FILE	"\x0A""geodb-file"
#define MOD_GEODB_KEY	"\x09""geodb-key"

enum operation_mode {
	MODE_SUBNET,
	MODE_GEODB,
	MODE_WEIGHTED
};

static const knot_lookup_t modes[] = {
	{ MODE_SUBNET,   "subnet" },
	{ MODE_GEODB,    "geodb" },
	{ MODE_WEIGHTED, "weighted" },
	{ 0, NULL }
};

static const char* mode_key[] = {
	[MODE_SUBNET]   = "net",
	[MODE_GEODB]    = "geo",
	[MODE_WEIGHTED] = "weight"
};

const yp_item_t geoip_conf[] = {
	{ MOD_CONFIG_FILE, YP_TSTR,  YP_VNONE },
	{ MOD_TTL,         YP_TINT,  YP_VINT = { 0, UINT32_MAX, 60, YP_STIME } },
	{ MOD_MODE,        YP_TOPT,  YP_VOPT = { modes, MODE_SUBNET} },
	{ MOD_DNSSEC,      YP_TBOOL, YP_VNONE },
	{ MOD_POLICY,      YP_TREF,  YP_VREF = { C_POLICY }, YP_FNONE, { knotd_conf_check_ref } },
	{ MOD_GEODB_FILE,  YP_TSTR,  YP_VNONE },
	{ MOD_GEODB_KEY,   YP_TSTR,  YP_VSTR = { "country/iso_code" }, YP_FMULTI },
	{ NULL }
};

char geoip_check_str[1024];

typedef struct {
	knotd_conf_check_args_t	*args; // Set for a dry run.
	knotd_mod_t *mod;              // Set for a real module load.
} check_ctx_t;

static int load_module(check_ctx_t *ctx);

int geoip_conf_check(knotd_conf_check_args_t *args)
{
	knotd_conf_t conf = knotd_conf_check_item(args, MOD_CONFIG_FILE);
	if (conf.count == 0) {
		args->err_str = "no configuration file specified";
		return KNOT_EINVAL;
	}
	conf = knotd_conf_check_item(args, MOD_MODE);
	if (conf.count == 1 && conf.single.option == MODE_GEODB) {
		if (!geodb_available()) {
			args->err_str = "geodb mode not available";
			return KNOT_EINVAL;
		}

		conf = knotd_conf_check_item(args, MOD_GEODB_FILE);
		if (conf.count == 0) {
			args->err_str = "no geodb file specified while in geodb mode";
			return KNOT_EINVAL;
		}

		conf = knotd_conf_check_item(args, MOD_GEODB_KEY);
		if (conf.count > GEODB_MAX_DEPTH) {
			args->err_str = "maximal number of geodb-key items exceeded";
			return KNOT_EINVAL;
		}
		for (size_t i = 0; i < conf.count; i++) {
			geodb_path_t path;
			if (parse_geodb_path(&path, (char *)conf.multi[i].string) != 0) {
				args->err_str = "unrecognized geodb-key format";
				return KNOT_EINVAL;
			}
		}
		knotd_conf_free(&conf);
	}

	check_ctx_t check = { .args = args };
	return load_module(&check);
}

typedef struct {
	enum operation_mode mode;
	uint32_t ttl;
	trie_t *geo_trie;
	bool dnssec;

	geodb_t *geodb;
	geodb_path_t paths[GEODB_MAX_DEPTH];
	uint16_t path_count;
} geoip_ctx_t;

typedef struct {
	struct sockaddr_storage *subnet;
	uint8_t subnet_prefix;

	void *geodata[GEODB_MAX_DEPTH]; // NULL if '*' is specified in config.
	uint32_t geodata_len[GEODB_MAX_DEPTH];
	uint8_t geodepth;

	uint16_t weight;

	// Index of the "parent" in the sorted view list.
	// Equal to its own index if there is no parent.
	size_t prev;

	size_t count, avail;
	knot_rrset_t *rrsets;
	knot_rrset_t *rrsigs;

	knot_dname_t *cname;
} geo_view_t;

typedef struct {
	size_t count, avail;
	geo_view_t *views;
	uint16_t total_weight;
} geo_trie_val_t;

typedef int (*view_cmp_t)(const void *a, const void *b);

int geodb_view_cmp(const void *a, const void *b)
{
	geo_view_t *va = (geo_view_t *)a;
	geo_view_t *vb = (geo_view_t *)b;

	int i = 0;
	while (i < va->geodepth && i < vb->geodepth) {
		if (va->geodata[i] == NULL) {
			if (vb->geodata[i] != NULL) {
				return -1;
			}
		} else {
			if (vb->geodata[i] == NULL) {
				return 1;
			}
			int len = MIN(va->geodata_len[i], vb->geodata_len[i]);
			int ret = memcmp(va->geodata[i], vb->geodata[i], len);
			if (ret < 0 || (ret == 0 && vb->geodata_len[i] > len)) {
				return -1;
			} else if (ret > 0 || (ret == 0 && va->geodata_len[i] > len)) {
				return 1;
			}
		}
		i++;
	}
	if (i < va->geodepth) {
		return 1;
	}
	if (i < vb->geodepth) {
		return -1;
	}
	return 0;
}

int subnet_view_cmp(const void *a, const void *b)
{
	geo_view_t *va = (geo_view_t *)a;
	geo_view_t *vb = (geo_view_t *)b;

	if (va->subnet->ss_family != vb->subnet->ss_family) {
		return va->subnet->ss_family - vb->subnet->ss_family;
	}

	int ret = 0;
	switch (va->subnet->ss_family) {
	case AF_INET:
		ret = memcmp(&((struct sockaddr_in *)va->subnet)->sin_addr,
		             &((struct sockaddr_in *)vb->subnet)->sin_addr,
		             sizeof(struct in_addr));
		break;
	case AF_INET6:
		ret = memcmp(&((struct sockaddr_in6 *)va->subnet)->sin6_addr,
		             &((struct sockaddr_in6 *)vb->subnet)->sin6_addr,
		             sizeof(struct in6_addr));
	}
	if (ret == 0) {
		return va->subnet_prefix - vb->subnet_prefix;
	}
	return ret;
}

int weighted_view_cmp(const void *a, const void *b)
{
	geo_view_t *va = (geo_view_t *)a;
	geo_view_t *vb = (geo_view_t *)b;

	return (int)va->weight - (int)vb->weight;
}

static view_cmp_t cmp_fct[] = {
	[MODE_SUBNET]   = &subnet_view_cmp,
	[MODE_GEODB]    = &geodb_view_cmp,
	[MODE_WEIGHTED] = &weighted_view_cmp
};

static int add_view_to_trie(knot_dname_t *owner, geo_view_t *view, geoip_ctx_t *ctx)
{
	int ret = KNOT_EOK;

	// Find the node belonging to the owner.
	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(owner, lf_storage);
	assert(lf);
	trie_val_t *val = trie_get_ins(ctx->geo_trie, lf + 1, *lf);
	geo_trie_val_t *cur_val = *val;

	if (cur_val == NULL) {
		// Create new node value.
		geo_trie_val_t *new_val = calloc(1, sizeof(geo_trie_val_t));
		new_val->avail = 1;
		new_val->count = 1;
		new_val->views = malloc(sizeof(geo_view_t));
		if (ctx->mode == MODE_WEIGHTED) {
			new_val->total_weight = view->weight;
			view->weight = 0; // because it is the first view
		}
		new_val->views[0] = *view;

		// Add new value to trie.
		*val = new_val;
	} else {
		// Double the views array in size if necessary.
		if (cur_val->avail == cur_val->count) {
			void *alloc_ret = realloc(cur_val->views,
			                          2 * cur_val->avail * sizeof(geo_view_t));
			if (alloc_ret == NULL) {
				return KNOT_ENOMEM;
			}
			cur_val->views = alloc_ret;
			cur_val->avail *= 2;
		}

		// Insert new element.
		if (ctx->mode == MODE_WEIGHTED) {
			cur_val->total_weight += view->weight;
			view->weight = cur_val->total_weight - view->weight;
		}
		cur_val->views[cur_val->count++] = *view;
	}

	return ret;
}

static void geo_log(check_ctx_t *check, int priority, const char *fmt, ...)
{
	va_list vargs;
	va_start(vargs, fmt);

	if (check->args != NULL) {
		if (vsnprintf(geoip_check_str, sizeof(geoip_check_str), fmt, vargs) < 0) {
			geoip_check_str[0] = '\0';
		}
		check->args->err_str = geoip_check_str;
	} else {
		knotd_mod_vlog(check->mod, priority, fmt, vargs);
	}

	va_end(vargs);
}

static knotd_conf_t geo_conf(check_ctx_t *check, const yp_name_t *item_name)
{
	if (check->args != NULL) {
		return knotd_conf_check_item(check->args, item_name);
	} else {
		return knotd_conf_mod(check->mod, item_name);
	}
}

static int finalize_geo_view(check_ctx_t *check, geo_view_t *view, knot_dname_t *owner,
                             geoip_ctx_t *ctx)
{
	if (view == NULL || view->count == 0) {
		return KNOT_EOK;
	}

	int ret = KNOT_EOK;
	if (ctx->dnssec) {
		assert(check->mod != NULL);
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
			ret = knotd_mod_dnssec_sign_rrset(check->mod, &view->rrsigs[i],
			                                  &view->rrsets[i], NULL);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	ret = add_view_to_trie(owner, view, ctx);
	if (ret != KNOT_EOK) {
		return ret;
	}

	memset(view, 0, sizeof(*view));
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
	view->cname = NULL;
	return KNOT_EOK;
}

static void clear_geo_view(geo_view_t *view)
{
	if (view == NULL) {
		return;
	}
	for (int i = 0; i < GEODB_MAX_DEPTH; i++) {
		free(view->geodata[i]);
	}
	free(view->subnet);
	for (int j = 0; j < view->count; j++) {
		knot_rrset_clear(&view->rrsets[j], NULL);
		if (view->rrsigs != NULL) {
			knot_rrset_clear(&view->rrsigs[j], NULL);
		}
	}
	free(view->rrsets);
	view->rrsets = NULL;
	free(view->rrsigs);
	view->rrsigs = NULL;
	free(view->cname);
	view->cname = NULL;
}

static int parse_origin(yp_parser_t *yp, zs_scanner_t *scanner)
{
	char *set_origin = sprintf_alloc("$ORIGIN %s%s\n", yp->key,
	                                 (yp->key[yp->key_len - 1] == '.') ? "" : ".");
	if (set_origin == NULL) {
		return KNOT_ENOMEM;
	}

	// Set owner as origin for future record parses.
	if (zs_set_input_string(scanner, set_origin, strlen(set_origin)) != 0 ||
	    zs_parse_record(scanner) != 0) {
		free(set_origin);
		return KNOT_EPARSEFAIL;
	}
	free(set_origin);
	return KNOT_EOK;
}

static int parse_view(check_ctx_t *check, geoip_ctx_t *ctx, yp_parser_t *yp, geo_view_t *view)
{
	// Initialize new geo view.
	memset(view, 0, sizeof(*view));
	int ret = init_geo_view(view);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Check view type syntax.
	int key_len = strlen(mode_key[ctx->mode]);
	if (yp->key_len != key_len || memcmp(yp->key, mode_key[ctx->mode], key_len) != 0) {
		geo_log(check, LOG_ERR, "invalid key type '%s' on line %zu",
		        yp->key, yp->line_count);
		return KNOT_EINVAL;
	}

	// Parse geodata/subnet.
	if (ctx->mode == MODE_GEODB) {
		if (parse_geodb_data((char *)yp->data, view->geodata, view->geodata_len,
			&view->geodepth, ctx->paths, ctx->path_count) != 0) {
			geo_log(check, LOG_ERR, "invalid geo format '%s' on line %zu",
			        yp->data, yp->line_count);
			return KNOT_EINVAL;
		}
	} else if (ctx->mode == MODE_SUBNET) {
		// Locate the optional slash in the subnet string.
		char *slash = strchr(yp->data, '/');
		if (slash == NULL) {
			slash = yp->data + yp->data_len;
		}
		*slash = '\0';

		// Parse address.
		view->subnet = calloc(1, sizeof(struct sockaddr_storage));
		if (view->subnet == NULL) {
			return KNOT_ENOMEM;
		}
		// Try to parse as IPv4.
		ret = sockaddr_set(view->subnet, AF_INET, yp->data, 0);
		view->subnet_prefix = 32;
		if (ret != KNOT_EOK) {
			// Try to parse as IPv6.
			ret = sockaddr_set(view->subnet, AF_INET6 ,yp->data, 0);
			view->subnet_prefix = 128;
		}
		if (ret != KNOT_EOK) {
			geo_log(check, LOG_ERR, "invalid address format '%s' on line %zu",
			        yp->data, yp->line_count);
			return KNOT_EINVAL;
		}

		// Parse subnet prefix.
		if (slash < yp->data + yp->data_len - 1) {
			ret = str_to_u8(slash + 1, &view->subnet_prefix);
			if (ret != KNOT_EOK) {
				geo_log(check, LOG_ERR, "invalid prefix '%s' on line %zu",
				        slash + 1, yp->line_count);
				return ret;
			}
			if (view->subnet->ss_family == AF_INET && view->subnet_prefix > 32) {
				view->subnet_prefix = 32;
				geo_log(check, LOG_WARNING, "IPv4 prefix too large on line %zu, set to 32",
				        yp->line_count);
			}
			if (view->subnet->ss_family == AF_INET6 && view->subnet_prefix > 128) {
				view->subnet_prefix = 128;
				geo_log(check, LOG_WARNING, "IPv6 prefix too large on line %zu, set to 128",
				        yp->line_count);
			}
		}
	} else if (ctx->mode == MODE_WEIGHTED) {
		uint8_t weight;
		ret = str_to_u8(yp->data, &weight);
		if (ret != KNOT_EOK) {
			geo_log(check, LOG_ERR, "invalid weight '%s' on line %zu",
			        yp->data, yp->line_count);
			return ret;
		}
		view->weight = weight;
	}

	return KNOT_EOK;
}

static int parse_rr(check_ctx_t *check, yp_parser_t *yp, zs_scanner_t *scanner,
                    knot_dname_t *owner, geo_view_t *view, uint32_t ttl)
{
	uint16_t rr_type = KNOT_RRTYPE_A;
	if (knot_rrtype_from_string(yp->key, &rr_type) != 0) {
		geo_log(check, LOG_ERR, "invalid RR type '%s' on line %zu",
		        yp->key, yp->line_count);
		return KNOT_EINVAL;
	}

	if (rr_type == KNOT_RRTYPE_CNAME && view->count > 0) {
		geo_log(check, LOG_ERR, "cannot add CNAME to view with other RRs on line %zu",
		        yp->line_count);
		return KNOT_EINVAL;
	}

	if (view->cname != NULL) {
		geo_log(check, LOG_ERR, "cannot add RR to view with CNAME on line %zu",
		        yp->line_count);
		return KNOT_EINVAL;
	}

	if (knot_rrtype_is_dnssec(rr_type)) {
		geo_log(check, LOG_ERR, "DNSSEC record '%s' not allowed on line %zu",
		        yp->key, yp->line_count);
		return KNOT_EINVAL;
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
				return KNOT_ENOMEM;
			}
			view->rrsets = alloc_ret;
			view->avail *= 2;
		}
		add_rr = &view->rrsets[view->count++];
		knot_dname_t *owner_cpy = knot_dname_copy(owner, NULL);
		if (owner_cpy == NULL) {
			return KNOT_ENOMEM;
		}
		knot_rrset_init(add_rr, owner_cpy, rr_type, KNOT_CLASS_IN, ttl);
	}

	// Parse record.
	char *input_string = sprintf_alloc("@ %s %s\n", yp->key, yp->data);
	if (input_string == NULL) {
		return KNOT_ENOMEM;
	}

	if (zs_set_input_string(scanner, input_string, strlen(input_string)) != 0 ||
	    zs_parse_record(scanner) != 0 ||
	    scanner->state != ZS_STATE_DATA) {
		free(input_string);
		return KNOT_EPARSEFAIL;
	}
	free(input_string);

	if (rr_type == KNOT_RRTYPE_CNAME) {
		view->cname = knot_dname_from_str_alloc(yp->data);
	}

	// Add new rdata to current rrset.
	return knot_rrset_add_rdata(add_rr, scanner->r_data, scanner->r_data_length, NULL);
}

static int geo_conf_yparse(check_ctx_t *check, geoip_ctx_t *ctx)
{
	int ret = KNOT_EOK;
	yp_parser_t *yp = NULL;
	zs_scanner_t *scanner = NULL;
	knot_dname_storage_t owner_buff;
	knot_dname_t *owner = NULL;
	geo_view_t *view = calloc(1, sizeof(geo_view_t));
	if (view == NULL) {
		return KNOT_ENOMEM;
	}

	// Initialize yparser.
	yp = malloc(sizeof(yp_parser_t));
	if (yp == NULL) {
		ret = KNOT_ENOMEM;
		goto cleanup;
	}
	yp_init(yp);
	knotd_conf_t conf = geo_conf(check, MOD_CONFIG_FILE);
	ret = yp_set_input_file(yp, conf.single.string);
	if (ret != KNOT_EOK) {
		geo_log(check, LOG_ERR, "failed to load module config file '%s' (%s)",
		        conf.single.string, knot_strerror(ret));
		goto cleanup;
	}

	// Initialize zscanner.
	scanner = malloc(sizeof(zs_scanner_t));
	if (scanner == NULL) {
		ret = KNOT_ENOMEM;
		goto cleanup;
	}
	if (zs_init(scanner, NULL, KNOT_CLASS_IN, ctx->ttl) != 0) {
		ret = KNOT_EPARSEFAIL;
		goto cleanup;
	}

	// Main loop.
	while (1) {
		// Get the next item in config.
		ret = yp_parse(yp);
		if (ret == KNOT_EOF) {
			ret = finalize_geo_view(check, view, owner, ctx);
			goto cleanup;
		}
		if (ret != KNOT_EOK) {
			geo_log(check, LOG_ERR,
			        "failed to parse module config file on line %zu (%s)",
			        yp->line_count, knot_strerror(ret));
			goto cleanup;
		}

		// If the next item is not a rrset, the current view is finished.
		if (yp->event != YP_EKEY1) {
			ret = finalize_geo_view(check, view, owner, ctx);
			if (ret != KNOT_EOK) {
				goto cleanup;
			}
		}

		// Next domain.
		if (yp->event == YP_EKEY0) {
			owner = knot_dname_from_str(owner_buff, yp->key, sizeof(owner_buff));
			if (owner == NULL) {
				geo_log(check, LOG_ERR,
				        "invalid domain name in module config file on line %zu",
				        yp->line_count);
				ret = KNOT_EINVAL;
				goto cleanup;
			}
			ret = parse_origin(yp, scanner);
			if (ret != KNOT_EOK) {
				goto cleanup;
			}
		}

		// Next view.
		if (yp->event == YP_EID) {
			ret = parse_view(check, ctx, yp, view);
			if (ret != KNOT_EOK) {
				goto cleanup;
			}
		}

		// Next RR of the current view.
		if (yp->event == YP_EKEY1) {
			// Check whether we really are in a view.
			if (view->avail <= 0) {
				const char *err_str[] = {
					[MODE_SUBNET]   = "- net: SUBNET",
					[MODE_GEODB]    = "- geo: LOCATION",
					[MODE_WEIGHTED] = "- weight: WEIGHT"
				};
				geo_log(check, LOG_ERR,
				        "missing '%s' in module config file before line %zu",
				        err_str[ctx->mode], yp->line_count);
				ret = KNOT_EINVAL;
				goto cleanup;
			}
			ret = parse_rr(check, yp, scanner, owner, view, ctx->ttl);
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

static void free_geoip_ctx(geoip_ctx_t *ctx)
{
	geodb_close(ctx->geodb);
	free(ctx->geodb);
	clear_geo_trie(ctx->geo_trie);
	trie_free(ctx->geo_trie);
	for (int i = 0; i < ctx->path_count; i++) {
		for (int j = 0; j < GEODB_MAX_PATH_LEN; j++) {
			free(ctx->paths[i].path[j]);
		}
	}
	free(ctx);
}

static bool view_strictly_in_view(geo_view_t *view, geo_view_t *in,
                                  enum operation_mode mode)
{
	switch (mode) {
	case MODE_GEODB:
		if (in->geodepth >= view->geodepth) {
			return false;
		}
		for (int i = 0; i < in->geodepth; i++) {
			if (in->geodata[i] != NULL) {
				if (in->geodata_len[i] != view->geodata_len[i]) {
					return false;
				}
				if (memcmp(in->geodata[i], view->geodata[i],
				           in->geodata_len[i]) != 0) {
					return false;
				}
			}
		}
		return true;
	case MODE_SUBNET:
		if (in->subnet_prefix >= view->subnet_prefix) {
			return false;
		}
		return sockaddr_net_match(view->subnet, in->subnet, in->subnet_prefix);
	case MODE_WEIGHTED:
		return true;
	default:
		assert(0);
		return false;
	}
}

static void geo_sort_and_link(geoip_ctx_t *ctx)
{
	trie_it_t *it = trie_it_begin(ctx->geo_trie);
	while (!trie_it_finished(it)) {
		geo_trie_val_t *val = (geo_trie_val_t *) (*trie_it_val(it));
		qsort(val->views, val->count, sizeof(geo_view_t), cmp_fct[ctx->mode]);

		for (int i = 1; i < val->count; i++) {
			geo_view_t *cur_view = &val->views[i];
			geo_view_t *prev_view = &val->views[i - 1];
			cur_view->prev = i;
			int prev = i - 1;
			do {
				if (view_strictly_in_view(cur_view, prev_view, ctx->mode)) {
					cur_view->prev = prev;
					break;
				}
				if (prev == prev_view->prev) {
					break;
				}
				prev = prev_view->prev;
				prev_view = &val->views[prev];
			} while (1);
		}
		trie_it_next(it);
	}
	trie_it_free(it);
}

// Return the index of the last lower or equal element or -1 of not exists.
static int geo_bin_search(geo_view_t *arr, int count, geo_view_t *x, view_cmp_t cmp)
{
	int l = 0, r = count;
	while (l < r) {
		int m = (l + r) / 2;
		if (cmp(&arr[m], x) <= 0) {
			l = m + 1;
		} else {
			r = m;
		}
	}
	return l - 1; // l is the index of first greater element or N if not exists.
}

static geo_view_t *find_best_view(geo_view_t *dummy, geo_trie_val_t *data, geoip_ctx_t *ctx)
{
	view_cmp_t cmp = cmp_fct[ctx->mode];
	int idx = geo_bin_search(data->views, data->count, dummy, cmp);
	if (idx == -1) { // There is no suitable view.
		return NULL;
	}
	if (cmp(dummy, &data->views[idx]) != 0 &&
	    !view_strictly_in_view(dummy, &data->views[idx], ctx->mode)) {
		idx = data->views[idx].prev;
		while (!view_strictly_in_view(dummy, &data->views[idx], ctx->mode)) {
			if (idx == data->views[idx].prev) {
				// We are at a root and we have found no suitable view.
				return NULL;
			}
			idx = data->views[idx].prev;
		}
	}
	return &data->views[idx];
}

static void find_rr_in_view(uint16_t qtype, geo_view_t *view,
                            knot_rrset_t **rr, knot_rrset_t **rrsig)
{
	knot_rrset_t *cname = NULL;
	knot_rrset_t *cnamesig = NULL;
	for (int i = 0; i < view->count; i++) {
		if (view->rrsets[i].type == qtype) {
			*rr = &view->rrsets[i];
			*rrsig = (view->rrsigs) ? &view->rrsigs[i] : NULL;
		} else if (view->rrsets[i].type == KNOT_RRTYPE_CNAME) {
			cname = &view->rrsets[i];
			cnamesig = (view->rrsigs) ? &view->rrsigs[i] : NULL;
		}
	}

	// Return CNAME if only CNAME is found.
	if (*rr == NULL && cname != NULL) {
		*rr = cname;
		*rrsig = cnamesig;
	}
}

static knotd_in_state_t geoip_process(knotd_in_state_t state, knot_pkt_t *pkt,
                                      knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	// Nothing to do if the query was already resolved by a previous module.
	if (state == KNOTD_IN_STATE_HIT || state == KNOTD_IN_STATE_FOLLOW) {
		return state;
	}

	geoip_ctx_t *ctx = (geoip_ctx_t *)knotd_mod_ctx(mod);

	// Save the query type.
	uint16_t qtype = knot_pkt_qtype(qdata->query);

	// Check if geolocation is available for given query.
	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(knot_pkt_qname(qdata->query), lf_storage);
	// Exit if no qname.
	if (lf == NULL) {
		return state;
	}
	trie_val_t *val = trie_get_try_wildcard(ctx->geo_trie, lf + 1, *lf);
	if (val == NULL) {
		// Nothing to do in this module.
		return state;
	}

	geo_trie_val_t *data = *val;

	// Check if EDNS Client Subnet is available.
	struct sockaddr_storage ecs_addr = { 0 };
	const struct sockaddr_storage *remote = knotd_qdata_remote_addr(qdata);
	if (knot_edns_client_subnet_get_addr(&ecs_addr, qdata->ecs) == KNOT_EOK) {
		remote = &ecs_addr;
	}

	uint16_t netmask = 0;
	geodb_data_t entries[ctx->path_count];

	// Create dummy view and fill it with data about the current remote.
	geo_view_t dummy = { 0 };
	switch(ctx->mode) {
	case MODE_SUBNET:
		dummy.subnet = (struct sockaddr_storage *)remote;
		dummy.subnet_prefix = (remote->ss_family == AF_INET) ? 32 : 128;
		break;
	case MODE_GEODB:
		if (geodb_query(ctx->geodb, entries, (struct sockaddr *)remote,
		                ctx->paths, ctx->path_count, &netmask) != 0) {
			return state;
		}
		// MMDB may supply IPv6 prefixes even for IPv4 address, see man libmaxminddb.
		if (remote->ss_family == AF_INET && netmask > 32) {
			netmask -= 96;
		}
		geodb_fill_geodata(entries, ctx->path_count,
		                   dummy.geodata, dummy.geodata_len, &dummy.geodepth);
		break;
	case MODE_WEIGHTED:
		dummy.weight = dnssec_random_uint16_t() % data->total_weight;
		break;
	default:
		assert(0);
		break;
	}

	// Find last lower or equal view.
	geo_view_t *view = find_best_view(&dummy, data, ctx);
	if (view == NULL) { // No suitable view was found.
		return state;
	}

	// Save netmask for ECS if in subnet mode.
	if (ctx->mode == MODE_SUBNET) {
		netmask = view->subnet_prefix;
	}

	// Fetch the correct rrset from found view.
	knot_rrset_t *rr = NULL;
	knot_rrset_t *rrsig = NULL;
	find_rr_in_view(qtype, view, &rr, &rrsig);

	// Answer the query if possible.
	if (rr != NULL) {
		// Update ECS if used.
		if (qdata->ecs != NULL && netmask > 0) {
			qdata->ecs->scope_len = netmask;
		}

		knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, rr, 0);
		if (ctx->dnssec && knot_pkt_has_dnssec(qdata->query) && rrsig != NULL) {
			knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, rrsig, 0);
		}

		// We've got an answer, set the AA bit.
		knot_wire_set_aa(pkt->wire);

		if (rr->type == KNOT_RRTYPE_CNAME && view->cname != NULL) {
			// Trigger CNAME chain resolution
			qdata->name = view->cname;
			return KNOTD_IN_STATE_FOLLOW;
		}

		return KNOTD_IN_STATE_HIT;
	} else {
		// view was found, but no suitable rrtype
		return KNOTD_IN_STATE_NODATA;
	}
}

static int load_module(check_ctx_t *check)
{
	assert((check->args != NULL) != (check->mod != NULL));
	knotd_mod_t *mod = check->mod;

	// Create module context.
	geoip_ctx_t *ctx = calloc(1, sizeof(geoip_ctx_t));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	knotd_conf_t conf = geo_conf(check, MOD_TTL);
	ctx->ttl = conf.single.integer;
	conf = geo_conf(check, MOD_MODE);
	ctx->mode = conf.single.option;

	// Initialize the dname trie.
	ctx->geo_trie = trie_create(NULL);
	if (ctx->geo_trie == NULL) {
		free_geoip_ctx(ctx);
		return KNOT_ENOMEM;
	}

	if (ctx->mode == MODE_GEODB) {
		// Initialize geodb.
		conf = geo_conf(check, MOD_GEODB_FILE);
		ctx->geodb = geodb_open(conf.single.string);
		if (ctx->geodb == NULL) {
			geo_log(check, LOG_ERR, "failed to open geo DB");
			free_geoip_ctx(ctx);
			return KNOT_EINVAL;
		}

		// Load configured geodb keys.
		conf = geo_conf(check, MOD_GEODB_KEY);
		assert(conf.count <= GEODB_MAX_DEPTH);
		ctx->path_count = conf.count;
		for (size_t i = 0; i < conf.count; i++) {
			(void)parse_geodb_path(&ctx->paths[i], (char *)conf.multi[i].string);
		}
		knotd_conf_free(&conf);
	}

	if (mod != NULL) {
		// Is DNSSEC used on this zone?
		conf = knotd_conf_mod(mod, MOD_DNSSEC);
		if (conf.count == 0) {
			conf = knotd_conf_zone(mod, C_DNSSEC_SIGNING, knotd_mod_zone(mod));
		}
		ctx->dnssec = conf.single.boolean;
		if (ctx->dnssec) {
			int ret = knotd_mod_dnssec_init(mod);
			if (ret != KNOT_EOK) {
				knotd_mod_log(mod, LOG_ERR, "failed to initialize DNSSEC");
				free_geoip_ctx(ctx);
				return ret;
			}
			ret = knotd_mod_dnssec_load_keyset(mod, false);
			if (ret != KNOT_EOK) {
				knotd_mod_log(mod, LOG_ERR, "failed to load DNSSEC keys");
				free_geoip_ctx(ctx);
				return ret;
			}
		}
	}

	// Parse geo configuration file.
	int ret = geo_conf_yparse(check, ctx);
	if (ret != KNOT_EOK) {
		free_geoip_ctx(ctx);
		return ret;
	}

	if (mod != NULL) {
		// Prepare geo views for faster search.
		geo_sort_and_link(ctx);

		knotd_mod_ctx_set(mod, ctx);
	} else {
		free_geoip_ctx(ctx);
	}

	return ret;
}

int geoip_load(knotd_mod_t *mod)
{
	check_ctx_t check = { .mod = mod };
	int ret = load_module(&check);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return knotd_mod_in_hook(mod, KNOTD_STAGE_PREANSWER, geoip_process);
}

void geoip_unload(knotd_mod_t *mod)
{
	geoip_ctx_t *ctx = knotd_mod_ctx(mod);
	if (ctx != NULL) {
		free_geoip_ctx(ctx);
	}
}

KNOTD_MOD_API(geoip, KNOTD_MOD_FLAG_SCOPE_ZONE,
              geoip_load, geoip_unload, geoip_conf, geoip_conf_check);
