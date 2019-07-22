/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/common/stats_yaml.h"

static void dump_counters(FILE *fd, int level, mod_ctr_t *ctr)
{
	for (uint32_t j = 0; j < ctr->count; j++) {
		uint64_t counter = ATOMIC_GET(ctr->counters[j]);

		// Skip empty counters.
		if (counter == 0) {
			continue;
		}

		if (ctr->idx_to_str != NULL) {
			char *str = ctr->idx_to_str(j, ctr->count);
			if (str != NULL) {
				DUMP_CTR(fd, level, "%s", str, counter);
				free(str);
			}
		} else {
			DUMP_CTR(fd, level, "%u", j, counter);
		}
	}
}

static void dump_modules(dump_ctx_t *ctx)
{
	int level = 0;
	knotd_mod_t *mod = NULL;
	WALK_LIST(mod, *ctx->query_modules) {
		// Skip modules without statistics.
		if (mod->stats_count == 0) {
			continue;
		}

		// Dump zone name.
		if (ctx->zone != NULL) {
			// Prevent from zone section override.
			if (!ctx->zone_emitted) {
				DUMP_STR(ctx->fd, 0, "zone", "");
				ctx->zone_emitted = true;
			}
			level = 1;

			char name[KNOT_DNAME_TXT_MAXLEN + 1];
			if (knot_dname_to_str(name, ctx->zone, sizeof(name)) == NULL) {
				return;
			}
			DUMP_STR(ctx->fd, level++, "\"%s\"", name, "");
		} else {
			level = 0;
		}

		// Dump module counters.
		DUMP_STR(ctx->fd, level, "%s", mod->id->name + 1, "");
		for (int i = 0; i < mod->stats_count; i++) {
			mod_ctr_t *ctr = mod->stats + i;
			if (ctr->name == NULL) {
				// Empty counter.
				continue;
			}
			if (ctr->count == 1) {
				// Simple counter.
				uint64_t counter = ATOMIC_GET(ctr->counter);
				DUMP_CTR(ctx->fd, level + 1, "%s", ctr->name, counter);
			} else {
				// Array of counters.
				DUMP_STR(ctx->fd, level + 1, "%s", ctr->name, "");
				dump_counters(ctx->fd, level + 2, ctr);
			}
		}
	}
}

static void zone_stats_dump(zone_t *zone, dump_ctx_t *ctx)
{
	if (EMPTY_LIST(zone->query_modules)) {
		return;
	}

	ctx->query_modules = &zone->query_modules;
	ctx->zone = zone->name;

	dump_modules(ctx);
}

void dump_to_yaml(FILE *fd, server_t *server)
{
	char date[64] = "";

	// Get formatted current time string.
	struct tm tm;
	time_t now = time(NULL);
	localtime_r(&now, &tm);
	strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S%z", &tm);

	// Get the server identity.
	conf_val_t val = conf_get(conf(), C_SRV, C_IDENT);
	const char *ident = conf_str(&val);
	if (ident == NULL || ident[0] == '\0') {
		ident = conf()->hostname;
	}

	// Dump record header.
	fprintf(fd,
	        "---\n"
	        "time: %s\n"
	        "identity: %s\n",
	        date, ident);

	// Dump server statistics.
	DUMP_STR(fd, 0, "server", "");
	for (const stats_item_t *item = server_stats; item->name != NULL; item++) {
		DUMP_CTR(fd, 1, "%s", item->name, item->val(server));
	}

	dump_ctx_t ctx = {
		.fd = fd,
		.query_modules = conf()->query_modules,
	};

	// Dump global statistics.
	dump_modules(&ctx);

	// Dump zone statistics.
	knot_zonedb_foreach(server->zone_db, zone_stats_dump, &ctx);
}
