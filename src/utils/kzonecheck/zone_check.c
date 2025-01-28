/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdio.h>
#include <assert.h>

#include "utils/kzonecheck/zone_check.h"

#include "knot/common/log.h"
#include "knot/zone/contents.h"
#include "knot/zone/digest.h"
#include "knot/zone/zonefile.h"
#include "knot/zone/zone-dump.h"
#include "utils/common/msg.h"

typedef struct {
	sem_handler_t handler;
	unsigned errors[SEM_ERR_UNKNOWN + 1]; /*!< Counting errors by type. */
	unsigned error_count;                 /*!< Total error count. */
} err_handler_stats_t;

static void err_callback(sem_handler_t *handler, const zone_contents_t *zone,
                         const knot_dname_t *node, sem_error_t error, const char *data)
{
	assert(handler != NULL);
	assert(zone != NULL);
	err_handler_stats_t *stats = (err_handler_stats_t *)handler;

	knot_dname_txt_storage_t buff;
	char *owner = knot_dname_to_str(buff, (node != NULL ? node : zone->apex->owner),
	                                sizeof(buff));
	if (owner == NULL) {
		owner = "";
	}

	fprintf(stderr, "[%s] %s%s%s\n", owner, sem_error_msg(error),
	       (data != NULL ? " "  : ""),
	       (data != NULL ? data : ""));

	stats->errors[error]++;
	stats->error_count++;
}

static void print_statistics(err_handler_stats_t *stats)
{
	fprintf(stderr, "\nError summary:\n");
	for (sem_error_t i = 0; i <= SEM_ERR_UNKNOWN; ++i) {
		if (stats->errors[i] > 0) {
			fprintf(stderr, "%4u\t%s\n", stats->errors[i], sem_error_msg(i));
		}
	}
}

int zone_check(const char *zone_file, const knot_dname_t *zone_name, bool zonemd,
               uint32_t dflt_ttl, semcheck_optional_t optional, time_t time,
               bool print, uint16_t threads)
{
	err_handler_stats_t stats = {
		.handler = { .cb = err_callback },
	};

	zloader_t loader;
	int ret = zonefile_open(&loader, zone_file, zone_name, dflt_ttl, optional,
	                        (sem_handler_t *)&stats, time, NULL);
	switch (ret) {
	case KNOT_EOK:
		break;
	case KNOT_EACCES:
	case KNOT_EFILE:
		ERR2("failed to load the zone file");
		return ret;
	case KNOT_ESOAINVAL:
		ERR2("failed to detect zone origin (missing SOA)");
		return ret;
	default:
		ERR2("failed to run semantic checks (%s)", knot_strerror(ret));
		return ret;
	}

	if (zone_name == NULL) {
		knot_dname_txt_storage_t origin;
		if (knot_dname_to_str(origin, loader.scanner.zone_origin , sizeof(origin)) != NULL) {
			log_debug("detected zone origin %s", origin);
		}
	}

	zone_contents_t *contents = zonefile_load(&loader, threads);
	zonefile_close(&loader);
	if (contents == NULL && !stats.handler.error) {
		ERR2("failed to run semantic checks");
		return KNOT_ERROR;
	}

	if (stats.error_count > 0) {
		print_statistics(&stats);
		if (stats.handler.error) {
			fprintf(stderr, "\n");
			ERR2("serious semantic error detected");
			ret = KNOT_EINVAL;
		} else {
			ret = KNOT_ESEMCHECK;
		}
	}

	if (zonemd) {
		ret = zone_contents_digest_verify(contents);
		if (ret != KNOT_EOK) {
			if (stats.error_count > 0 && !stats.handler.error) {
				fprintf(stderr, "\n");
			}
			ERR2("invalid ZONEMD");
		}
	}

	if (print) {
		if (ret != KNOT_EOK) {
			fprintf(stderr, "\n");
		}
		printf(";; Zone dump (Knot DNS %s)\n", PACKAGE_VERSION);
		zone_dump_text(contents, NULL, stdout, false, NULL);
	}

	zone_contents_deep_free(contents);

	return ret;
}
