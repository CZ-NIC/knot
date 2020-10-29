/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>

#include "libknot/libknot.h"
#include "contrib/files.h"
#include "knot/common/log.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/zone/semantic-check.h"
#include "knot/zone/adjust.h"
#include "knot/zone/contents.h"
#include "knot/zone/zonefile.h"
#include "knot/zone/zone-dump.h"

#define ERROR(zone, fmt, ...) log_zone_error(zone, "zone loader, " fmt, ##__VA_ARGS__)
#define WARNING(zone, fmt, ...) log_zone_warning(zone, "zone loader, " fmt, ##__VA_ARGS__)
#define NOTICE(zone, fmt, ...) log_zone_notice(zone, "zone loader, " fmt, ##__VA_ARGS__)

static void process_error(zs_scanner_t *s)
{
	zcreator_t *zc = s->process.data;
	const knot_dname_t *zname = zc->z->apex->owner;

	ERROR(zname, "%s in zone, file '%s', line %"PRIu64" (%s)",
	      s->error.fatal ? "fatal error" : "error",
	      s->file.name, s->line_counter,
	      zs_strerror(s->error.code));
}

static bool handle_err(zcreator_t *zc, const knot_rrset_t *rr, int ret, bool master)
{
	const knot_dname_t *zname = zc->z->apex->owner;

	knot_dname_txt_storage_t buff;
	char *owner = knot_dname_to_str(buff, rr->owner, sizeof(buff));
	if (owner == NULL) {
		owner = "";
	}

	if (ret == KNOT_EOUTOFZONE) {
		WARNING(zname, "ignoring out-of-zone data, owner %s", owner);
		return true;
	} else if (ret == KNOT_ETTL) {
		char type[16] = "";
		knot_rrtype_to_string(rr->type, type, sizeof(type));
		NOTICE(zname, "TTL mismatch, owner %s, type %s, TTL set to %u",
		       owner, type, rr->ttl);
		return true;
	} else {
		ERROR(zname, "failed to process record, owner %s", owner);
		return false;
	}
}

int zcreator_step(zcreator_t *zc, const knot_rrset_t *rr)
{
	if (zc == NULL || rr == NULL || rr->rrs.count != 1) {
		return KNOT_EINVAL;
	}

	if (rr->type == KNOT_RRTYPE_SOA &&
	    node_rrtype_exists(zc->z->apex, KNOT_RRTYPE_SOA)) {
		// Ignore extra SOA
		return KNOT_EOK;
	}

	zone_node_t *node = NULL;
	int ret = zone_contents_add_rr(zc->z, rr, &node);
	if (ret != KNOT_EOK) {
		if (!handle_err(zc, rr, ret, zc->master)) {
			// Fatal error
			return ret;
		}
	}

	return KNOT_EOK;
}

/*! \brief Creates RR from parser input, passes it to handling function. */
static void process_data(zs_scanner_t *scanner)
{
	zcreator_t *zc = scanner->process.data;
	if (zc->ret != KNOT_EOK) {
		scanner->state = ZS_STATE_STOP;
		return;
	}

	knot_dname_t *owner = knot_dname_copy(scanner->r_owner, NULL);
	if (owner == NULL) {
		zc->ret = KNOT_ENOMEM;
		return;
	}

	knot_rrset_t rr;
	knot_rrset_init(&rr, owner, scanner->r_type, scanner->r_class, scanner->r_ttl);

	int ret = knot_rrset_add_rdata(&rr, scanner->r_data, scanner->r_data_length, NULL);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&rr, NULL);
		zc->ret = ret;
		return;
	}

	/* Convert RDATA dnames to lowercase before adding to zone. */
	ret = knot_rrset_rr_to_canonical(&rr);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&rr, NULL);
		zc->ret = ret;
		return;
	}

	zc->ret = zcreator_step(zc, &rr);
	knot_rrset_clear(&rr, NULL);
}

int zonefile_open(zloader_t *loader, const char *source,
                  const knot_dname_t *origin, semcheck_optional_t semantic_checks, time_t time)
{
	if (!loader) {
		return KNOT_EINVAL;
	}

	memset(loader, 0, sizeof(zloader_t));

	/* Check zone file. */
	if (access(source, F_OK | R_OK) != 0) {
		return KNOT_EACCES;
	}

	/* Create context. */
	zcreator_t *zc = malloc(sizeof(zcreator_t));
	if (zc == NULL) {
		return KNOT_ENOMEM;
	}
	memset(zc, 0, sizeof(zcreator_t));

	zc->z = zone_contents_new(origin, true);
	if (zc->z == NULL) {
		free(zc);
		return KNOT_ENOMEM;
	}

	/* Prepare textual owner for zone scanner. */
	char *origin_str = knot_dname_to_str_alloc(origin);
	if (origin_str == NULL) {
		zone_contents_deep_free(zc->z);
		free(zc);
		return KNOT_ENOMEM;
	}

	if (zs_init(&loader->scanner, origin_str, KNOT_CLASS_IN, 3600) != 0 ||
	    zs_set_input_file(&loader->scanner, source) != 0 ||
	    zs_set_processing(&loader->scanner, process_data, process_error, zc) != 0) {
		zs_deinit(&loader->scanner);
		free(origin_str);
		zone_contents_deep_free(zc->z);
		free(zc);
		return KNOT_EFILE;
	}
	free(origin_str);

	loader->source = strdup(source);
	loader->creator = zc;
	loader->semantic_checks = semantic_checks;
	loader->time = time;

	return KNOT_EOK;
}

zone_contents_t *zonefile_load(zloader_t *loader)
{
	if (!loader) {
		return NULL;
	}

	zcreator_t *zc = loader->creator;
	const knot_dname_t *zname = zc->z->apex->owner;

	assert(zc);
	int ret = zs_parse_all(&loader->scanner);
	if (ret != 0 && loader->scanner.error.counter == 0) {
		ERROR(zname, "failed to load zone, file '%s' (%s)",
		      loader->source, zs_strerror(loader->scanner.error.code));
		goto fail;
	}

	if (zc->ret != KNOT_EOK) {
		ERROR(zname, "failed to load zone, file '%s' (%s)",
		      loader->source, knot_strerror(zc->ret));
		goto fail;
	}

	if (loader->scanner.error.counter > 0) {
		ERROR(zname, "failed to load zone, file '%s', %"PRIu64" errors",
		      loader->source, loader->scanner.error.counter);
		goto fail;
	}

	if (!node_rrtype_exists(loader->creator->z->apex, KNOT_RRTYPE_SOA)) {
		loader->err_handler->error = true;
		loader->err_handler->cb(loader->err_handler, zc->z, NULL,
		                        SEM_ERR_SOA_NONE, NULL);
		goto fail;
	}

	ret = zone_adjust_contents(zc->z, adjust_cb_flags_and_nsec3, adjust_cb_nsec3_flags,
	                           true, true, 1, NULL);
	if (ret != KNOT_EOK) {
		ERROR(zname, "failed to finalize zone contents (%s)",
		      knot_strerror(ret));
		goto fail;
	}

	ret = sem_checks_process(zc->z, loader->semantic_checks,
	                         loader->err_handler, loader->time);

	if (ret != KNOT_EOK) {
		ERROR(zname, "failed to load zone, file '%s' (%s)",
		      loader->source, knot_strerror(ret));
		goto fail;
	}

	/* The contents will now change possibly messing up NSEC3 tree, it will
	   be adjusted again at zone_update_commit. */
	ret = zone_adjust_contents(zc->z, unadjust_cb_point_to_nsec3, NULL,
	                           false, false, 1, NULL);
	if (ret != KNOT_EOK) {
		ERROR(zname, "failed to finalize zone contents (%s)",
		      knot_strerror(ret));
		goto fail;
	}

	return zc->z;

fail:
	zone_contents_deep_free(zc->z);
	return NULL;
}

int zonefile_exists(const char *path, struct timespec *mtime)
{
	if (path == NULL) {
		return KNOT_EINVAL;
	}

	struct stat zonefile_st = { 0 };
	if (stat(path, &zonefile_st) < 0) {
		return knot_map_errno();
	}

	if (mtime != NULL) {
		*mtime = zonefile_st.st_mtim;
	}

	return KNOT_EOK;
}

int zonefile_write(const char *path, zone_contents_t *zone)
{
	if (!zone || !path) {
		return KNOT_EINVAL;
	}

	int ret = make_path(path, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP);
	if (ret != KNOT_EOK) {
		return ret;
	}

	FILE *file = NULL;
	char *tmp_name = NULL;
	ret = open_tmp_file(path, &tmp_name, &file, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = zone_dump_text(zone, file, true);
	fclose(file);
	if (ret != KNOT_EOK) {
		unlink(tmp_name);
		free(tmp_name);
		return ret;
	}

	/* Swap temporary zonefile and new zonefile. */
	ret = rename(tmp_name, path);
	if (ret != 0) {
		ret = knot_map_errno();
		unlink(tmp_name);
		free(tmp_name);
		return ret;
	}

	free(tmp_name);

	return KNOT_EOK;
}

void zonefile_close(zloader_t *loader)
{
	if (!loader) {
		return;
	}

	zs_deinit(&loader->scanner);
	free(loader->source);
	free(loader->creator);
}

void err_handler_logger(sem_handler_t *handler, const zone_contents_t *zone,
                        const zone_node_t *node, sem_error_t error, const char *data)
{
	assert(handler != NULL);
	assert(zone != NULL);

	if (handler->error) {
		handler->fatal_error = true;
	} else {
		handler->warning = true;
	}

	knot_dname_txt_storage_t owner;
	if (node != NULL) {
		if (knot_dname_to_str(owner, node->owner, sizeof(owner)) == NULL) {
			owner[0] = '\0';
		}
	}

	log_fmt_zone(handler->error ? LOG_ERR : LOG_WARNING,
	             LOG_SOURCE_ZONE, zone->apex->owner, NULL,
	             "check%s%s, %s%s%s",
	             (node != NULL ? ", node " : ""),
	             (node != NULL ? owner     : ""),
	             sem_error_msg(error),
	             (data != NULL ? " "  : ""),
	             (data != NULL ? data : ""));

	handler->error = false;
}

#undef ERROR
#undef WARNING
#undef NOTICE
