/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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

static bool handle_err(const knot_dname_t *zname, const knot_rrset_t *rr, int ret)
{
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

int zcreator_step(zone_contents_t *contents, const knot_rrset_t *rr, zone_skip_t *skip)
{
	assert(contents);
	assert(rr);

	if (zone_skip_type(skip, rr->type)) {
		return KNOT_EOK;
	}

	zone_node_t *node = NULL;
	int ret = zone_contents_add_rr(contents, rr, &node);
	if (ret != KNOT_EOK) {
		if (!handle_err(contents->apex->owner, rr, ret)) {
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

	zc->ret = zcreator_step(zc->z, &rr, zc->skip);
	knot_rrset_clear(&rr, NULL);
}

static void check_origin(zs_scanner_t *s)
{
	if (s->r_type == KNOT_RRTYPE_SOA) {
		uint8_t *origin_buf = s->process.data;
		assert(s->r_owner_length <= KNOT_DNAME_MAXLEN);
		origin_buf[0] = s->r_owner_length;
		memcpy(origin_buf + 1, s->r_owner, s->r_owner_length);
		s->state = ZS_STATE_STOP;
	}
}

int zonefile_open(zloader_t *loader, const char *source, const knot_dname_t *origin,
                  uint32_t dflt_ttl, semcheck_optional_t semantic_checks, time_t time)
{
	if (loader == NULL || source == NULL) {
		return KNOT_EINVAL;
	}

	memset(loader, 0, sizeof(zloader_t));

	if (access(source, F_OK | R_OK) != 0) {
		return knot_map_errno();
	}

	zcreator_t *zc = malloc(sizeof(zcreator_t));
	if (zc == NULL) {
		return KNOT_ENOMEM;
	}
	memset(zc, 0, sizeof(zcreator_t));

	uint8_t origin_buf[1 + KNOT_DNAME_MAXLEN];
	if (origin == NULL) { // Origin autodetection based on SOA owner and source.
		const char *ext = ".zone";
		char *origin_str = basename(source);
		if (strcmp(origin_str + strlen(origin_str) - strlen(ext), ext) == 0) {
			origin_str = strndup(origin_str, strlen(origin_str) - strlen(ext));
		} else {
			origin_str = strdup(origin_str);
		}

		origin_buf[0] = 0;

		zs_scanner_t s;
		if (zs_init(&s, origin_str, KNOT_CLASS_IN, 0) != 0 ||
		    zs_set_input_file(&s, source) != 0 ||
		    zs_set_processing(&s, check_origin, NULL, &origin_buf) != 0 ||
		    (zs_parse_all(&s) != 0 && s.error.fatal)) {
			free(origin_str);
			zs_deinit(&s);
			return KNOT_EFILE;
		}
		free(origin_str);
		zs_deinit(&s);

		if (origin_buf[0] == 0) {
			return KNOT_ESOAINVAL;
		}
		origin = origin_buf + 1;
	}

	knot_dname_txt_storage_t origin_str;
	if (knot_dname_to_str(origin_str, origin, sizeof(origin_str)) == NULL) {
		return KNOT_EINVAL;
	}

	if (zs_init(&loader->scanner, origin_str, KNOT_CLASS_IN, dflt_ttl) != 0 ||
	    zs_set_input_file(&loader->scanner, source) != 0 ||
	    zs_set_processing(&loader->scanner, process_data, process_error, zc) != 0) {
		zs_deinit(&loader->scanner);
		free(zc);
		return KNOT_EFILE;
	}

	zc->z = zone_contents_new(origin, true);
	if (zc->z == NULL) {
		zs_deinit(&loader->scanner);
		free(zc);
		return KNOT_ENOMEM;
	}

	loader->source = strdup(source);
	loader->creator = zc;
	loader->semantic_checks = semantic_checks;
	loader->time = time;

	return KNOT_EOK;
}

zone_contents_t *zonefile_load(zloader_t *loader, uint16_t threads)
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

	knot_rdataset_t *soa = node_rdataset(zc->z->apex, KNOT_RRTYPE_SOA);
	if (soa == NULL || soa->count != 1) {
		sem_error_t code = (soa == NULL) ? SEM_ERR_SOA_NONE : SEM_ERR_SOA_MULTIPLE;
		loader->err_handler->error = true;
		loader->err_handler->cb(loader->err_handler, zc->z, NULL, code, NULL);
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
	                         loader->err_handler, loader->time, threads);

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

int zonefile_write(const char *path, zone_contents_t *zone, zone_skip_t *skip)
{
	if (path == NULL) {
		return KNOT_EINVAL;
	}

	if (zone == NULL) {
		return KNOT_EEMPTYZONE;
	}

	int ret = make_path(path, S_IRUSR | S_IWUSR | S_IXUSR |
	                          S_IRGRP | S_IWGRP | S_IXGRP);
	if (ret != KNOT_EOK) {
		return ret;
	}

	FILE *file = NULL;
	char *tmp_name = NULL;
	ret = open_tmp_file(path, &tmp_name, &file, S_IRUSR | S_IWUSR |
	                                            S_IRGRP | S_IWGRP);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = zone_dump_text(zone, skip, file, true, NULL);
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
                        const knot_dname_t *node, sem_error_t error, const char *data)
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
		if (knot_dname_to_str(owner, node, sizeof(owner)) == NULL) {
			owner[0] = '\0';
		}
	}

	int level = handler->soft_check ? LOG_NOTICE :
	            (handler->error ? LOG_ERR : LOG_WARNING);

	log_fmt_zone(level, LOG_SOURCE_ZONE, zone->apex->owner, NULL,
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
