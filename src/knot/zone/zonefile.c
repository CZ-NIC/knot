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

static void file_error(zs_scanner_t *s)
{
	zloader_t *loader = s->process.data;
	const knot_dname_t *zname = loader->contents->apex->owner;

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

static void process_data(zs_scanner_t *scanner)
{
	zloader_t *zl = scanner->process.data;

	if (zl->ret != KNOT_EOK) {
		scanner->state = ZS_STATE_STOP;
		return;
	}

	knot_dname_t *owner = knot_dname_copy(scanner->r_owner, NULL);
	if (owner == NULL) {
		zl->ret = KNOT_ENOMEM;
		return;
	}

	knot_rrset_t rr;
	knot_rrset_init(&rr, owner, scanner->r_type, scanner->r_class, scanner->r_ttl);

	int ret = knot_rrset_add_rdata(&rr, scanner->r_data, scanner->r_data_length, NULL);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&rr, NULL);
		zl->ret = ret;
		return;
	}

	ret = knot_rrset_rr_to_canonical(&rr);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&rr, NULL);
		zl->ret = ret;
		return;
	}

	zl->ret = zcreator_step(zl->contents, &rr, zl->skip);

	knot_rrset_clear(&rr, NULL);
}

static int init_common(zloader_t *loader, const knot_dname_t *origin, time_t time,
                       semcheck_optional_t sem_checks, sem_handler_t *err_handler,
                       zone_skip_t *skip)
{
	if (loader == NULL || origin == NULL || err_handler == NULL) {
		return KNOT_EINVAL;
	}

	loader->contents = zone_contents_new(origin, true);
	if (loader->contents == NULL) {
		return KNOT_ENOMEM;
	}

	loader->ret = KNOT_EOK;
	loader->sem_checks = sem_checks;
	loader->err_handler = err_handler;
	loader->skip = skip;
	loader->time = time;

	return KNOT_EOK;
}

int zonefile_open(zloader_t *loader, const char *source, const knot_dname_t *origin,
                  uint32_t dflt_ttl, semcheck_optional_t sem_checks,
                  sem_handler_t *sem_err_handler, time_t time, zone_skip_t *skip)
{
	if (loader == NULL || source == NULL) {
		return KNOT_EINVAL;
	}

	if (access(source, F_OK | R_OK) != 0) {
		return knot_map_errno();
	}

	/* Prepare textual owner for zone scanner (NULL for autodetection). */
	char *origin_str = NULL;
	knot_dname_txt_storage_t origin_buf;
	if (origin != NULL) {
		origin_str = knot_dname_to_str(origin_buf, origin, sizeof(origin_buf));
		if (origin_str == NULL) {
			return KNOT_EINVAL;
		}
	}

	if (zs_init(&loader->scanner, origin_str, KNOT_CLASS_IN, dflt_ttl) != 0 ||
	    zs_set_input_file(&loader->scanner, source) != 0 ||
	    zs_set_processing(&loader->scanner, process_data, file_error, loader) != 0) {
		bool missing_origin = loader->scanner.error.code == ZS_NO_SOA;
		zs_deinit(&loader->scanner);
		return missing_origin ? KNOT_ESOAINVAL : KNOT_EFILE;
	}

	int ret = init_common(loader, loader->scanner.zone_origin, time, sem_checks,
	                      sem_err_handler, skip);
	if (ret != KNOT_EOK) {
		zs_deinit(&loader->scanner);
		return ret;
	}

	loader->type = ZONE_BACKEND_FILE;
	loader->source = strdup(source);

	return KNOT_EOK;
}

#ifdef ENABLE_REDIS
redisContext *zone_rdb_connect(conf_t *conf)
{
	conf_val_t db_listen = conf_db_param(conf, C_ZONE_DB_LISTEN);
	struct sockaddr_storage addr = conf_addr(&db_listen, NULL);

	int port = sockaddr_port(&addr);
	sockaddr_port_set(&addr, 0);

	char addr_str[SOCKADDR_STRLEN];
	if (sockaddr_tostr(addr_str, sizeof(addr_str), &addr) <= 0) {
		return NULL;
	}

	const struct timeval timeout = { 0 };

	redisContext *rdb;
	if (addr.ss_family == AF_UNIX) {
		rdb = redisConnectUnixWithTimeout(addr_str, timeout);
	} else {
		rdb = redisConnectWithTimeout(addr_str, port, timeout);
	}
	if (rdb == NULL) {
		log_error("rdb, failed to connect");
	} else if (rdb->err) {
		log_error("rdb, failed to connect (%s)", rdb->errstr);
		return NULL;
	}

	return rdb;
}

int zone_rdb_open(zloader_t *loader, redisContext *rdb, const knot_dname_t *origin,
                  semcheck_optional_t sem_checks, sem_handler_t *sem_err_handler,
                  time_t time, zone_skip_t *skip)
{
	int ret = init_common(loader, origin, time, sem_checks, sem_err_handler, skip);
	if (ret != KNOT_EOK) {
		return ret;
	}

	loader->type = ZONE_BACKEND_DB;
	loader->rdb = rdb;

	return KNOT_EOK;
}

static int process_rdb_data(zone_contents_t *contents, redisReply *data,
                            zone_skip_t *skip)
{
	knot_dname_t *r_owner = (knot_dname_t *)data->element[0]->str;
	uint16_t r_type = data->element[1]->integer;
	uint32_t r_ttl = data->element[2]->integer;
	knot_rdataset_t r_data = {
		.count = data->element[3]->integer,
		.size = data->element[4]->len,
		.rdata = (knot_rdata_t *)data->element[4]->str
	};

	knot_dname_t *owner = knot_dname_copy(r_owner, NULL);
	if (owner == NULL) {
		return KNOT_ENOMEM;
	}

	knot_rrset_t rrs;
	knot_rrset_init(&rrs, owner, r_type, KNOT_CLASS_IN, r_ttl);

	int ret = knot_rdataset_copy(&rrs.rrs, &r_data, NULL);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&rrs, NULL);
		return ret;
	}

	ret = zcreator_step(contents, &rrs, skip);
	knot_rrset_clear(&rrs, NULL);
	return ret;
}

static int rdb_load(zloader_t *loader)
{
	assert(loader);
	assert(loader->type == ZONE_BACKEND_DB);

	const knot_dname_t *zname = loader->contents->apex->owner;

	redisReply *reply = redisCommand(loader->rdb,
	                                 "KNOT.ZONE.LOAD %b",
	                                 zname, knot_dname_size(zname));
	if (reply == NULL) {
		ERROR(zname, "failed to connect to database");
		return KNOT_ERROR;
	} else if (reply->type == REDIS_REPLY_ERROR) {
		ERROR(zname, "failed to load from database (%s)",
		      reply->str);
		freeReplyObject(reply);
		return KNOT_ERROR;
	} else if (reply->type != REDIS_REPLY_ARRAY) {
		ERROR(zname, "failed to load from database (bad data)");
		freeReplyObject(reply);
		return KNOT_ERROR;
	}

	for (size_t i = 0; i < reply->elements; i++) {
		redisReply *data = reply->element[i];
		int ret = process_rdb_data(loader->contents, data, loader->skip);
		if (ret != KNOT_EOK) {
			ERROR(zname, "failed to process database data (%s)",
			      knot_strerror(ret));
			freeReplyObject(reply);
			return ret;
		}
	}

	freeReplyObject(reply);

	return KNOT_EOK;
}

int zone_rdb_exists(conf_t *conf, const knot_dname_t *zone, uint32_t *serial)
{
	if (zone == NULL || serial == NULL) {
		return KNOT_EINVAL;
	}

	redisContext *rdb = zone_rdb_connect(conf);
	if (rdb == NULL) {
		return KNOT_ECONN;
	}

	int64_t val = -1;
	redisReply *reply = redisCommand(rdb,
	                                 "KNOT.ZONE.EXISTS %b",
	                                 zone, knot_dname_size(zone));
	if (reply != NULL && reply->type == REDIS_REPLY_INTEGER) {
		val = reply->integer;
	}
	freeReplyObject(reply);

	redisFree(rdb);

	return (val != -1) ? KNOT_EOK : KNOT_ENOENT;
}
#endif

static int file_load(zloader_t *loader)
{
	assert(loader);
	assert(loader->type == ZONE_BACKEND_FILE);

	const knot_dname_t *zname = loader->contents->apex->owner;

	int ret = zs_parse_all(&loader->scanner);
	if (ret != 0 && loader->scanner.error.counter == 0) {
		ERROR(zname, "failed to load file '%s' (%s)",
		      loader->source, zs_strerror(loader->scanner.error.code));
		return KNOT_ERROR;
	} else if (loader->ret != KNOT_EOK) {
		ERROR(zname, "failed to load file '%s' (%s)",
		      loader->source, knot_strerror(loader->ret));
		return KNOT_ERROR;
	} else if (loader->scanner.error.counter > 0) {
		ERROR(zname, "failed to load file '%s', %"PRIu64" errors",
		      loader->source, loader->scanner.error.counter);
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

zone_contents_t *zonefile_load(zloader_t *loader, uint16_t threads)
{
	if (loader == NULL) {
		return NULL;
	}

	const knot_dname_t *zname = loader->contents->apex->owner;

	int ret;
	if (loader->type == ZONE_BACKEND_FILE) {
		ret = file_load(loader);
	} else {
#ifdef ENABLE_REDIS
		ret = rdb_load(loader);
#else
		ret = KNOT_ENOTSUP;
#endif
	}
	if (ret != KNOT_EOK) {
		goto fail;
	}

	knot_rdataset_t *soa = node_rdataset(loader->contents->apex, KNOT_RRTYPE_SOA);
	if (soa == NULL || soa->count != 1) {
		sem_error_t code = (soa == NULL) ? SEM_ERR_SOA_NONE : SEM_ERR_SOA_MULTIPLE;
		loader->err_handler->error = true;
		loader->err_handler->cb(loader->err_handler, loader->contents, NULL, code, NULL);
		goto fail;
	}

	ret = zone_adjust_contents(loader->contents, adjust_cb_flags_and_nsec3,
	                           adjust_cb_nsec3_flags, true, true, 1, NULL);
	if (ret != KNOT_EOK) {
		ERROR(zname, "failed to finalize zone contents (%s)",
		      knot_strerror(ret));
		goto fail;
	}

	ret = sem_checks_process(loader->contents, loader->sem_checks,
	                         loader->err_handler, loader->time, threads);

	if (ret != KNOT_EOK) {
		ERROR(zname, "failed to load zone (%s)",
		      knot_strerror(ret));
		goto fail;
	}

	/* The contents will now change possibly messing up NSEC3 tree, it will
	   be adjusted again at zone_update_commit. */
	ret = zone_adjust_contents(loader->contents, unadjust_cb_point_to_nsec3,
	                           NULL, false, false, 1, NULL);
	if (ret != KNOT_EOK) {
		ERROR(zname, "failed to finalize zone contents (%s)",
		      knot_strerror(ret));
		goto fail;
	}

	return loader->contents;
fail:
	zone_contents_deep_free(loader->contents);

	return NULL;
}

void zonefile_close(zloader_t *loader)
{
	if (loader == NULL) {
		return;
	}

	if (loader->type == ZONE_BACKEND_FILE) {
		zs_deinit(&loader->scanner);
		free(loader->source);
	} else {
#ifdef ENABLE_REDIS
		redisFree(loader->rdb);
#endif
	}
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

#ifdef ENABLE_REDIS
int zone_rdb_write(redisContext *rdb, zone_contents_t *zone)
{
	if (rdb == NULL) {
		return KNOT_EINVAL;
	}

	if (zone == NULL) {
		return KNOT_EEMPTYZONE;
	}

	return zone_dump_rdb(zone, rdb);
}
#endif

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
