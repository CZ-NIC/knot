/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/zone/skip.h"
#include "knot/zone/zone.h"
#include "knot/zone/semantic-check.h"
#include "libzscanner/scanner.h"

#ifdef ENABLE_REDIS
#include <hiredis/hiredis.h>
#endif

typedef struct {
	unsigned type;
	union {
		void *rdb;                     /*!< Rdb context. */
		struct {
			char *source;          /*!< Zone source file. */
			zs_scanner_t scanner;  /*!< Zone scanner. */
		};
	};

	int ret;                         /*!< Callback return value. */
	zone_contents_t *contents;       /*!< Created zone. */
	semcheck_optional_t sem_checks;  /*!< Do semantic checks. */
	sem_handler_t *err_handler;      /*!< Semantic checks error handler. */
	zone_skip_t *skip;               /*!< Skip configured types. */
	time_t time;                     /*!< time for zone check. */
} zloader_t;

void err_handler_logger(sem_handler_t *handler, const zone_contents_t *zone,
                        const knot_dname_t *node, sem_error_t error, const char *data);

/*!
 * \brief Open zone file for loading.
 *
 * \param loader Output zone loader.
 * \param source Source file name.
 * \param origin Zone origin.
 * \param dflt_ttl Default TTL.
 * \param semantic_checks Perform semantic checks.
 * \param time Time for semantic check.
 * \param skip RRTypes to be skipped.
 *
 * \retval Initialized loader on success.
 * \retval NULL on error.
 */
int zonefile_open(zloader_t *loader, const char *source, const knot_dname_t *origin,
                  uint32_t dflt_ttl, semcheck_optional_t sem_checks,
                  sem_handler_t *sem_err_handler, time_t time, zone_skip_t *skip);

#ifdef ENABLE_REDIS
redisContext *zone_rdb_connect(conf_t *conf);

int zone_rdb_exists(conf_t *conf, const knot_dname_t *zone, uint32_t *serial);

int zone_rdb_open(zloader_t *loader, redisContext *rdb, const knot_dname_t *origin,
                  semcheck_optional_t sem_checks, sem_handler_t *sem_err_handler,
                  time_t time, zone_skip_t *skip);

int zone_rdb_write(redisContext *rdb, zone_contents_t *zone);
#endif

/*!
 * \brief Loads zone from a zone file.
 *
 * \param loader Zone loader instance.
 * \param threads The number of threads to use for semantic checks (0 for auto).
 *
 * \retval Loaded zone contents on success.
 * \retval NULL otherwise.
 */
zone_contents_t *zonefile_load(zloader_t *loader, uint16_t threads);

/*!
 * \brief Checks if zonefile exists.
 *
 * \param path   Zonefile path.
 * \param mtime  Zonefile mtime if exists (can be NULL).
 *
 * \return KNOT_E*
 */
int zonefile_exists(const char *path, struct timespec *mtime);

/*!
 * \brief Write zone contents to zone file.
 *
 * \param path    Zonefile path.
 * \param zone    Zone contents.
 * \param skip    RRTypes to be skipped.
 *
 * \return KNOT_E*
 */
int zonefile_write(const char *path, zone_contents_t *zone, zone_skip_t *skip);

/*!
 * \brief Close zone file loader.
 *
 * \param loader Zone loader instance.
 */
void zonefile_close(zloader_t *loader);

/*!
 * \brief Adds one RR into zone.
 *
 * \param contents  Zone contents to add rr to.
 * \param rr        RR to add.
 * \param skip      RRTypes to be skipped.
 *
 * \return KNOT_E*
 */
int zcreator_step(zone_contents_t *contents, const knot_rrset_t *rr, zone_skip_t *skip);
