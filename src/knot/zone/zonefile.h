/*  Copyright (C) 2025 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "knot/zone/zone.h"
#include "knot/zone/semantic-check.h"
#include "libzscanner/scanner.h"

typedef struct {
	unsigned type;
	union {
		void *rdb;
		struct {
			char *source;          /*!< Zone source file. */
			zs_scanner_t scanner;  /*!< Zone scanner. */
		};
	};

	int ret;                         /*!< Callback return value. */
	zone_contents_t *contents;       /*!< Created zone. */
	semcheck_optional_t sem_checks;  /*!< Do semantic checks. */
	sem_handler_t *err_handler;      /*!< Semantic checks error handler. */
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
 *
 * \retval Initialized loader on success.
 * \retval NULL on error.
 */
int zonefile_open(zloader_t *loader, const char *source, const knot_dname_t *origin,
                  uint32_t dflt_ttl, semcheck_optional_t sem_checks,
                  sem_handler_t *sem_err_handler, time_t time);

int zone_rdb_open(zloader_t *loader, const knot_dname_t *origin, const char *addr,
                  int port, semcheck_optional_t sem_checks,
                  sem_handler_t *sem_err_handler, time_t time);

/*!
 * \brief Loads zone from a zone file.
 *
 * \param loader Zone loader instance.
 *
 * \retval Loaded zone contents on success.
 * \retval NULL otherwise.
 */
zone_contents_t *zonefile_load(zloader_t *loader);

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
 */
int zonefile_write(const char *path, zone_contents_t *zone);

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
 * \param rr  RR to add.
 *
 * \return KNOT_E*
 */
int zcreator_step(zone_contents_t *contents, const knot_rrset_t *rr);
