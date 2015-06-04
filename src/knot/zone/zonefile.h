/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file zone-load.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Zone loading
 *
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stdio.h>

#include "knot/zone/zone.h"
#include "knot/zone/semantic-check.h"
#include "zscanner/scanner.h"
/*!
 * \brief Zone creator structure.
 */
typedef struct zcreator {
	zone_contents_t *z;  /*!< Created zone. */
	bool master;              /*!< Master flag. True if server is a primary
	                               master for the zone. */
	int ret;                  /*!< Return value. */
} zcreator_t;

/*!
 * \brief Zone loader structure.
 */
typedef struct zloader_t {
	char *source;                /*!< Zone source file. */
	char *origin;                /*!< Zone's origin string. */
	bool semantic_checks;        /*!< Do semantic checks. */
	err_handler_t *err_handler;  /*!< Semantic checks error handler. */
	zs_scanner_t *scanner;       /*!< Zone scanner. */
	zcreator_t *creator;         /*!< Loader context. */
} zloader_t;

/*!
 * \brief Open zone file for loading.
 *
 * \param zl Output zone loader.
 * \param source Source file name.
 * \param origin Zone origin.
 * \param semantic_checks Perform semantic checks.
 *
 * \retval Initialized loader on success.
 * \retval NULL on error.
 */
int zonefile_open(zloader_t *loader, const char *source, const char *origin,
		  bool semantic_checks);

/*!
 * \brief Loads zone from a zone file.
 *
 * \param loader Zone loader instance.
 *
 * \retval Loaded zone contents on success.
 * \retval NULL otherwise.
 */
zone_contents_t *zonefile_load(zloader_t *loader);

/*! \brief Return zone file mtime. */
time_t zonefile_mtime(const char *path);

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
 * \param zl  Zone loader.
 * \param rr  RR to add.
 *
 * \return KNOT_E*
 */
int zcreator_step(zcreator_t *zl, const knot_rrset_t *rr);

/*!
 * \brief Scanner error processing function.
 * \param scanner  Scanner to use.
 */
void process_error(zs_scanner_t *scanner);

/*!
 * \brief Logs TTL mismatch error.
 *
 * \param zone    Related zone.
 * \param node    Node with TTL mismatch.
 * \param rr      RR that caused the mismatch.
 */
void log_ttl_error(const zone_contents_t *zone, const zone_node_t *node,
                   const knot_rrset_t *rr);

/*! @} */
