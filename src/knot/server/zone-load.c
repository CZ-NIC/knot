/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <sys/stat.h>
#include <inttypes.h>

#include "knot/conf/conf.h"
#include "knot/other/debug.h"
#include "knot/zone/contents.h"
#include "knot/zone/zonefile.h"
#include "libknot/dname.h"
#include "libknot/dnssec/crypto.h"
#include "libknot/dnssec/random.h"
#include "libknot/rrtype/soa.h"
#include "knot/zone/zone.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonedb.h"
#include "common/descriptor.h"

/* Constants */

#define XFRIN_BOOTSTRAP_DELAY 2000 /*!< AXFR bootstrap avg. delay */

/*- zone loading/updating ---------------------------------------------------*/

/*!
 * \brief Handle retrieval of zone if zone file does not exist.
 *
 * \param conf      New configuration for given zone.
 *
 * \return New zone, NULL if bootstrap not possible.
 */
static zone_t *bootstrap_zone(conf_zone_t *conf)
{
	assert(conf);

	bool bootstrap = !EMPTY_LIST(conf->acl.xfr_in);
	if (!bootstrap) {
		return load_zone_file(conf); /* No master for this zone, fallback. */
	}

	zone_t *new_zone = zone_new(conf);
	if (!new_zone) {
		log_zone_error("Bootstrap of zone '%s' failed: %s\n",
		               conf->name, knot_strerror(KNOT_ENOMEM));
		return NULL;
	}

	/* Initialize bootstrap timer. */
	new_zone->xfr_in.bootstrap_retry = knot_random_uint32_t() % XFRIN_BOOTSTRAP_DELAY;

	return new_zone;
}

zone_t *load_zone_file(conf_zone_t *conf)
{
	assert(conf);

	/* Open zone file for parsing. */
	zloader_t zl;
	int ret = zonefile_open(&zl, conf);
	if (ret != KNOT_EOK) {
		log_zone_error("Failed to open zone file '%s': %s\n",
		               conf->file, knot_strerror(ret));
		return NULL;
	}

	/* Create the new zone. */
	zone_t *zone = zone_new((conf_zone_t *)conf);
	if (zone == NULL) {
		log_zone_error("Failed to create zone '%s': %s\n",
		               conf->name, knot_strerror(KNOT_ENOMEM));
		return NULL;
	}

	struct stat st;
	if (stat(conf->file, &st) < 0) {
		/* Go silently and reset mtime to 0. */
		memset(&st, 0, sizeof(struct stat));
	}

	/* Set the zone type (master/slave). If zone has no master set, we
	 * are the primary master for this zone (i.e. zone type = master).
	 */
	zl.creator->master = (zone_master(zone) == NULL);

	/* Load the zone contents. */
	knot_zone_contents_t *zone_contents = zonefile_load(&zl);
	zonefile_close(&zl);

	/* Check the loader result. */
	if (zone_contents == NULL) {
		log_zone_error("Failed to load zone file '%s'.\n", conf->file);
		zone->conf = NULL;
		zone_free(&zone);
		return NULL;
	}

	/* Link zone contents to zone. */
	zone->contents = zone_contents;

	/* Save the timestamp from the zone db file. */
	zone->zonefile_mtime = st.st_mtime;
	zone->zonefile_serial = knot_zone_serial(zone->contents);

	return zone;
}

/*!
 * \brief Check zone configuration constraints.
 */
static int update_zone_postcond(zone_t *new_zone, const conf_t *config)
{
	/* Bootstrapped zone, no checks apply. */
	if (new_zone->contents == NULL) {
		return KNOT_EOK;
	}

	/* Check minimum EDNS0 payload if signed. (RFC4035/sec. 3) */
	if (knot_zone_contents_is_signed(new_zone->contents)) {
		unsigned edns_dnssec_min = KNOT_EDNS_MIN_DNSSEC_PAYLOAD;
		if (config->max_udp_payload < edns_dnssec_min) {
			log_zone_warning("EDNS payload lower than %uB for "
			                 "DNSSEC-enabled zone '%s'.\n",
			                 edns_dnssec_min, new_zone->conf->name);
		}
	}

	/* Check NSEC3PARAM state if present. */
	int result = knot_zone_contents_load_nsec3param(new_zone->contents);
	if (result != KNOT_EOK) {
		log_zone_error("NSEC3 signed zone has invalid or no "
			       "NSEC3PARAM record.\n");
		return result;
	}

	return KNOT_EOK;
}
