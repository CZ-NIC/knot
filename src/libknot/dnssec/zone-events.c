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

#include <config.h>
#include <assert.h>
#include <time.h>
#include "knot/conf/conf.h"
#include "knot/server/zones.h"
#include "libknot/dnssec/zone-events.h"
#include "libknot/dnssec/zone-nsec.h"
#include "libknot/dnssec/zone-sign.h"
#include "libknot/dnssec/zone-keys.h"
#include "libknot/dnssec/policy.h"
#include "libknot/zone/zone.h"
#include "libknot/util/debug.h"

static uint32_t time_now(void)
{
	return (uint32_t)time(NULL);
}

static void init_default_policy(knot_dnssec_policy_t *p,
                                knot_update_serial_t soa_up)
{
	knot_dnssec_policy_t p_image = DEFAULT_DNSSEC_POLICY;
	memcpy(p, &p_image, sizeof(knot_dnssec_policy_t));
	p->soa_up = soa_up;
}

static void init_forced_policy(knot_dnssec_policy_t *p,
                               knot_update_serial_t soa_up)
{
	knot_dnssec_policy_t p_image = FORCED_DNSSEC_POLICY;
	memcpy(p, &p_image, sizeof(knot_dnssec_policy_t));
	p->soa_up = soa_up;
}

static int zone_sign(knot_zone_t *zone, knot_changeset_t *out_ch, bool force,
                     knot_update_serial_t soa_up)
{
	if (zone == NULL || zone->contents == NULL) {
		return KNOT_EINVAL;
	}

	dbg_dnssec_verb("Changeset emtpy before generating NSEC chain: %d\n",
	        knot_changeset_is_empty(out_ch));

	conf_zone_t *zone_config = ((zonedata_t *)knot_zone_data(zone))->conf;
	int result = KNOT_EOK;

	if (!zone_config->dnssec_enable) {
		char *zname = knot_dname_to_str(zone->name);
		log_server_warning("DNSSEC not enabled for '%s'.\n", zname);
		free(zname);
		return KNOT_EOK;
	}

	rcu_read_lock();
	char *keydir = strdup(conf()->dnssec_keydir);
	rcu_read_unlock();

	// Read zone keys from disk
	knot_zone_keys_t zone_keys = { '\0' };
	bool nsec3_enabled = is_nsec3_enabled(zone->contents);
	result = load_zone_keys(keydir, zone->contents->apex->owner,
	                        nsec3_enabled, &zone_keys);
	free(keydir);
	if (result != KNOT_EOK) {
		char *zname = knot_dname_to_str(zone->name);
		log_zone_error("DNSSEC keys could not be loaded (%s). "
		               "Not signing the %s zone!\n",
		               knot_strerror(result), zname);
		free(zname);
		free_zone_keys(&zone_keys);
		return result;
	}

	// Create sign policy
	knot_dnssec_policy_t policy;
	if (force) {
		init_forced_policy(&policy, soa_up);
	} else {
		init_default_policy(&policy, soa_up);
	}

	// generate NSEC records
	result = knot_zone_create_nsec_chain(zone->contents, out_ch);
	if (result != KNOT_EOK) {
		char *zname = knot_dname_to_str(zone->name);
		log_zone_error("Could not create NSEC(3) chain (%s). "
		               "Not signing the %s zone!\n",
		               knot_strerror(result), zname);
		free(zname);
		free_zone_keys(&zone_keys);
		return result;
	}
	dbg_dnssec_verb("Changeset emtpy after generating NSEC chain: %d\n",
	        knot_changeset_is_empty(out_ch));

	// add missing signatures
	result = knot_zone_sign(zone->contents, &zone_keys, &policy, out_ch);
	if (result != KNOT_EOK) {
		char *zname = knot_dname_to_str(zone->name);
		log_zone_error("Error signing zone %s (%s).\n",
		               zname, knot_strerror(result));
		free(zname);
		free_zone_keys(&zone_keys);
		return result;
	}
	dbg_dnssec_verb("Changeset emtpy after signing: %d\n",
	        knot_changeset_is_empty(out_ch));

	// Check if only SOA changed
	if (knot_changeset_is_empty(out_ch) &&
	    !knot_zone_sign_soa_expired(zone->contents, &zone_keys, &policy)) {
		char *zname = knot_dname_to_str(zone->name);
		log_server_info("No signing performed, zone %s is valid.\n",
		                zname);
		free(zname);
		free_zone_keys(&zone_keys);
		assert(knot_changeset_is_empty(out_ch));
		return KNOT_EOK;
	}

	// update SOA if there were any changes
	result = knot_zone_sign_update_soa(zone->contents, &zone_keys, &policy,
	                                   out_ch);
	if (result != KNOT_EOK) {
		char *zname = knot_dname_to_str(zone->name);
		log_server_error("Cannot update SOA record (%s)."
		                 " Not signing the %s zone!\n",
		                 knot_strerror(result), zname);
		free(zname);
		free_zone_keys(&zone_keys);
		return result;
	}

	free_zone_keys(&zone_keys);

	return KNOT_EOK;
}

int knot_dnssec_zone_sign(knot_zone_t *zone,
                          knot_changeset_t *out_ch,
                          knot_update_serial_t soa_up)
{
	return zone_sign(zone, out_ch, false, soa_up);
}

int knot_dnssec_zone_sign_force(knot_zone_t *zone,
                                knot_changeset_t *out_ch)
{
	return zone_sign(zone, out_ch, true, KNOT_SOA_SERIAL_INC);
}
