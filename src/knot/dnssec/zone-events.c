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
#include <time.h>
#include "knot/conf/conf.h"
#include "libknot/dnssec/policy.h"
#include "knot/dnssec/zone-events.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "common/debug.h"
#include "knot/zone/zone.h"

static int init_dnssec_structs(const zone_contents_t *zone,
                               const conf_zone_t *config,
                               knot_zone_keys_t *zone_keys,
                               knot_dnssec_policy_t *policy,
                               knot_update_serial_t soa_up, bool force)
{
	assert(zone);
	assert(config);
	assert(zone_keys);
	assert(policy);

	// Read zone keys from disk
	bool nsec3_enabled = knot_is_nsec3_enabled(zone);
	int result = knot_load_zone_keys(config->dnssec_keydir,
	                                 zone->apex->owner,
	                                 nsec3_enabled, zone_keys);
	if (result != KNOT_EOK) {
		char *zname = knot_dname_to_str(zone->apex->owner);
		log_zone_error("DNSSEC: Zone %s - %s\n", zname,
		               knot_strerror(result));
		free(zname);
		knot_free_zone_keys(zone_keys);
		return result;
	}

	// Init sign policy
	knot_dnssec_init_default_policy(policy);
	policy->soa_up = soa_up;
	policy->forced_sign = force;

	// Override signature lifetime, if set in config
	if (config->sig_lifetime > 0) {
		knot_dnssec_policy_set_sign_lifetime(policy, config->sig_lifetime);
	}

	return KNOT_EOK;
}

static int zone_sign(zone_contents_t *zone, const conf_zone_t *zone_config,
                     changeset_t *out_ch, bool force,
                     knot_update_serial_t soa_up, uint32_t *refresh_at)
{
	assert(zone);
	assert(out_ch);

	char *msgpref = sprintf_alloc("DNSSEC: Zone %s -", zone_config->name);
	if (msgpref == NULL) {
		return KNOT_ENOMEM;
	}

	log_zone_info("DNSSEC: Zone %s - Signing started...\n", zone_config->name);
	uint32_t new_serial = zone_contents_next_serial(zone, zone_config->serial_policy);

	dbg_dnssec_verb("Changeset empty before generating NSEC chain: %d\n",
	                changeset_is_empty(out_ch));

	// Init needed structs
	knot_zone_keys_t zone_keys;
	knot_init_zone_keys(&zone_keys);
	knot_dnssec_policy_t policy = { '\0' };
	int result = init_dnssec_structs(zone, zone_config, &zone_keys, &policy,
	                                 soa_up, force);
	if (result != KNOT_EOK) {
		free(msgpref);
		return result;
	}

	// generate NSEC records
	result = knot_zone_create_nsec_chain(zone, out_ch,
	                                     &zone_keys, &policy);
	if (result != KNOT_EOK) {
		log_zone_error("%s Could not create NSEC(3) chain (%s).\n",
		               msgpref, knot_strerror(result));
		free(msgpref);
		knot_free_zone_keys(&zone_keys);
		return result;
	}
	dbg_dnssec_verb("Changeset empty after generating NSEC chain: %d\n",
	                changeset_is_empty(out_ch));

	// add missing signatures
	result = knot_zone_sign(zone, &zone_keys, &policy, out_ch,
	                        refresh_at);
	if (result != KNOT_EOK) {
		log_zone_error("%s Error while signing (%s).\n",
		               msgpref, knot_strerror(result));
		free(msgpref);
		knot_free_zone_keys(&zone_keys);
		return result;
	}
	dbg_dnssec_verb("Changeset emtpy after signing: %d\n",
	                changeset_is_empty(out_ch));

	// Check if only SOA changed
	if (changeset_is_empty(out_ch) &&
	    !knot_zone_sign_soa_expired(zone, &zone_keys, &policy)) {
		log_zone_info("%s No signing performed, zone is valid.\n",
		              msgpref);
		free(msgpref);
		knot_free_zone_keys(&zone_keys);
		assert(changeset_is_empty(out_ch));
		return KNOT_EOK;
	}

	// update SOA if there were any changes
	knot_rrset_t soa = node_rrset(zone->apex, KNOT_RRTYPE_SOA);
	knot_rrset_t rrsigs = node_rrset(zone->apex, KNOT_RRTYPE_RRSIG);
	assert(!knot_rrset_empty(&soa));
	result = knot_zone_sign_update_soa(&soa, &rrsigs, &zone_keys, &policy,
	                                   new_serial, out_ch);
	if (result != KNOT_EOK) {
		log_zone_error("%s Cannot update SOA record (%s). Not signing"
		               "the zone!\n", msgpref, knot_strerror(result));
		free(msgpref);
		knot_free_zone_keys(&zone_keys);
		return result;
	}

	knot_free_zone_keys(&zone_keys);
	dbg_dnssec_detail("Zone signed: changes=%zu\n",
	                  changeset_size(out_ch));

	log_zone_info("%s Successfully signed.\n", msgpref);
	free(msgpref);

	return KNOT_EOK;
}

int knot_dnssec_zone_sign(zone_contents_t *zone, const conf_zone_t *zone_config,
                          changeset_t *out_ch,
                          knot_update_serial_t soa_up, uint32_t *refresh_at)
{
	if (zone == NULL || zone_config == NULL || out_ch == NULL) {
		return KNOT_EINVAL;
	}

	return zone_sign(zone, zone_config, out_ch, false, soa_up, refresh_at);
}

int knot_dnssec_zone_sign_force(zone_contents_t *zone, const conf_zone_t *zone_config,
                                changeset_t *out_ch, uint32_t *refresh_at)
{
	if (zone == NULL || zone_config == NULL || out_ch == NULL) {
		return KNOT_EINVAL;
	}

	return zone_sign(zone, zone_config, out_ch, true, KNOT_SOA_SERIAL_UPDATE,
	                 refresh_at);
}

int knot_dnssec_sign_changeset(const zone_contents_t *zone,
                               conf_zone_t *zone_config,
                               const changeset_t *in_ch,
                               changeset_t *out_ch,
                               uint32_t *refresh_at)
{
	if (zone == NULL || in_ch == NULL || out_ch == NULL || refresh_at == NULL) {
		return KNOT_EINVAL;
	}

	// Keep the original serial
	knot_update_serial_t soa_up = KNOT_SOA_SERIAL_KEEP;
	uint32_t new_serial = zone_contents_serial(zone);

	// Init needed structures
	knot_zone_keys_t zone_keys;
	knot_init_zone_keys(&zone_keys);
	knot_dnssec_policy_t policy = { '\0' };
	int ret = init_dnssec_structs(zone, zone_config, &zone_keys, &policy,
	                              soa_up, false);
	if (ret != KNOT_EOK) {
		return ret;
	}

	char *zname = knot_dname_to_str(zone->apex->owner);
	char *msgpref = sprintf_alloc("DNSSEC: Zone %s -", zname);
	free(zname);
	if (msgpref == NULL) {
		return KNOT_ENOMEM;
	}

	// Sign added and removed RRSets in changeset
	ret = knot_zone_sign_changeset(zone, in_ch, out_ch,
	                               &zone_keys, &policy);
	if (ret != KNOT_EOK) {
		log_zone_error("%s Failed to sign changeset (%s)\n", msgpref,
		               knot_strerror(ret));
		knot_free_zone_keys(&zone_keys);
		free(msgpref);
		return ret;
	}

	// Create NSEC(3) chain
	ret = knot_zone_create_nsec_chain(zone, out_ch, &zone_keys, &policy);
	if (ret != KNOT_EOK) {
		log_zone_error("%s Failed to create NSEC(3) chain (%s)\n",
		               msgpref, knot_strerror(ret));
		knot_free_zone_keys(&zone_keys);
		free(msgpref);
		return ret;
	}

	// Sign added NSEC(3)
	ret = knot_zone_sign_nsecs_in_changeset(&zone_keys, &policy,
	                                        out_ch);
	if (ret != KNOT_EOK) {
		log_zone_error("%s Failed to sign changeset (%s)\n",
		               msgpref, knot_strerror(ret));
		knot_free_zone_keys(&zone_keys);
		free(msgpref);
		return ret;
	}

	// Update SOA RRSIGs
	knot_rrset_t soa = node_rrset(zone->apex, KNOT_RRTYPE_SOA);
	knot_rrset_t rrsigs = node_rrset(zone->apex, KNOT_RRTYPE_RRSIG);
	ret = knot_zone_sign_update_soa(&soa, &rrsigs, &zone_keys, &policy,
	                                new_serial, out_ch);
	if (ret != KNOT_EOK) {
		log_zone_error("%s Failed to sign SOA RR (%s)\n", msgpref,
		               knot_strerror(ret));
		knot_free_zone_keys(&zone_keys);
		free(msgpref);
		return ret;
	}

	knot_free_zone_keys(&zone_keys);
	free(msgpref);

	*refresh_at = policy.refresh_before; // only new signatures are made

	return KNOT_EOK;
}
