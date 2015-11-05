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

#include "common/mem.h"
#include "knot/conf/conf.h"
#include "libknot/dnssec/policy.h"
#include "knot/dnssec/zone-events.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "common/debug.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonefile.h"


static int init_dnssec_structs(zone_contents_t *zone,
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
        log_zone_error(zone->apex->owner, "DNSSEC, failed to load keys (%s)",
                       knot_strerror(result));
        knot_free_zone_keys(zone_keys);
        return result;
    }
    
    //Most likely unstable. Test excessively REPLACE WITH LOAD NSEC5KEY FUNCTION. CONDITIONAL ON NSEC%KEY EXISTING!!!
    //zone->nsec5_key = knot_get_nsec5_key(zone_keys);
    if(knot_get_nsec5_key(zone_keys)) {
        zone->nsec5_key = *knot_load_nsec5_key(config->dnssec_keydir,
                                           zone->apex->owner);
        dbg_dnssec_verb("NSEC5KEY with keytag %d and algorithm %d loaded to zone\n", zone->nsec5_key.nsec5_key.keytag,zone->nsec5_key.nsec5_key.algorithm);
    
    }
    //bool nsec5_enabled = knot_is_nsec5_enabled(zone);
    //printf ("EINAI NSEC5 ENABLED: %d\n",nsec5_enabled);
    
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
    
    const knot_dname_t *zone_name = zone->apex->owner;
    
    log_zone_info(zone_name, "DNSSEC, signing started");
    uint32_t new_serial = zone_contents_next_serial(zone, zone_config->serial_policy);
    
    dbg_dnssec_verb("changeset empty before generating NSEC chain: %d\n",
                    changeset_empty(out_ch));
    
    // Init needed structs
    knot_zone_keys_t zone_keys;
    knot_init_zone_keys(&zone_keys);
    knot_dnssec_policy_t policy = { '\0' };
    int result = init_dnssec_structs(zone, zone_config, &zone_keys, &policy,
                                     soa_up, force);
    if (result != KNOT_EOK) {
        return result;
    }
    
    // generate NSEC records
    result = knot_zone_create_nsec_chain(zone, out_ch,
                                         &zone_keys, &policy);
    if (result != KNOT_EOK) {
        log_zone_error(zone_name, "DNSSEC, failed to create NSEC(3) chain (%s)",
                       knot_strerror(result));
        knot_free_zone_keys(&zone_keys);
        return result;
    }
    dbg_dnssec_verb("changeset empty after generating NSEC chain: %d\n",
                    changeset_empty(out_ch));
    
    //zonefile_write("/Users/dpapadopoulos/Desktop/zone_events_post_create_Chain",zone);
    
    // add missing signatures
    result = knot_zone_sign(zone, &zone_keys, &policy, out_ch,
                            refresh_at);
    if (result != KNOT_EOK) {
        log_zone_error(zone_name, "DNSSEC, failed to sign the zone (%s)",
                       knot_strerror(result));
        knot_free_zone_keys(&zone_keys);
        return result;
    }
    dbg_dnssec_verb("changeset emtpy after signing: %d\n",
                    changeset_empty(out_ch));
    
    //zonefile_write("/Users/dpapadopoulos/Desktop/zone_events_post_zone_sign",zone);

    
    // Check if only SOA changed
    if (changeset_empty(out_ch) &&
        !knot_zone_sign_soa_expired(zone, &zone_keys, &policy)) {
        log_zone_info(zone_name, "DNSSEC, no signing performed, zone is valid");
        knot_free_zone_keys(&zone_keys);
        assert(changeset_empty(out_ch));
        return KNOT_EOK;
    }
    //zonefile_write("/Users/dpapadopoulos/Desktop/zone_events_pre_soa_sign",zone);

    // update SOA if there were any changes
    knot_rrset_t soa = node_rrset(zone->apex, KNOT_RRTYPE_SOA);
    knot_rrset_t rrsigs = node_rrset(zone->apex, KNOT_RRTYPE_RRSIG);
    assert(!knot_rrset_empty(&soa));
    result = knot_zone_sign_update_soa(&soa, &rrsigs, &zone_keys, &policy,
                                       new_serial, out_ch);
    if (result != KNOT_EOK) {
        log_zone_error(zone_name, "DNSSEC, not signing, failed to update "
                       "SOA record (%s)", knot_strerror(result));
        knot_free_zone_keys(&zone_keys);
        return result;
    }
    //zonefile_write("/Users/dpapadopoulos/Desktop/zone_events_post_soa_sign",zone);
    
    /*dbg_dnssec_detail("ZWNOKLEIDO: pre-zone-keys-release: keytag=%d\n",
                       zone->nsec5_key.nsec5_key.keytag);
    dbg_dnssec_detail("ZWNOKLEIDO: pre-zone-keys-release: private_key=%d\n",
                      zone->nsec5_key.nsec5_key.data);
    
    knot_zone_key_t *testokleido = knot_get_nsec5_key(&zone_keys);
    
    dbg_dnssec_detail("KLEIDOKLEIDO: pre-zone-key-release: keytag=%d\n",
                      testokleido->nsec5_key.keytag);
    dbg_dnssec_detail("KLEIDOKLEIDO: pre-zone-key-release: private_key=%d\n",
                        testokleido->nsec5_key.data);
    */
    knot_free_zone_keys(&zone_keys);
    dbg_dnssec_detail("zone signed: changes=%zu\n",
                      changeset_size(out_ch));
    
    log_zone_info(zone_name, "DNSSEC, successfully signed");
    //zonefile_write("/Users/dpapadopoulos/Desktop/vgainontas_apo_to_zone_sign",zone);
    /*
    dbg_dnssec_detail("ZWNOKLEIDO: post-zone-key-release: keytag=%d\n",
                      zone->nsec5_key.nsec5_key.keytag);
    dbg_dnssec_detail("ZWNOKLEIDO: post-zone-keys-release: private_key=%d\n",
                      zone->nsec5_key.nsec5_key.data);
    //dbg_dnssec_detail("ZWNOKLEIDO: post-zone-keys-release: address of nsec5_ctx=%d\n",&(zone->nsec5_key.nsec5_ctx));
    
    
    
    dbg_dnssec_detail("KLEIDOKLEIDO: post-zone-key-release: keytag=%d\n",
                      testokleido->nsec5_key.keytag);
    dbg_dnssec_detail("KLEIDOKLEIDO: post-zone-key-release: private_key=%d\n",
                      testokleido->nsec5_key.data);
    //dbg_dnssec_detail("KLEIDOKLEIDO: post-zone-keys-release: address of nsec5_ctx=%d\n",&(testokleido->nsec5_ctx));
    */
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

int knot_dnssec_sign_changeset(zone_contents_t *zone,
                               conf_zone_t *zone_config,
                               const changeset_t *in_ch,
                               changeset_t *out_ch,
                               uint32_t *refresh_at)
{
    if (zone == NULL || in_ch == NULL || out_ch == NULL || refresh_at == NULL) {
        return KNOT_EINVAL;
    }
    
    const knot_dname_t *zone_name = zone->apex->owner;
    
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
    
    // Sign added and removed RRSets in changeset
    ret = knot_zone_sign_changeset(zone, in_ch, out_ch,
                                   &zone_keys, &policy);
    if (ret != KNOT_EOK) {
        log_zone_error(zone_name, "DNSSEC, failed to sign changeset (%s)",
                       knot_strerror(ret));
        knot_free_zone_keys(&zone_keys);
        return ret;
    }
    
    // Create NSEC(3) chain
    ret = knot_zone_create_nsec_chain(zone, out_ch, &zone_keys, &policy);
    if (ret != KNOT_EOK) {
        log_zone_error(zone_name, "DNSSEC, failed to create NSEC(3) chain (%s)",
                       knot_strerror(ret));
        knot_free_zone_keys(&zone_keys);
        return ret;
    }
    
    // Sign added NSEC(3)
    ret = knot_zone_sign_nsecs_in_changeset(&zone_keys, &policy,
                                            out_ch);
    if (ret != KNOT_EOK) {
        log_zone_error(zone_name, "DNSSEC, failed to sign changeset (%s)",
                       knot_strerror(ret));
        knot_free_zone_keys(&zone_keys);
        return ret;
    }
    
    // Update SOA RRSIGs
    knot_rrset_t soa = node_rrset(zone->apex, KNOT_RRTYPE_SOA);
    knot_rrset_t rrsigs = node_rrset(zone->apex, KNOT_RRTYPE_RRSIG);
    ret = knot_zone_sign_update_soa(&soa, &rrsigs, &zone_keys, &policy,
                                    new_serial, out_ch);
    if (ret != KNOT_EOK) {
        log_zone_error(zone_name, "DNSSEC, failed to sign SOA record (%s)",
                       knot_strerror(ret));
        knot_free_zone_keys(&zone_keys);
        return ret;
    }
    
    knot_free_zone_keys(&zone_keys);
    
    *refresh_at = policy.refresh_before; // only new signatures are made
    
    return KNOT_EOK;
}
