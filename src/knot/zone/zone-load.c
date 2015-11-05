/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "common/log.h"
#include "knot/server/journal.h"
#include "knot/zone/zone-diff.h"
#include "knot/zone/zone-load.h"
#include "knot/zone/contents.h"
#include "knot/zone/zonefile.h"
#include "knot/dnssec/zone-events.h"
#include "knot/updates/apply.h"
#include "libknot/rdata.h"
#include "knot/dnssec/zone-nsec.h"


zone_contents_t *zone_load_contents(conf_zone_t *zone_config)
{
	assert(zone_config);

	zloader_t zl;
	int ret = zonefile_open(&zl, zone_config->file, zone_config->name,
	                        zone_config->enable_checks);
	if (ret != KNOT_EOK) {
		return NULL;
	}

	/* Set the zone type (master/slave). If zone has no master set, we
	 * are the primary master for this zone (i.e. zone type = master).
	 */
	zl.creator->master = !zone_load_can_bootstrap(zone_config);

	zone_contents_t *zone_contents = zonefile_load(&zl);
	zonefile_close(&zl);
	if (zone_contents == NULL) {
		return NULL;
	}
	return zone_contents;
}

/*! \brief Check zone configuration constraints. */
int zone_load_check(zone_contents_t *contents, conf_zone_t *zone_config)
{
	/* Bootstrapped zone, no checks apply. */
	if (contents == NULL) {
		return KNOT_EOK;
	}

	const knot_dname_t *zone_name = contents->apex->owner;

	/* Check minimum EDNS0 payload if signed. (RFC4035/sec. 3) */
	if (zone_contents_is_signed(contents)) {
		if (conf()->max_udp_payload < KNOT_EDNS_MIN_DNSSEC_PAYLOAD) {
			log_zone_warning(zone_name, "EDNS payload size is "
			                 "lower than %u bytes for DNSSEC zone",
					 KNOT_EDNS_MIN_DNSSEC_PAYLOAD);
			conf()->max_udp_payload = KNOT_EDNS_MIN_DNSSEC_PAYLOAD;
		}
	}

	/* Check NSEC3PARAM state if present. */
    //printf("MESA sto zone_load_check TO KEYTAG EINAI: %d\n", contents->nsec5_key.nsec5_key.keytag);
    //printf("PARAMETERS LOADED FROM ZONE LOAD\n");

	int result = zone_contents_load_nsec3param(contents);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "NSEC3 signed zone has invalid or no "
		               "NSEC3PARAM record");
		return result;
	}

    // TODO: ADD a check for the presence and validity of NSEC5KEY
	return KNOT_EOK;
}

/*!
 * \brief Apply changesets to zone from journal.
 */
int zone_load_journal(zone_t *zone, zone_contents_t *contents)
{
    //printf("MPIKA STO LOAD_JOURNAL\n");
	/* Check if journal is used and zone is not empty. */
	if (!journal_exists(zone->conf->ixfr_db) ||
	    zone_contents_is_empty(contents)) {
		return KNOT_EOK;
	}

	/* Fetch SOA serial. */
	uint32_t serial = zone_contents_serial(contents);

	/*! \todo Check what should be the upper bound. */
	list_t chgs;
	init_list(&chgs);

	pthread_mutex_lock(&zone->journal_lock);
	int ret = journal_load_changesets(zone, &chgs, serial, serial - 1);
	pthread_mutex_unlock(&zone->journal_lock);

	if ((ret != KNOT_EOK && ret != KNOT_ERANGE) || EMPTY_LIST(chgs)) {
		changesets_free(&chgs);
		/* Absence of records is not an error. */
		if (ret == KNOT_ENOENT) {
			return KNOT_EOK;
		} else {
			return ret;
		}
	}

	/* Apply changesets. */
	ret = apply_changesets_directly(contents, &chgs);
	log_zone_info(zone->name, "changes from journal applied %u -> %u (%s)",
	              serial, zone_contents_serial(contents),
	              knot_strerror(ret));

	updates_cleanup(&chgs);
	changesets_free(&chgs);
	return ret;
}

int zone_load_post(zone_contents_t *contents, zone_t *zone, uint32_t *dnssec_refresh)
{
	if (zone == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	const conf_zone_t *conf = zone->conf;
	changeset_t change;
	ret = changeset_init(&change, zone->name);
	if (ret != KNOT_EOK) {
		return ret;
	}

    //printf("PRIN TO ZONESIGN (STO zone-load.c -> zone_load_post) TO KEYTAG EINAI: %d\n", contents->nsec5_key.nsec5_key.keytag);

	/* Sign zone using DNSSEC (if configured). */
	if (conf->dnssec_enable) {
		assert(conf->build_diffs);
		ret = knot_dnssec_zone_sign(contents, conf, &change, KNOT_SOA_SERIAL_UPDATE,
		                            dnssec_refresh);
        //printf("VGIKA APO TO knot_dnssec_zone_sign\n");
		if (ret != KNOT_EOK) {
            printf("alla to ret den itan KNOT_EOK\n");
			changeset_clear(&change);
			return ret;
		}
        //printf("AAAAAAAAAAAAABAAAAAAAAAABABABBAABBAJSBIBSIBKJSBCKBKCBDKJBVJKDBVKJBJKVBFKJVBFJ\n");
        //printf("AAAAAAAAAAAAABAAAAAAAAAABABABBAABBAJSBIBSIBKJSBCKBKCBDKJBVJKDBVKJBJKVBFKJVBFJ\n");

        //printf("============================8------------->=================\n");
        //zonefile_write("/Users/dpapadopoulos/Desktop/stozone_load_poat_meta_to_sign_print_to_apply",contents);
        //printf("============================8------------->=================\n");
        //printf("AAAAAAAAAAAAABAAAAAAAAAABABABBAABBAJSBIBSIBKJSBCKBKCBDKJBVJKDBVKJBJKVBFKJVBFJ\n");
        //printf("AAAAAAAAAAAAABAAAAAAAAAABABABBAABBAJSBIBSIBKJSBCKBKCBDKJBVJKDBVKJBJKVBFKJVBFJ\n");
    
        //zonefile_write("/Users/dpapadopoulos/Desktop/stozone_load_poat_to_changeset_meta_to_sign",change.add);
        
		/* Apply DNSSEC changes. */
		if (!changeset_empty(&change)) {
            //printf("zone_load_post MPAINW NA KANW ALLAGES me apply changes directly\n");
			ret = apply_changeset_directly(contents, &change);
            //printf("zone_load_post vgika apo allages me apply changes directly\n");
            //printf("PRIN TO CLEANUP\n");
			update_cleanup(&change);
			if (ret != KNOT_EOK) {
                printf("APO TIS ALLAGES VGIKA ME oxi KNOT_EOK\n");
				changeset_clear(&change);
                //printf("VGIKA APO TO CHANGEET_CLEAR\n");
				return ret;
			}
		} else {
			changeset_clear(&change);
		}
        //The following is necessary in case the zone was loaded from journal
        //and the changeset is empty. The apointer adjustment during load_journal
        //does not have the nsec5key as it is not yet loaded. Signing is not performed
        //as the zone is still valid, therefore the nsec3 pointers are never adjusted.
        //This situation occurs if one replaces the signed file with the unsigned version
        //of the same zone yet maintains the old journal.
        if (knot_is_nsec5_enabled(contents) && !contents->apex->nsec3_node) {
            ret = zone_contents_adjust_full(contents, NULL, NULL);
            if (ret != KNOT_EOK) {
                printf("THE NEW ADJUSTMENT FAILED\n");
                changeset_clear(&change);
                return ret;
            }
        }
	}

    //zonefile_write("/Users/dpapadopoulos/Desktop/stozone_load_poat_meta_to_apply",contents);
    
    //printf("+++++++++++++++++++++++++++++++++++++++++META TO ZONESIGN (STO zone-load.c -> load_post) TO KEYTAG EINAI: %d+++++++++++++++++++++\n\n\n ", contents->nsec5_key.nsec5_key.keytag);

    
	/* Calculate IXFR from differences (if configured). */
	const bool contents_changed = zone->contents && (contents != zone->contents);
    //printf("zone->cotnents: %d contents != zone->contents: %d", zone->contents, (contents != zone->contents));
	if (contents_changed && conf->build_diffs) {
        //printf("=============CONFIGURED FOR IXFR================================\n");
		/* Replace changes from zone signing, the resulting diff will cover
		 * those changes as well. */
		changeset_clear(&change);
		ret = changeset_init(&change, zone->name);
		if (ret != KNOT_EOK) {
			return ret;
		}
		ret = zone_contents_create_diff(zone->contents, contents, &change);
		if (ret == KNOT_ENODIFF) {
			log_zone_warning(zone->name, "failed to create journal "
			                 "entry, zone file changed without "
			                 "SOA serial update");
			ret = KNOT_EOK;
		} else if (ret == KNOT_ERANGE) {
			log_zone_warning(zone->name, "IXFR history will be lost, "
			                 "zone file changed, but SOA serial decreased");
			ret = KNOT_EOK;
		} else if (ret != KNOT_EOK) {
			log_zone_error(zone->name, "failed to calculate "
			               "differences from the zone file update (%s)",
			               knot_strerror(ret));
			return ret;
		}
	}

	/* Write changes (DNSSEC, diff, or both) to journal if all went well. */
	if (!changeset_empty(&change)) {
        //printf("********++++++++++=============||||||||------mpainw na grapsw ti zwni\n");
		ret = zone_change_store(zone, &change);
	}

	changeset_clear(&change);
	return ret;
}

bool zone_load_can_bootstrap(const conf_zone_t *zone_config)
{
	return zone_config && !EMPTY_LIST(zone_config->acl.xfr_in);
}

