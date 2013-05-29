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

#include <config.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>

#include "libknot/util/debug.h"
#include "common/errcode.h"
#include "zone-diff.h"
#include "libknot/nameserver/name-server.h"
#include "common/descriptor.h"

struct zone_diff_param {
	const knot_zone_contents_t *contents;
	char nsec3;
	knot_changeset_t *changeset;
	int ret;
};

// forward declaration
static int knot_zone_diff_rdata(const knot_rrset_t *rrset1,
                                const knot_rrset_t *rrset2,
                                knot_changeset_t *changeset);

static int knot_zone_diff_load_soas(const knot_zone_contents_t *zone1,
                                    const knot_zone_contents_t *zone2,
                                    knot_changeset_t *changeset)
{
	if (zone1 == NULL || zone2 == NULL || changeset == NULL) {
		return KNOT_EINVAL;
	}

	const knot_node_t *apex1 = knot_zone_contents_apex(zone1);
	const knot_node_t *apex2 = knot_zone_contents_apex(zone2);
	if (apex1 == NULL || apex2 == NULL) {
		dbg_zonediff("zone_diff: "
		             "both zones must have apex nodes.\n");
		return KNOT_EINVAL;
	}

	knot_rrset_t *soa_rrset1 = knot_node_get_rrset(apex1, KNOT_RRTYPE_SOA);
	knot_rrset_t *soa_rrset2 = knot_node_get_rrset(apex2, KNOT_RRTYPE_SOA);
	if (soa_rrset1 == NULL || soa_rrset2 == NULL) {
		dbg_zonediff("zone_diff: "
		             "both zones must have apex nodes.\n");
		return KNOT_EINVAL;
	}

	if (knot_rrset_rdata_rr_count(soa_rrset1) == 0 ||
	    knot_rrset_rdata_rr_count(soa_rrset2) == 0) {
		dbg_zonediff("zone_diff: "
		             "both zones must have apex nodes with SOA "
		             "RRs.\n");
		return KNOT_EINVAL;
	}

	int64_t soa_serial1 =
		knot_rrset_rdata_soa_serial(soa_rrset1);
	if (soa_serial1 == -1) {
		dbg_zonediff("zone_diff: load_soas: Got bad SOA.\n");
	}

	int64_t soa_serial2 =
		knot_rrset_rdata_soa_serial(soa_rrset2);

	if (soa_serial2 == -1) {
		dbg_zonediff("zone_diff: load_soas: Got bad SOA.\n");
	}

	if (ns_serial_compare(soa_serial1, soa_serial2) == 0) {
		dbg_zonediff("zone_diff: "
		             "second zone must have higher serial than the "
		             "first one. (%"PRId64" vs. %"PRId64")\n",
		             soa_serial1, soa_serial2);
		return KNOT_ENODIFF;
	}

	if (ns_serial_compare(soa_serial1, soa_serial2) > 0) {
		dbg_zonediff("zone_diff: "
		             "second zone must have higher serial than the "
		             "first one. (%"PRId64" vs. %"PRId64")\n",
		             soa_serial1, soa_serial2);
		return KNOT_ERANGE;
	}

	/* We will not touch SOA later, now is the time to handle RRSIGs. */
	int ret = knot_zone_diff_rdata(knot_rrset_rrsigs(soa_rrset1),
	                               knot_rrset_rrsigs(soa_rrset2),
	                               changeset);
	if (ret != KNOT_EOK) {
		dbg_zonediff_verb("zone_diff: load_soas: Failed to diff SOAs' RRSIGs."
		       " Reason: %s.\n", knot_strerror(ret));
		/* This might not necasarilly be an error. */
	}

	assert(changeset);

	ret = knot_rrset_deep_copy(soa_rrset1, &changeset->soa_from, 1);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: load_soas: Cannot copy RRSet.\n");
		return ret;
	}

	/* We MUST NOT save this RRSIG. */
	knot_rrset_deep_free(&changeset->soa_from->rrsigs, 1, 1);
	assert(changeset->soa_from->rrsigs == NULL);

	ret = knot_rrset_deep_copy(soa_rrset2, &changeset->soa_to, 1);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: load_soas: Cannot copy RRSet.\n");
		return ret;
	}

	knot_rrset_deep_free(&changeset->soa_to->rrsigs, 1, 1);
	assert(changeset->soa_to->rrsigs == NULL);

	changeset->serial_from = soa_serial1;
	changeset->serial_to = soa_serial2;

	dbg_zonediff_verb("zone_diff: load_soas: SOAs diffed. (%"PRId64" -> %"PRId64")\n",
	            soa_serial1, soa_serial2);

	return KNOT_EOK;
}

/*!< \todo Only use add or remove function, not both as they are the same. */
/*!< \todo Also, this might be all handled by function in changesets.h!!! */
static int knot_zone_diff_changeset_add_rrset(knot_changeset_t *changeset,
                                              const knot_rrset_t *rrset)
{
	/* Remove all RRs of the RRSet. */
	if (changeset == NULL || rrset == NULL) {
		dbg_zonediff("zone_diff: add_rrset: NULL parameters.\n");
		return KNOT_EINVAL;
	}

	if (knot_rrset_rdata_rr_count(rrset) == 0) {
		dbg_zonediff_detail("zone_diff: Nothing to add.\n");
		return KNOT_EOK;
	}

	dbg_zonediff_detail("zone_diff: add_rrset: Adding RRSet (%d RRs):\n",
	              knot_rrset_rdata_rr_count(rrset));
	knot_rrset_dump(rrset);

	knot_rrset_t *rrset_copy = NULL;
	int ret = knot_rrset_deep_copy(rrset, &rrset_copy, 1);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: add_rrset: Cannot copy RRSet.\n");
		return ret;
	}
	if (rrset_copy->rrsigs != NULL) {
		knot_rrset_deep_free(&rrset_copy->rrsigs, 1, 1);
	}
	assert(knot_rrset_rrsigs(rrset_copy) == NULL);

	ret = knot_changeset_add_new_rr(changeset, rrset_copy,
	                                    KNOT_CHANGESET_ADD);
	if (ret != KNOT_EOK) {
		/* We have to free the copy now! */
		knot_rrset_deep_free(&rrset_copy, 1, 1);
		dbg_zonediff("zone_diff: add_rrset: Could not add RRSet. "
		             "Reason: %s.\n", knot_strerror(ret));
		return ret;
	}

	return KNOT_EOK;
}

static int knot_zone_diff_changeset_remove_rrset(knot_changeset_t *changeset,
                                                 const knot_rrset_t *rrset)
{
	/* Remove all RRs of the RRSet. */
	if (changeset == NULL) {
		dbg_zonediff("zone_diff: remove_rrset: NULL parameters.\n");
		return KNOT_EINVAL;
	}

	if (rrset == NULL) {
		return KNOT_EOK;
	}

	if (knot_rrset_rdata_rr_count(rrset) == 0) {
		/* RDATA are the same, however*/
		dbg_zonediff_detail("zone_diff: Nothing to remove.\n");
		return KNOT_EOK;
	}

	dbg_zonediff_detail("zone_diff: remove_rrset: Removing RRSet (%d RRs):\n",
	              knot_rrset_rdata_rr_count(rrset));
	knot_rrset_dump(rrset);

	knot_rrset_t *rrset_copy = NULL;
	int ret = knot_rrset_deep_copy(rrset, &rrset_copy, 1);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: remove_rrset: Cannot copy RRSet.\n");
		return ret;
	}
	if (rrset_copy->rrsigs != NULL) {
		knot_rrset_deep_free(&rrset_copy->rrsigs, 1, 1);
	}
	assert(knot_rrset_rrsigs(rrset_copy) == NULL);

	ret = knot_changeset_add_new_rr(changeset, rrset_copy,
	                                    KNOT_CHANGESET_REMOVE);
	if (ret != KNOT_EOK) {
		/* We have to free the copy now. */
		knot_rrset_deep_free(&rrset_copy, 1, 1);
		dbg_zonediff("zone_diff: remove_rrset: Could not remove RRSet. "
		             "Reason: %s.\n", knot_strerror(ret));
		return ret;
	}

	return KNOT_EOK;
}

static int knot_zone_diff_add_node(const knot_node_t *node,
                                   knot_changeset_t *changeset)
{
	if (node == NULL || changeset == NULL) {
		dbg_zonediff("zone_diff: add_node: NULL arguments.\n");
		return KNOT_EINVAL;
	}

	/* Add all rrsets from node. */
	const knot_rrset_t **rrsets = knot_node_rrsets(node);
	if (rrsets == NULL) {
		/* Empty non-terminals - legal case. */
		dbg_zonediff_detail("zone_diff: Node has no RRSets.\n");
		return KNOT_EOK;
	}

	for (uint i = 0; i < knot_node_rrset_count(node); i++) {
		assert(rrsets[i]);
		int ret = knot_zone_diff_changeset_add_rrset(changeset,
		                                         rrsets[i]);
		if (ret != KNOT_EOK) {
			dbg_zonediff("zone_diff: add_node: Cannot add RRSet (%s).\n",
			       knot_strerror(ret));
			free(rrsets);
			return ret;
		}

		if (knot_rrset_rrsigs(rrsets[i])) {
			/* Add RRSIGs of the new node. */
			ret = knot_zone_diff_changeset_add_rrset(changeset,
						knot_rrset_rrsigs(rrsets[i]));
			if (ret != KNOT_EOK) {
				dbg_zonediff("zone_diff: add_node: Cannot "
				             "add RRSIG (%s).\n",
				       knot_strerror(ret));
				free(rrsets);
				return ret;
			}
		}
	}

	free(rrsets);

	return KNOT_EOK;
}

static int knot_zone_diff_remove_node(knot_changeset_t *changeset,
                                                const knot_node_t *node)
{
	if (changeset == NULL || node == NULL) {
		dbg_zonediff("zone_diff: remove_node: NULL parameters.\n");
		return KNOT_EINVAL;
	}

	dbg_zonediff("zone_diff: remove_node: Removing node:\n");
dbg_zonediff_exec_detail(
	knot_node_dump((knot_node_t *)node);
);

	const knot_rrset_t **rrsets = knot_node_rrsets(node);
	if (rrsets == NULL) {
		dbg_zonediff_verb("zone_diff: remove_node: "
		                  "Nothing to remove.\n");
		return KNOT_EOK;
	}

	dbg_zonediff_detail("zone_diff: remove_node: Will be removing %d RRSets.\n",
	              knot_node_rrset_count(node));

	/* Remove all the RRSets of the node. */
	for (uint i = 0; i < knot_node_rrset_count(node); i++) {
		int ret = knot_zone_diff_changeset_remove_rrset(changeset,
		                                            rrsets[i]);
		if (ret != KNOT_EOK) {
			dbg_zonediff("zone_diff: remove_node: Failed to "
			             "remove rrset. Error: %s\n",
			             knot_strerror(ret));
			free(rrsets);
			return ret;
		}
		if (knot_rrset_rrsigs(rrsets[i])) {
			/* Remove RRSIGs of the old node. */
			ret = knot_zone_diff_changeset_remove_rrset(changeset,
						knot_rrset_rrsigs(rrsets[i]));
			if (ret != KNOT_EOK) {
				dbg_zonediff("zone_diff: remove_node: Cannot "
				             "remove RRSIG (%s).\n",
				       knot_strerror(ret));
				free(rrsets);
				return ret;
			}
		}
	}

	free(rrsets);

	return KNOT_EOK;
}

static int knot_zone_diff_rdata_return_changes(const knot_rrset_t *rrset1,
                                               const knot_rrset_t *rrset2,
                                               knot_rrset_t **changes)
{
	if (rrset1 == NULL || rrset2 == NULL) {
		dbg_zonediff("zone_diff: diff_rdata: NULL arguments. (%p) (%p).\n",
		       rrset1, rrset2);
		return KNOT_EINVAL;
	}

	/*
	* Take one rdata from first list and search through the second list
	* looking for an exact match. If no match occurs, it means that this
	* particular RR has changed.
	* After the list has been traversed, we have a list of
	* changed/removed rdatas. This has awful computation time.
	*/
	dbg_zonediff_detail("zone_diff: diff_rdata: Diff of %s, type=%u. "
	              "RR count 1=%d RR count 2=%d.\n",
	              knot_dname_to_str(rrset1->owner), rrset1->type,
	              knot_rrset_rdata_rr_count(rrset1),
	              knot_rrset_rdata_rr_count(rrset2));

	/* Create fake RRSet, it will be easier to handle. */
	*changes = knot_rrset_new(knot_rrset_get_owner(rrset1),
	                          knot_rrset_type(rrset1),
	                          knot_rrset_class(rrset1),
	                          knot_rrset_ttl(rrset1));
	if (*changes == NULL) {
		dbg_zonediff("zone_diff: diff_rdata: "
		             "Could not create RRSet with changes.\n");
		return KNOT_ENOMEM;
	}

	const rdata_descriptor_t *desc =
		get_rdata_descriptor(knot_rrset_type(rrset1));
	assert(desc);

	for (uint16_t i = 0; i < knot_rrset_rdata_rr_count(rrset1); ++i) {
		size_t rr_pos = 0;
		int ret = knot_rrset_find_rr_pos(rrset2, rrset1, i, &rr_pos);
		if (ret == KNOT_ENOENT) {
			/* No such RR is present in 'rrset2'. */
			dbg_zonediff("zone_diff: diff_rdata: "
			       "No match for RR (type=%u owner=%s).\n",
			       knot_rrset_type(rrset1),
			       knot_dname_to_str(rrset1->owner));
			/* We'll copy index 'i' into 'changes' RRSet. */
			ret = knot_rrset_add_rr_from_rrset(*changes, rrset1, i);
			if (ret != KNOT_EOK) {
				dbg_zonediff("zone_diff: diff_rdata: Could not"
				             " add RR to RRSet (%s).\n",
				             knot_strerror(ret));
				knot_rrset_free(changes);
				return ret;
			}
		} else if (ret == KNOT_EOK) {
			/* RR in both RRSets. no-op*/
			dbg_zonediff_detail("zone_diff: diff_rdata: "
			              "Found matching RR for type %d.\n",
			              rrset1->type);
		} else {
			dbg_zonediff("zone_diff: diff_rdata: Could not search "
			             "for RR (%s).\n", knot_strerror(ret));
			knot_rrset_free(changes);
			return ret;
		}
	}

	return KNOT_EOK;
}

static int knot_zone_diff_rdata(const knot_rrset_t *rrset1,
                                const knot_rrset_t *rrset2,
                                knot_changeset_t *changeset)
{
	if ((changeset == NULL) || (rrset1 == NULL && rrset2 == NULL)) {
		dbg_zonediff("zone_diff: diff_rdata: NULL arguments.\n");
		return KNOT_EINVAL;
	}
	/*
	 * The easiest solution is to remove all the RRs that had no match and
	 * to add all RRs that had no match, but those from second RRSet. */

	/* Get RRs to remove from zone. */
	knot_rrset_t *to_remove = NULL;
	if (rrset1 != NULL && rrset2 == NULL) {
		assert(rrset1->type == KNOT_RRTYPE_RRSIG);
		dbg_zonediff_detail("zone_diff: diff_rdata: RRSIG will be "
		              "removed.\n");
		int ret = knot_rrset_deep_copy(rrset1, &to_remove, 1);
		if (ret != KNOT_EOK) {
			dbg_zonediff("zone_diff: diff_rdata: Could not copy rrset. "
			             "Error: %s.\n", knot_strerror(ret));
			return ret;
		}
	} else if (rrset1 != NULL && rrset2 != NULL) {
		int ret = knot_zone_diff_rdata_return_changes(rrset1, rrset2,
		                                              &to_remove);
		if (ret != KNOT_EOK) {
			dbg_zonediff("zone_diff: diff_rdata: Could not get changes. "
			             "Error: %s.\n", knot_strerror(ret));
			return ret;
		}
	} else {
		dbg_zonediff("zone_diff: diff_rdata: These are not the diffs you "
		       "are looking for.\n");
	}

	dbg_zonediff_detail("zone_diff: diff_rdata: To remove:\n");
	knot_rrset_dump(to_remove);

	/*
	 * to_remove RRSet might be empty, meaning that
	 * there are no differences in RDATA, but TTLs can differ.
	 */
	if (rrset1 && rrset2 &&
	    (knot_rrset_ttl(rrset1) != knot_rrset_ttl(rrset2)) &&
	    knot_rrset_rdata_rr_count(to_remove) == 0) {
		dbg_zonediff_detail("zone_diff: diff_rdata: Remove RR: Old TTL=%"PRIu32", New=%"PRIu32"\n",
		                    rrset1->ttl, rrset2->ttl);
		/* We have to remove old TTL. */
		assert(knot_rrset_ttl(to_remove) == knot_rrset_ttl(rrset1));
		/*
		 * Fill the RDATA so that the change gets saved. All RRs can
		 * be copied because TTLs are the same for all of them.
		 */
		knot_rrset_free(&to_remove);
		int ret = knot_rrset_deep_copy(rrset1, &to_remove, 1);
		if (ret != KNOT_EOK) {
			dbg_zonediff("zone_diff: diff_rdata: Cannot copy RRSet "
			             "(%s).\n", knot_strerror(ret));
			return ret;
		}
	}

	int ret = knot_zone_diff_changeset_remove_rrset(changeset,
	                                            to_remove);
	if (ret != KNOT_EOK) {
		knot_rrset_deep_free(&to_remove, 1, 1);
		dbg_zonediff("zone_diff: diff_rdata: Could not remove RRs. "
		             "Error: %s.\n", knot_strerror(ret));
		return ret;
	}

	/* Copy was made in add_rrset function, we can free now. */
	knot_rrset_deep_free(&to_remove, 1, 1);

	/* Get RRs to add to zone. */ // TODO move to extra function, same for remove
	knot_rrset_t *to_add = NULL;
	if (rrset2 != NULL && rrset1 == NULL) {
		assert(rrset2->type == KNOT_RRTYPE_RRSIG);
		dbg_zonediff_detail("zone_diff: diff_rdata: RRSIG will be "
		              "added.\n");
		int ret = knot_rrset_deep_copy(rrset2, &to_add, 1);
		if (ret != KNOT_EOK) {
			dbg_zonediff("zone_diff: diff_rdata: Could not copy rrset. "
			             "Error: %s.\n", knot_strerror(ret));
			return ret;
		}
	} else if (rrset1 != NULL && rrset2 != NULL) {
		ret = knot_zone_diff_rdata_return_changes(rrset2, rrset1,
		                                          &to_add);
		if (ret != KNOT_EOK) {
			dbg_zonediff("zone_diff: diff_rdata: Could not get changes. "
			             "Error: %s.\n", knot_strerror(ret));
			return ret;
		}
	} else {
		dbg_zonediff("zone_diff: diff_rdata: These are not the diffs you "
		       "are looking for.\n");
	}

	dbg_zonediff_detail("zone_diff: diff_rdata: To add:\n");
	knot_rrset_dump(to_add);

	/*
	 * to_remove RRSet might be empty, meaning that
	 * there are no differences in RDATA, but TTLs can differ.
	 */
	if (rrset1 && rrset2 &&
	    knot_rrset_ttl(rrset1) != knot_rrset_ttl(rrset2)) {
		/* We have to add newer TTL. */
		dbg_zonediff_detail("zone_diff: diff_rdata: Add RR: Old TTL=%"PRIu32", New=%"PRIu32"\n",
		                    rrset1->ttl, rrset2->ttl);
		if (knot_rrset_rdata_rr_count(to_add) == 0) {
			/*
			 * Fill the RDATA so that the change gets saved. All RRs can
			 * be copied because TTLs are the same for all of them.
			 */
			knot_rrset_free(&to_add);
			int ret = knot_rrset_deep_copy(rrset1, &to_add, 1);
			if (ret != KNOT_EOK) {
				dbg_zonediff("zone_diff: diff_rdata: Cannot copy RRSet "
				             "(%s).\n", knot_strerror(ret));
				return ret;
			}
		}
		knot_rrset_set_ttl(to_add, knot_rrset_ttl(rrset2));
	}

	ret = knot_zone_diff_changeset_add_rrset(changeset,
	                                         to_add);
	if (ret != KNOT_EOK) {
		knot_rrset_deep_free(&to_add, 1, 1);
		dbg_zonediff("zone_diff: diff_rdata: Could not remove RRs. "
		             "Error: %s.\n", knot_strerror(ret));
		return ret;
	}

	/* Copy was made in add_rrset function, we can free now. */
	knot_rrset_deep_free(&to_add, 1, 1);

	return KNOT_EOK;
}

static int knot_zone_diff_rrsets(const knot_rrset_t *rrset1,
                                 const knot_rrset_t *rrset2,
                                 knot_changeset_t *changeset)
{
//	if (rrset1 == NULL || rrset2 == NULL) {
//		/* This could happen when diffing RRSIGs. */
//		if (rrset1 == NULL && rrset2 != NULL) {
//			dbg_zonediff("zone_diff: diff_rrsets: RRSIG missing in first"
//			       " rrset1.\n");
//			int ret =
//				knot_zone_diff_changeset_add_rrset(changeset,
//			                                           rrset2);
//			if (ret != KNOT_EOK) {
//				dbg_zonediff("zone_diff: diff_rrsets: "
//				       "Cannot add RRSIG. (%s)\n",
//				       knot_strerror(ret));
//			}
//		} else if (rrset1 != NULL && rrset2 == NULL) {
//			dbg_zonediff("zone_diff: diff_rrsets: RRSIG missing in second"
//			       " rrset1.\n");
//			int ret =
//				knot_zone_diff_changeset_remove_rrset(changeset,
//			                                              rrset1);
//			if (ret != KNOT_EOK) {
//				dbg_zonediff("zone_diff: diff_rrsets: "
//				       "Cannot remove RRSIG. (%s)\n",
//				       knot_strerror(ret));
//			}
//		}
//		dbg_zonediff_detail("zone_diff: diff_rrsets: "
//		              "NULL arguments (RRSIGs?). (%p) (%p)\n",
//		              rrset1, rrset2);
//		return KNOT_EOK;
//	}

	assert(knot_dname_compare(knot_rrset_owner(rrset1),
	                          knot_rrset_owner(rrset2)) == 0);
	assert(knot_rrset_type(rrset1) == knot_rrset_type(rrset2));

	int ret = knot_zone_diff_rdata(knot_rrset_rrsigs(rrset1),
	                               knot_rrset_rrsigs(rrset2), changeset);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: diff_rrsets (%s:%u): Failed to diff RRSIGs. "
		       "They were: %p %p. (%s).\n",
		       knot_dname_to_str(rrset1->owner),
		       rrset1->type,
		       rrset1->rrsigs,
		       rrset2->rrsigs, knot_strerror(ret));
	}

	/* RRs (=rdata) have to be cross-compared, unfortunalely. */
	return knot_zone_diff_rdata(rrset1, rrset2, changeset);
}

/*!< \todo this could be generic function for adding / removing. */
static void knot_zone_diff_node(knot_node_t *node, void *data)
{
	if (node == NULL || data == NULL) {
		dbg_zonediff("zone_diff: diff_node: NULL arguments.\n");
		return;
	}

	struct zone_diff_param *param = (struct zone_diff_param *)data;
	if (param->changeset == NULL || param->contents == NULL) {
		dbg_zonediff("zone_diff: diff_node: NULL arguments.\n");
		param->ret = KNOT_EINVAL;
		return;
	}

	if (param->ret != KNOT_EOK) {
		/* Error occured before, no point in continuing. */
		dbg_zonediff_detail("zone_diff: diff_node: error: %s\n",
		                    knot_strerror(param->ret));
		return;
	}

	/*
	 * First, we have to search the second tree to see if there's according
	 * node, if not, the whole node has been removed.
	 */
	const knot_node_t *node_in_second_tree = NULL;
	const knot_dname_t *node_owner = knot_node_owner(node);
	assert(node_owner);
	if (!param->nsec3) {
		node_in_second_tree =
			knot_zone_contents_find_node(param->contents,
			                             node_owner);
	} else {
		dbg_zonediff_verb("zone_diff: diff_node: NSEC3 zone.\n");
		node_in_second_tree =
			knot_zone_contents_find_nsec3_node(param->contents,
			                                   node_owner);
	}

	if (node_in_second_tree == NULL) {
		dbg_zonediff_detail("zone_diff: diff_node: Node %s is not "
		              "in the second tree.\n",
		              knot_dname_to_str(node_owner));
		int ret = knot_zone_diff_remove_node(param->changeset,
		                                               node);
		if (ret != KNOT_EOK) {
			dbg_zonediff("zone_diff: failed to remove node.\n");
			param->ret = ret;
			return;
		}
		param->ret = KNOT_EOK;
		return;
	}

	assert(node_in_second_tree != node);

	dbg_zonediff_detail("zone_diff: diff_node: Node %s is present in "
	              "both trees.\n", knot_dname_to_str(node_owner));
	/* The nodes are in both trees, we have to diff each RRSet. */
	const knot_rrset_t **rrsets = knot_node_rrsets(node);
	if (rrsets == NULL) {
		dbg_zonediff("zone_diff: Node in first tree has no RRSets.\n");
		/*
		 * If there are no RRs in the first tree, all of the RRs
		 * in the second tree will have to be inserted to ADD section.
		 */
		int ret = knot_zone_diff_add_node(node_in_second_tree,
		                                  param->changeset);
		if (ret != KNOT_EOK) {
			dbg_zonediff("zone_diff: diff_node: "
			             "Could not add node from second tree. "
			             "Reason: %s.\n", knot_strerror(ret));
		}
		param->ret = ret;
		return;
	}

	for (uint i = 0; i < knot_node_rrset_count(node); i++) {
		/* Search for the RRSet in the node from the second tree. */
		const knot_rrset_t *rrset = rrsets[i];
		assert(rrset);

		/* SOAs are handled explicitly. */
		if (knot_rrset_type(rrset) == KNOT_RRTYPE_SOA) {
			continue;
		}

		const knot_rrset_t *rrset_from_second_node =
			knot_node_rrset(node_in_second_tree,
			                knot_rrset_type(rrset));
		if (rrset_from_second_node == NULL) {
			dbg_zonediff("zone_diff: diff_node: There is no counterpart "
			       "for RRSet of type %u in second tree.\n",
			       knot_rrset_type(rrset));
			/* RRSet has been removed. Make a copy and remove. */
			assert(rrset);
			int ret = knot_zone_diff_changeset_remove_rrset(
				param->changeset,
				rrset);
			if (ret != KNOT_EOK) {
				dbg_zonediff("zone_diff: diff_node: "
				             "Failed to remove RRSet.\n");
				param->ret = ret;
				free(rrsets);
				return;
			}

			/* Remove RRSet's RRSIGs as well. */
			if (knot_rrset_rrsigs(rrset)) {
				ret = knot_zone_diff_changeset_remove_rrset(
				            param->changeset,
				            knot_rrset_rrsigs(rrset));
				if (ret != KNOT_EOK) {
				    dbg_zonediff("zone_diff: diff_node+: "
				                 "Failed to remove RRSIGs.\n");
				    param->ret = ret;
				    free(rrsets);
				    return;
				}
			}
		} else {
			dbg_zonediff("zone_diff: diff_node: There is a counterpart "
			       "for RRSet of type %u in second tree.\n",
			       knot_rrset_type(rrset));
			/* Diff RRSets. */
			int ret = knot_zone_diff_rrsets(rrset,
			                                rrset_from_second_node,
			                                param->changeset);
			if (ret != KNOT_EOK) {
				dbg_zonediff("zone_diff: "
				             "Failed to diff RRSets.\n");
				param->ret = ret;
				free(rrsets);
				return;
			}

//			dbg_zonediff_verb("zone_diff: diff_node: Changes in "
//			            "RRSIGs.\n");
//			/*! \todo There is ad-hoc solution in the function, maybe handle here. */
//			ret = knot_zone_diff_rrsets(rrset->rrsigs,
//			                                rrset_from_second_node->rrsigs,
//			                                param->changeset);
//			if (ret != KNOT_EOK) {
//				dbg_zonediff("zone_diff: "
//				             "Failed to diff RRSIGs.\n");
//				param->ret = ret;
//				return;
//			}
		}
	}

	free(rrsets);

	/*! \todo move to one function with the code above. */
	rrsets = knot_node_rrsets(node_in_second_tree);
	if (rrsets == NULL) {
		dbg_zonediff("zone_diff: Node in second tree has no RRSets.\n");
		/*
		 * This can happen when node in second
		 * tree is empty non-terminal and as such has no RRs.
		 * Whole node from the first tree has to be removed.
		 */
		// TODO following code creates duplicated RR in diff.
		// IHMO such case should be handled here
//		int ret = knot_zone_diff_remove_node(param->changeset,
//		                                     node);
//		if (ret != KNOT_EOK) {
//			dbg_zonediff("zone_diff: diff_node: "
//			             "Cannot remove node. Reason: %s.\n",
//			             knot_strerror(ret));
//		}
		param->ret = KNOT_EOK;
		return;
	}

	for (uint i = 0; i < knot_node_rrset_count(node_in_second_tree); i++) {
		/* Search for the RRSet in the node from the second tree. */
		const knot_rrset_t *rrset = rrsets[i];
		assert(rrset);

		/* SOAs are handled explicitly. */
		if (knot_rrset_type(rrset) == KNOT_RRTYPE_SOA) {
			continue;
		}

		const knot_rrset_t *rrset_from_first_node =
			knot_node_rrset(node,
			                knot_rrset_type(rrset));
		if (rrset_from_first_node == NULL) {
			dbg_zonediff("zone_diff: diff_node: There is no counterpart "
			       "for RRSet of type %u in first tree.\n",
			       knot_rrset_type(rrset));
			/* RRSet has been added. Make a copy and add. */
			assert(rrset);
			int ret = knot_zone_diff_changeset_add_rrset(
				param->changeset,
				rrset);
			if (ret != KNOT_EOK) {
				dbg_zonediff("zone_diff: diff_node: "
				             "Failed to add RRSet.\n");
				param->ret = ret;
				free(rrsets);
				return;
			}
			if (knot_rrset_rrsigs(rrset)) {
				int ret = knot_zone_diff_changeset_add_rrset(
			        param->changeset,
			         knot_rrset_rrsigs(rrset));
			   if (ret != KNOT_EOK) {
			     dbg_zonediff("zone_diff: diff_node: "
			            "Failed to add RRSIGs.\n");
			    param->ret = ret;
					free(rrsets);
				return;
			 }
			}
		} else {
			/* Already handled. */
			;
		}
	}

	free(rrsets);

	assert(param->ret == KNOT_EOK);
}

/*!< \todo possibly not needed! */
static void knot_zone_diff_add_new_nodes(knot_node_t *node, void *data)
{
	assert(node);
	if (node == NULL || data == NULL) {
		dbg_zonediff("zone_diff: add_new_nodes: NULL arguments.\n");
		return;
	}

	struct zone_diff_param *param = (struct zone_diff_param *)data;
	if (param->changeset == NULL || param->contents == NULL) {
		dbg_zonediff("zone_diff: add_new_nodes: NULL arguments.\n");
		param->ret = KNOT_EINVAL;
		return;
	}

	if (param->ret != KNOT_EOK) {
		/* Error occured before, no point in continuing. */
		dbg_zonediff_detail("zone_diff: add_new_nodes: error: %s\n",
		                    knot_strerror(param->ret));
		return;
	}

	/*
	* If a node is not present in the second zone, it is a new node
	* and has to be added to changeset. Differencies on the RRSet level are
	* already handled.
	*/
	const knot_zone_contents_t *other_zone = param->contents;
	assert(other_zone);

	const knot_dname_t *node_owner = knot_node_owner(node);
	/*
	 * Node should definitely have an owner, otherwise it would not be in
	 * the tree.
	 */
	assert(node_owner);

	knot_node_t *new_node = NULL;
	if (!param->nsec3) {
		new_node = knot_zone_contents_get_node(other_zone, node_owner);
	} else {
		new_node = knot_zone_contents_get_nsec3_node(other_zone,
		                                             node_owner);
	}

	if (!new_node) {
		assert(node);
		int ret = knot_zone_diff_add_node(node, param->changeset);
		if (ret != KNOT_EOK) {
			dbg_zonediff("zone_diff: add_new_nodes: Cannot add "
			             "node: %s to changeset. Reason: %s.\n",
			             knot_dname_to_str(node->owner),
			             knot_strerror(ret));
		}
	}

	assert(param->ret == KNOT_EOK);
}

int knot_zone_contents_diff(const knot_zone_contents_t *zone1,
                            const knot_zone_contents_t *zone2,
                            knot_changeset_t *changeset)
{
	if (zone1 == NULL || zone2 == NULL) {
		dbg_zonediff("zone_diff: NULL argument(s).\n");
		return KNOT_EINVAL;
	}

//	/* Create changeset structure. */
//	*changeset = malloc(sizeof(knot_changeset_t));
//	if (*changeset == NULL) {
//		ERR_ALLOC_FAILED;
//		return KNOT_ENOMEM;
//	}
	memset(changeset, 0, sizeof(knot_changeset_t));

	/* Settle SOAs first. */
	int ret = knot_zone_diff_load_soas(zone1, zone2, changeset);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: loas_SOAs failed with error: %s\n",
		             knot_strerror(ret));
		return ret;
	}

	dbg_zonediff("zone_diff: SOAs loaded.\n");

	/* Traverse one tree, compare every node, each RRSet with its rdata. */
	struct zone_diff_param param;
	param.contents = zone2;
	param.nsec3 = 0;
	param.changeset = changeset;
	param.ret = KNOT_EOK;
	ret = knot_zone_contents_tree_apply_inorder(
	                        (knot_zone_contents_t *)zone1,
	                        knot_zone_diff_node,
	                        &param);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: Tree traversal failed "
		             "with error: %s. Error from inner function: %s\n",
		             knot_strerror(ret),
		             knot_strerror(param.ret));
		return ret;
	}

	/* Do the same for NSEC3 nodes. */
	param.nsec3 = 1;
	ret = knot_zone_contents_nsec3_apply_inorder((knot_zone_contents_t *)zone1, knot_zone_diff_node,
	                                             &param);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: Tree traversal failed "
		             "with error: %s\n",
		             knot_strerror(ret));
		return ret;
	}

	/*
	 * Some nodes may have been added. The code above will not notice,
	 * we have to go through the second tree and add missing nodes to
	 * changeset.
	 */
	param.nsec3 = 0;
	param.contents = zone1;
	ret = knot_zone_contents_tree_apply_inorder((knot_zone_contents_t *)zone2,
		knot_zone_diff_add_new_nodes,
		&param);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: Tree traversal failed "
		             "with error: %s. Error from inner function: %s\n",
		             knot_strerror(ret),
		             knot_strerror(param.ret));
		return ret;
	}

	/* NSEC3 nodes. */
	param.nsec3 = 1;
	param.contents = zone1;
	ret = knot_zone_contents_nsec3_apply_inorder((knot_zone_contents_t *)zone2,
		knot_zone_diff_add_new_nodes,
		&param);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: Tree traversal failed "
		             "with error: %s\n",
		             knot_strerror(ret));
		return ret;
	}

	return KNOT_EOK;
}

#ifdef KNOT_ZONEDIFF_DEBUG
#ifdef DEBUG_ENABLE_DETAILS
static void knot_zone_diff_dump_changeset(knot_changeset_t *ch)
{
	dbg_zonediff_detail("Changeset FROM: %d\n", ch->serial_from);
	knot_rrset_dump(ch->soa_from);
	dbg_zonediff_detail("\n");
	dbg_zonediff_detail("Changeset TO: %d\n", ch->serial_to);
	knot_rrset_dump(ch->soa_to);
	dbg_zonediff_detail("\n");
	dbg_zonediff_detail("Adding %zu RRs.\n", ch->add_count);
	dbg_zonediff_detail("Removing %zu RRs.\n", ch->remove_count);

	dbg_zonediff_detail("ADD section:\n");
	dbg_zonediff_detail("**********************************************\n");
	for (int i = 0; i < ch->add_count; i++) {
		knot_rrset_dump(ch->add[i]);
		dbg_zonediff_detail("\n");
	}
	dbg_zonediff_detail("REMOVE section:\n");
	dbg_zonediff_detail("**********************************************\n");
	for (int i = 0; i < ch->remove_count; i++) {
		knot_rrset_dump(ch->remove[i]);
		dbg_zonediff_detail("\n");
	}
}
#endif
#endif

int knot_zone_diff_create_changesets(const knot_zone_contents_t *z1,
                                     const knot_zone_contents_t *z2,
                                     knot_changesets_t **changesets)
{
	if (z1 == NULL || z2 == NULL) {
		dbg_zonediff("zone_diff: create_changesets: NULL arguments.\n");
		return KNOT_EINVAL;
	}
	/* Create changesets. */
	/* Setting type to IXFR - that's the default, DDNS triggers special
	 * processing when applied. See #2110 and #2111.
	 */
	int ret = knot_changeset_allocate(changesets, KNOT_CHANGESET_TYPE_IXFR);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: create_changesets: "
		             "Could not allocate changesets."
		             "Reason: %s.\n", knot_strerror(ret));
		return ret;
	}

	memset((*changesets)->sets, 0, sizeof(knot_changeset_t));

	ret = knot_zone_contents_diff(z1, z2, (*changesets)->sets);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: create_changesets: "
		             "Could not diff zones. "
		             "Reason: %s.\n", knot_strerror(ret));
		return ret;
	}

	(*changesets)->count = 1;

	dbg_zonediff("Changesets created successfully!\n");
	dbg_zonediff_detail("Changeset dump:\n");
dbg_zonediff_exec_detail(
	knot_zone_diff_dump_changeset((*changesets)->sets);
);

	return KNOT_EOK;
}
