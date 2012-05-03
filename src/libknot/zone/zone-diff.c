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

#include <assert.h>

#include "libknot/util/error.h"
#include "libknot/util/debug.h"
#include "libknot/rdata.h"
#include "zone-diff.h"

/*! \todo XXX TODO FIXME remove once testing is done. */
#include "zcompile/zcompile.h"
#include "knot/zone/zone-load.h"

struct zone_diff_param {
	knot_zone_contents_t *contents;
	char nsec3;
	knot_changeset_t *changeset;
	int ret;
};

#define printf_detail printf
#define printf_verb printf

static int knot_zone_diff_load_soas(const knot_zone_contents_t *zone1,
                                    const knot_zone_contents_t *zone2,
                                    knot_changeset_t *changeset)
{
	if (zone1 == NULL || zone2 == NULL || changeset == NULL) {
		return KNOT_EBADARG;
	}

	const knot_node_t *apex1 = knot_zone_contents_apex(zone1);
	const knot_node_t *apex2 = knot_zone_contents_apex(zone2);
	if (apex1 == NULL || apex2 == NULL) {
		printf("zone_diff: "
		             "both zones must have apex nodes.\n");
		return KNOT_EBADARG;
	}

	knot_rrset_t *soa_rrset1 = knot_node_get_rrset(apex1, KNOT_RRTYPE_SOA);
	knot_rrset_t *soa_rrset2 = knot_node_get_rrset(apex2, KNOT_RRTYPE_SOA);
	if (soa_rrset1 == NULL || soa_rrset2 == NULL) {
		printf("zone_diff: "
		             "both zones must have apex nodes.\n");
		return KNOT_EBADARG;
	}

	if (knot_rrset_rdata(soa_rrset1) == NULL ||
	    knot_rrset_rdata(soa_rrset2) == NULL) {
		printf("zone_diff: "
		             "both zones must have apex nodes with SOA "
		             "RRs.\n");
		return KNOT_EBADARG;
	}

	int64_t soa_serial1 =
		knot_rdata_soa_serial(knot_rrset_rdata(soa_rrset1));
	if (soa_serial1 == -1) {
		printf("zone_diff: load_soas: Got bad SOA.\n");
	}

	int64_t soa_serial2 =
		knot_rdata_soa_serial(knot_rrset_rdata(soa_rrset2));
	
	if (soa_serial2 == -1) {
		printf("zone_diff: load_soas: Got bad SOA.\n");
	}	

	if (soa_serial1 >= soa_serial2) {
		printf("zone_diff: "
		             "second zone must have higher serial than the "
		             "first one.\n");
		return KNOT_EBADARG;
	}

	assert(changeset);

	changeset->soa_from = soa_rrset1;
	changeset->soa_to = soa_rrset2;

	return KNOT_EOK;
}

//static int knot_zone_diff_changeset_add_rr(knot_changeset_t *changeset,
//                                           const knot_rrset_t *rrset,
//                                           knot_rdata_t *rr)
//{
//	if (changeset == NULL || rrset == NULL || rr == NULL) {
//		printf("zone_diff: add_rr: NULL arguments.\n");
//		return KNOT_EBADARG;
//	}
	
//	/* Following code will actually insert RRs to changeset. */
	
//	/* First, check whether RRSet is not already in the array. */
//	knot_rrset_t *found_rrset = NULL;
//	for(uint i = 0; i < changeset->remove_count; i++) {
//		if (knot_rrset_compare(rrset, changeset->remove[i],
//		                       KNOT_RRSET_COMPARE_HEADER) == 0) {
//			assert(changeset->remove[i]);
//			found_rrset = changeset->remove[i];
//		}
//	}
	
//	if (found_rrset) {
//		int ret = knot_rrset_add_rdata(found_rrset, rr);
//		if (ret != KNOT_EOK) {
//			printf("zone_diff: add_rr: "
//			             "Could not add rdata. Reason: %s.\n",
//			             knot_strerror(ret));
//			return ret;
//		}
//	} else {
//		/*
//		 * Add this RRSet to the end of the
//		 * list, then add this particular RR.
//		 */
		
//		knot_rrset_t *tmp_rrset =
//			knot_rrset_new(knot_rrset_get_owner(rrset),
//		                       knot_rrset_type(rrset),
//		                       knot_rrset_class(rrset),
//		                       knot_rrset_ttl(rrset));
//		if (tmp_rrset == NULL) {
//			printf("zone_diff: add_rr: "
//			             "Could not create tmp rrset.\n");
//			return KNOT_ERROR;
//		}
		
//		int ret = knot_rrset_add_rdata(tmp_rrset, rr);
//		if (ret != KNOT_EOK) {
//			printf("zone_diff: add_rr: "
//			             "Could not add rdata to tmp rrset/\n");
//			return ret;
//		}
		
//		ret = knot_changeset_add_new_rr(changeset, tmp_rrset,
//		                                XFRIN_CHANGESET_ADD);
//		if (ret != KNOT_EOK) {
//			printf("zone_diff: add_rr: "
//			             "Could not add RRSet to list of RRSets to"
//			             "be removed.\n");
//			return ret;
//		}
//	}
	
//	return KNOT_EOK;
//}

//static int knot_zone_diff_changeset_remove_rr(knot_changeset_t *changeset,
//                                              const knot_rrset_t *rrset,
//                                              knot_rdata_t *rr)
//{
//	if (changeset == NULL || rrset == NULL || rr == NULL) {
//		printf("zone_diff: remove_rr: NULL arguments.\n");
//		return KNOT_EBADARG;
//	}
	
//	/* Following code will actually insert RRs to changeset. */
	
//	/* First, check whether RRSet is not already in the array. */
//	knot_rrset_t *found_rrset = NULL;
//	for(uint i = 0; i < changeset->remove_count; i++) {
//		if (knot_rrset_compare(rrset, changeset->remove[i],
//		                       KNOT_RRSET_COMPARE_HEADER) == 0) {
//			assert(changeset->remove[i]);
//			found_rrset = changeset->remove[i];
//		}
//	}
	
//	if (found_rrset) {
//		int ret = knot_rrset_add_rdata(found_rrset, rr);
//		if (ret != KNOT_EOK) {
//			printf("zone_diff: remove_rr: "
//			             "Could not add rdata. Reason: %s.\n",
//			             knot_strerror(ret));
//			return ret;
//		}
//	} else {
//		/*
//		 * Add this RRSet to the end of the
//		 * list, then add this particular RR.
//		 */
		
//		knot_rrset_t *tmp_rrset =
//			knot_rrset_new(knot_rrset_get_owner(rrset),
//		                       knot_rrset_type(rrset),
//		                       knot_rrset_class(rrset),
//		                       knot_rrset_ttl(rrset));
//		if (tmp_rrset == NULL) {
//			printf("zone_diff: remove_rr: "
//			             "Could not create tmp rrset.\n");
//			return KNOT_ERROR;
//		}
		
//		int ret = knot_rrset_add_rdata(tmp_rrset, rr);
//		if (ret != KNOT_EOK) {
//			printf("zone_diff: remove_rr: "
//			             "Could not add rdata to tmp rrset/\n");
//			return ret;
//		}
		
//		ret = knot_changeset_add_new_rr(changeset, tmp_rrset,
//		                                XFRIN_CHANGESET_REMOVE);
//		if (ret != KNOT_EOK) {
//			printf("zone_diff: remove_rr: "
//			             "Could not add RRSet to list of RRSets to "
//			             "be removed.\n");
//			return ret;
//		}
//	}
	
//	return KNOT_EOK;
//}

/*!< \todo Only use add or remove function, not both as they are the same. */
/*!< \todo Also, this might be all handled by function in changesets.h!!! */
static int knot_zone_diff_changeset_add_rrset(knot_changeset_t *changeset,
                                              knot_rrset_t *rrset)
{
	/* Remove all RRs of the RRSet. */
	if (changeset == NULL || rrset == NULL) {
		printf("zone_diff: add_rrset: NULL parameters.\n");
		return KNOT_EBADARG;
	}
	
	if (knot_rrset_rdata_rr_count(rrset) == 0) {
		printf_detail("zone_diff: Nothing to add.\n");
		return KNOT_EOK;
	}
	
	printf_detail("zone_diff: add_rrset: Adding RRSet (%d RRs):\n",
	              knot_rrset_rdata_rr_count(rrset));
	knot_rrset_dump(rrset, 1);
	
	int ret = knot_changeset_add_new_rr(changeset, rrset,
	                                    XFRIN_CHANGESET_ADD);
	if (ret != KNOT_EOK) {
		printf("zone_diff: add_rrset: Could not add RRSet. "
		             "Reason: %s.\n", knot_strerror(ret));
		return ret;
	}

//	const knot_rdata_t *tmp_rdata = NULL;
//	while ((tmp_rdata = knot_rrset_rdata_next(rrset, tmp_rdata)) != NULL) {
//		int ret = knot_zone_diff_changeset_add_rr(changeset,
//		                                          rrset,
//		                                          tmp_rdata);
//		if (ret != KNOT_EOK) {
//			printf("zone_diff: add_rrset: Cannot add "
//			             "RR\n");
//			return ret;
//		}
//	}
	
//	printf_detail("zone_diff: add_rrset: "
//	                    "RRSet succesfully added.\n");
	
	return KNOT_EOK;
}

static int knot_zone_diff_changeset_remove_rrset(knot_changeset_t *changeset,
                                                 knot_rrset_t *rrset)
{
	/* Remove all RRs of the RRSet. */
	if (changeset == NULL || rrset == NULL) {
		printf("zone_diff: remove_rrset: NULL parameters.\n");
		return KNOT_EBADARG;
	}
	
	if (knot_rrset_rdata_rr_count(rrset) == 0) {
		printf_detail("zone_diff: Nothing to remove.\n");
		return KNOT_EOK;
	}
	
	printf_detail("zone_diff: remove_rrset: Removing RRSet (%d RRs):\n",
	              knot_rrset_rdata_rr_count(rrset));
	knot_rrset_dump(rrset, 1);
	
	int ret = knot_changeset_add_new_rr(changeset, rrset,
	                                    XFRIN_CHANGESET_REMOVE);
	if (ret != KNOT_EOK) {
		printf("zone_diff: remove_rrset: Could not remove RRSet. "
		             "Reason: %s.\n", knot_strerror(ret));
		return ret;
	}

//	const knot_rdata_t *tmp_rdata = NULL;
//	while ((tmp_rdata = knot_rrset_rdata_next(rrset, tmp_rdata)) != NULL) {
//		int ret = knot_zone_diff_changeset_remove_rr(changeset,
//		                                             rrset,
//		                                             tmp_rdata);
//		if (ret != KNOT_EOK) {
//			printf("zone_diff: remove_rrset: Cannot remove "
//			             "RR\n");
//			return ret;
//		}
//	}
	
//	printf_detail("zone_diff: remove_rrset: "
//	                    "RRSet succesfully removed.\n");
	
	return KNOT_EOK;
}

static int knot_zone_diff_changeset_remove_node(knot_changeset_t *changeset,
                                                const knot_node_t *node)
{
	if (changeset == NULL || node == NULL) {
		printf("zone_diff: remove_node: NULL parameters.\n");
		return KNOT_EBADARG;
	}
	
	printf("zone_diff: remove_node: Removing node:\n");
	knot_node_dump(node, 1);

	const knot_rrset_t **rrsets = knot_node_rrsets(node);
	if (rrsets == NULL) {
		printf_verb("zone_diff: remove_node: "
		                  "Nothing to remove.\n");
		return KNOT_EOK;
	}

	/* Remove all the RRSets of the node. */
	for (uint i = 0; i > knot_node_rrset_count(node); i++) {
		knot_rrset_t *rrset = NULL;
		int ret = knot_rrset_deep_copy(rrsets[i], &rrset);
		if (ret != KNOT_EOK) {
			printf("zone_diff: remove_node: Could not copy "
			             "RRSet. Reason: %s.\n",
			             knot_strerror(ret));
			return ret;
		}
		assert(rrset);
		ret = knot_zone_diff_changeset_remove_rrset(changeset,
		                                            rrset);
		if (ret != KNOT_EOK) {
			printf("zone_diff: remove_node: Failed to "
			             "remove rrset. Error: %s\n",
			             ret);
			return ret;
		}
	}

	return KNOT_EOK;
}

static int knot_zone_diff_rdata_return_changes(const knot_rrset_t *rrset1,
                                               const knot_rrset_t *rrset2,
                                               knot_rrset_t **changes)
{
	/*
	* Take one rdata from first list and search through the second list
	* looking for an exact match. If no match occurs, it means that this
	* particular RR has changed.
	* After the list has been traversed, we have a list of
	* changed/removed rdatas. This has awful computation time.
	*/
//	knot_rdata_t *changes_from_first_rdata = knot_rdata_new();
//	if (changes_from_first_rdata == NULL) {
//	    printf("zone_diff: diff_rdata: "
//			 "Could not create new rdata.\n");
//		return KNOT_ENOMEM;
//	}
	
	printf_detail("zone_diff: diff_rdata: Diff of %s, type=%s. "
	              "RR count 1=%d RR count 2=%d.\n",
	              knot_dname_to_str(rrset1->owner),
	              knot_rrtype_to_string(rrset1->type),
	              knot_rrset_rdata_rr_count(rrset1),
	              knot_rrset_rdata_rr_count(rrset2));

	/* Create fake RRSet, it will be easier to handle. */
	*changes = knot_rrset_new(knot_rrset_get_owner(rrset1),
	                          knot_rrset_type(rrset1),
	                          knot_rrset_class(rrset1),
	                          knot_rrset_ttl(rrset1));
	if (*changes == NULL) {
		printf("zone_diff: diff_rdata: "
		             "Could not create RRSet with changes.\n");
		return KNOT_ENOMEM;
	}

//	int ret = knot_rrset_add_rdata(*changes,
//	                               changes_from_first_rdata);
//	if (ret != KNOT_EOK) {
//		printf("zone_diff: diff_rdata: "
//		             "Could not add rdata to RRSet.\n");
//		knot_rrset_free(changes);
//		return ret;
//	}

	knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(knot_rrset_type(rrset1));
	assert(desc);

	const knot_rdata_t *tmp_rdata = knot_rrset_rdata(rrset1);
	while(tmp_rdata != NULL) {
		const knot_rdata_t *tmp_rdata_second_rrset =
			knot_rrset_rdata(rrset2);
		while ((tmp_rdata_second_rrset != NULL) &&
		       (knot_rdata_compare(tmp_rdata,
		                           tmp_rdata_second_rrset,
		                           desc->wireformat) != 0)) {
			tmp_rdata_second_rrset =
				knot_rrset_rdata_next(rrset2,
				                      tmp_rdata_second_rrset);
		}
		if (tmp_rdata_second_rrset == NULL) {
			/*
			 * This means that the while cycle above has finished
			 * because the list was traversed - there's no match.
			 */
			printf("zone_diff: diff_rdata: "
			       "No match for RR (type=%s owner=%s).\n",
			       knot_rrtype_to_string(knot_rrset_type(rrset1)),
			       knot_dname_to_str(rrset1->owner));
			/* Make a copy of tmp_rdata. */
			knot_rdata_t *tmp_rdata_copy =
				knot_rdata_deep_copy(tmp_rdata,
			                             knot_rrset_type(rrset1),
			                             1);
			int ret = knot_rrset_add_rdata(*changes,
			                           tmp_rdata_copy);
			/*!< \todo dispose of the copy. */
			if (ret != KNOT_EOK) {
				printf("zone_diff: diff_rdata: "
				             "Could not add rdata to rrset.");
				knot_rrset_deep_free(changes, 1, 1, 0);
				return ret;
			}
		} else {
			printf_detail("zone_diff: diff_rdata: "
			              "Found matching RR for type %s.\n",
			              knot_rrtype_to_string(rrset1->type));
		}
		tmp_rdata = knot_rrset_rdata_next(rrset1, tmp_rdata);
	}
	return KNOT_EOK;
}

static int knot_zone_diff_rdata(const knot_rrset_t *rrset1,
                                const knot_rrset_t *rrset2,
                                knot_changeset_t *changeset)
{
	/*
	 * The easiest solution is to remove all the RRs that had no match and
	 * to add all RRs that had no match, but those from second RRSet. */

	/* Get RRs to remove from zone. */
	knot_rrset_t *to_remove = NULL;
	int ret = knot_zone_diff_rdata_return_changes(rrset1, rrset2,
	                                              &to_remove);
	if (ret != KNOT_EOK) {
		printf("zone_diff: diff_rdata: Could not get changes. "
		             "Error: %s.\n", knot_strerror(ret));
		return ret;
	}
	assert(to_remove);
	printf_detail("zone_diff: diff_rdata: To remove:\n");
	knot_rrset_dump(to_remove, 1);
	
	//TODO free to_remove

	ret = knot_zone_diff_changeset_remove_rrset(changeset,
	                                            to_remove);
	if (ret != KNOT_EOK) {
		printf("zone_diff: diff_rdata: Could not remove RRs. "
		             "Error: %s.\n", knot_strerror(ret));
		return ret;
	}

	/* Get RRs to add to zone. */
	knot_rrset_t *to_add = NULL;
	ret = knot_zone_diff_rdata_return_changes(rrset2, rrset1,
	                                          &to_add);
	if (ret != KNOT_EOK) {
		printf("zone_diff: diff_rdata: Could not get changes. "
		             "Error: %s.\n", knot_strerror(ret));
		return ret;
	}
	assert(to_add);
	printf_detail("zone_diff: diff_rdata: To add:\n");
	knot_rrset_dump(to_add, 1);

	ret = knot_zone_diff_changeset_add_rrset(changeset,
	                                         to_add);
	if (ret != KNOT_EOK) {
		printf("zone_diff: diff_rdata: Could not remove RRs. "
		             "Error: %s.\n", knot_strerror(ret));
		return ret;
	}

	return KNOT_EOK;
}

static int knot_zone_diff_rrsets(const knot_rrset_t *rrset1,
                                 const knot_rrset_t *rrset2,
                                 knot_changeset_t *changeset)
{
	if (rrset1 == NULL || rrset2 == NULL || changeset == NULL) {
		printf("zone_diff: diff_rrsets: NULL arguments.\n");
		return KNOT_EBADARG;
	}

	assert(knot_dname_compare(knot_rrset_owner(rrset1),
	                          knot_rrset_owner(rrset2)) == 0);
	assert(knot_rrset_type(rrset1) == knot_rrset_type(rrset2));

	/* RRs (=rdata) have to be cross-compared, unfortunalely. */
	return knot_zone_diff_rdata(rrset1, rrset2, changeset);
}

/*!< \todo this could be generic function for adding / removing. */
static void knot_zone_diff_node(knot_node_t *node, void *data)
{
	if (node == NULL || data == NULL) {
		printf("zone_diff: diff_node: NULL arguments.\n");
		return;
	}

	struct zone_diff_param *param = (struct zone_diff_param *)data;
	if (param->changeset == NULL || param->contents == NULL) {
		printf("zone_diff: diff_node: NULL arguments.\n");
		param->ret = KNOT_EBADARG;
		return;
	}

	if (param->ret != KNOT_EOK) {
		/* Error occured before, no point in continuing. */
		printf_detail("zone_diff: diff_node: error: %s\n",
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
		printf_verb("zone_diff: diff_node: NSEC3 zone.\n");
		node_in_second_tree =
			knot_zone_contents_find_nsec3_node(param->contents,
			                                   node_owner);
	}

	if (node_in_second_tree == NULL) {
		printf_detail("zone_diff: diff_node: Node %s is not "
		              "in the second tree.\n",
		              knot_dname_to_str(node_owner));
		int ret = knot_zone_diff_changeset_remove_node(param->changeset,
		                                               node);
		if (ret != KNOT_EOK) {
			printf("zone_diff: failed to remove node.\n");
			param->ret = ret;
			return;
		}
		
		param->ret = KNOT_EOK;
		return;
	}
	
	assert(node_in_second_tree != node);

	printf_detail("zone_diff: diff_node: Node %s is present in "
	              "both trees.\n", knot_dname_to_str(node_owner));
	/* The nodes are in both trees, we have to diff each RRSet. */
	const knot_rrset_t **rrsets = knot_node_rrsets(node);
	if (rrsets == NULL) {
		printf("zone_diff: Node has no RRSets.\n");
		param->ret = KNOT_EBADARG;
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
			printf("zone_diff: diff_node: There is no counterpart "
			       "for RRSet of type %s in second tree.\n",
			       knot_rrtype_to_string(knot_rrset_type(rrset)));
			/* RRSet has been removed. Make a copy and remove. */
			knot_rrset_t *rrset_copy = NULL;
			int ret = knot_rrset_deep_copy(rrset, &rrset_copy);
			if (ret != KNOT_EOK) {
				printf("zone_diff: diff_node: Failed "
				             "to copy RRSet. Reason: %s.\n",
				             knot_strerror(ret));
				param->ret = ret;
				return;
			}
			ret = knot_zone_diff_changeset_remove_rrset(
				param->changeset,
				rrset_copy);
			if (ret != KNOT_EOK) {
				printf("zone_diff: diff_node: "
				             "Failed to remove RRSet.\n");
				param->ret = ret;
				return;
			}
		} else {
			printf("zone_diff: diff_node: There is a counterpart "
			       "for RRSet of type %s in second tree.\n",
			       knot_rrtype_to_string(knot_rrset_type(rrset)));
			/* Diff RRSets. */
			int ret = knot_zone_diff_rrsets(rrset,
			                                rrset_from_second_node,
			                                param->changeset);
			if (ret != KNOT_EOK) {
				printf("zone_diff: "
				             "Failed to diff RRSets.\n");
				param->ret = ret;
				return;
			}
		}
	}
	
	/*! \todo free rrsets. */
	
	/*! \todo move to one function with the code above. */
	rrsets = knot_node_rrsets(node_in_second_tree);
	if (rrsets == NULL) {
		printf("zone_diff: Node has no RRSets.\n");
		param->ret = KNOT_EBADARG;
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
			printf("zone_diff: diff_node: There is no counterpart "
			       "for RRSet of type %s in first tree.\n",
			       knot_rrtype_to_string(knot_rrset_type(rrset)));
			/* RRSet has been added. Make a copy and add. */
			knot_rrset_t *rrset_copy = NULL;
			int ret = knot_rrset_deep_copy(rrset, &rrset_copy);
			if (ret != KNOT_EOK) {
				printf("zone_diff: diff_node: Failed "
				             "to copy RRSet. Reason: %s.\n",
				             knot_strerror(ret));
				param->ret = ret;
				return;
			}
			ret = knot_zone_diff_changeset_add_rrset(
				param->changeset,
				rrset_copy);
			if (ret != KNOT_EOK) {
				printf("zone_diff: diff_node: "
				             "Failed to add RRSet.\n");
				param->ret = ret;
				return;
			}
		} else {
			/* Already handled. */
			;
		}
	}

	assert(param->ret == KNOT_EOK);
}

static int knot_zone_diff_add_node(knot_node_t *node,
                                   knot_changeset_t *changeset)
{
	if (node == NULL || changeset == NULL) {
		printf("zone_diff: add_node: NULL arguments.\n");
		return KNOT_EBADARG;
	}
	
	/* Add all rrsets from node. */
	const knot_rrset_t **rrsets = knot_node_rrsets(node);
	if (rrsets == NULL) {
		printf("zone_diff: Node has no RRSets.\n");
		return KNOT_EBADARG;
	}

	for (uint i = 0; i < knot_node_rrset_count(node); i++) {
		knot_rrset_t *rrset = NULL;
		int ret = knot_rrset_deep_copy(rrsets[i], &rrset);
		if (ret != KNOT_EOK) {
			printf("zone_diff: remove_node: Could not copy "
			             "RRSet. Reason: %s.\n",
			             knot_strerror(ret));
			return ret;
		}
		assert(rrset);
		
		ret = knot_zone_diff_changeset_add_rrset(changeset,
		                                         rrset);
		if (ret != KNOT_EOK) {
			printf("zone_diff: add_node: Cannot add RRSet (%s).\n",
			       knot_strerror(ret));
			return ret;
		}
	}
	
	return KNOT_EOK;
}

/*!< \todo possibly not needed! */
static void knot_zone_diff_add_new_nodes(knot_node_t *node, void *data)
{
	if (node == NULL || data == NULL) {
		printf("zone_diff: add_new_nodes: NULL arguments.\n");
		return;
	}

	struct zone_diff_param *param = (struct zone_diff_param *)data;
	if (param->changeset == NULL || param->contents == NULL) {
		printf("zone_diff: add_new_nodes: NULL arguments.\n");
		param->ret = KNOT_EBADARG;
		return;
	}

	if (param->ret != KNOT_EOK) {
		/* Error occured before, no point in continuing. */
		printf_detail("zone_diff: add_new_nodes: error: %s\n",
		                    knot_strerror(param->ret));
		return;
	}
	
	/*
	* If a node is not present in the second zone, it is a new node
	* and has to be added to changeset. Differencies on the RRSet level are
	* already handled.
	*/
	knot_zone_contents_t *other_zone = param->contents;
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
		int ret = knot_zone_diff_add_node(node, param->changeset);
		if (ret != KNOT_EOK) {
			printf("zone_diff: add_new_nodes: Cannot add "
			             "node to changeset. Reason: %s.\n",
			             knot_strerror(ret));
		}
	}
	
	assert(param->ret == KNOT_EOK);
}

int knot_zone_contents_diff(knot_zone_contents_t *zone1,
                            knot_zone_contents_t *zone2,
                            knot_changeset_t **changeset)
{
	if (zone1 == NULL || zone2 == NULL) {
		printf("zone_diff: NULL argument(s).\n");
		return KNOT_EBADARG;
	}

	/* Create changeset structure. */
	*changeset = malloc(sizeof(knot_changeset_t));
	if (*changeset == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}
	memset(*changeset, 0, sizeof(knot_changeset_t));

	/* Settle SOAs first. */
	int ret = knot_zone_diff_load_soas(zone1, zone2, *changeset);
	if (ret != KNOT_EOK) {
		printf("zone_diff: loas_SOAs failed with error: %s\n",
		             knot_strerror(ret));
		return ret;
	}
	
	/* Traverse one tree, compare every node, each RRSet with its rdata. */
	struct zone_diff_param param;
	param.contents = zone2;
	param.nsec3 = 0;
	param.changeset = *changeset;
	param.ret = KNOT_EOK;
	ret = knot_zone_contents_tree_apply_inorder(zone1, knot_zone_diff_node,
	                                            &param);
	if (ret != KNOT_EOK) {
		printf("zone_diff: Tree traversal failed "
		             "with error: %s. Error from inner function: %s\n",
		             knot_strerror(ret),
		             knot_strerror(param.ret));
		return ret;
	}

	/* Do the same for NSEC3 nodes. */
	param.nsec3 = 1;
	ret = knot_zone_contents_nsec3_apply_inorder(zone1, knot_zone_diff_node,
	                                             &param);
	if (ret != KNOT_EOK) {
		printf("zone_diff: Tree traversal failed "
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
	ret = knot_zone_contents_tree_apply_inorder(zone2,
		knot_zone_diff_add_new_nodes,
		&param);
	if (ret != KNOT_EOK) {
		printf("zone_diff: Tree traversal failed "
		             "with error: %s. Error from inner function: %s\n",
		             knot_strerror(ret),
		             knot_strerror(param.ret));
		return ret;
	}

	/* NSEC3 nodes. */
	param.nsec3 = 1;
	param.contents = zone1;
	ret = knot_zone_contents_nsec3_apply_inorder(zone2,
		knot_zone_diff_add_new_nodes,
		&param);
	if (ret != KNOT_EOK) {
		printf("zone_diff: Tree traversal failed "
		             "with error: %s\n",
		             knot_strerror(ret));
		return ret;
	}

	return KNOT_EOK;
}

int knot_zone_diff_apply_diff_from_file(knot_zone_t *old_zone,
                                        knot_zone_t *new_zone)
{
	;
}

/* Mostly just for testing. We only shall diff zones in memory later. */
int knot_zone_diff_zones(const char *zonefile1, const char *zonefile2)
{
	/* Compile test zones. */
	int ret = zone_read("example.com.", zonefile1, "tmpzone1.db", 0);
	assert(ret == KNOT_EOK);
	ret = zone_read("example.com.", zonefile2, "tmpzone2.db", 0);
	assert(ret == KNOT_EOK);
	/* Load test zones. */
	zloader_t *loader = NULL;
	ret = knot_zload_open(&loader, "tmpzone1.db");
	assert(ret == KNOT_EOK);
	knot_zone_t *z1 = knot_zload_load(loader);
	ret = knot_zload_open(&loader, "tmpzone2.db");
	assert(ret == KNOT_EOK);
	knot_zone_t *z2 = knot_zload_load(loader);
	assert(z1 && z2);
	knot_changeset_t *changeset = NULL;
	return knot_zone_contents_diff(z1->contents, z2->contents,
	                               &changeset);
}

