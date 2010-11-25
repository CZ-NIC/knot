#include <stdio.h>
#include <assert.h>

#include <ldns/ldns.h>
#include <urcu.h>

#include "zone-database.h"
#include "common.h"
#include "dns-utils.h"

/*----------------------------------------------------------------------------*/
/* Private functions                                                          */
/*----------------------------------------------------------------------------*/

static void zdb_find_zone(zdb_database_t *database, ldns_rdf *zone_name,
                          zdb_zone_t **zone, zdb_zone_t **prev)
{
	*zone = database->head;
	*prev = NULL;

	// start of RCU reader critical section
	rcu_read_lock();

	while ((*zone) != NULL
	       && ldns_dname_compare((*zone)->zone_name, zone_name)) {
		(*prev) = (*zone);
		(*zone) = (*zone)->next;
	}

	// end of RCU reader critical section
	rcu_read_unlock();
}

/*----------------------------------------------------------------------------*/

static void zdb_disconnect_zone(zdb_database_t *database, zdb_zone_t *z,
                                zdb_zone_t *prev)
{
	// disconect the zone from the list
	if (prev != NULL) {
		assert(prev->next == z);
		prev->next = z->next;
	} else {
		assert(database->head == z);
		database->head = z->next;
	}
}

/*----------------------------------------------------------------------------*/

static uint zdb_create_list(zdb_zone_t *zone, ldns_zone *zone_ldns)
{
	uint nodes = 0;

	debug_zdb("Creating linked list of zone nodes...\n");

	// sort the zone so we obtain RRSets
	ldns_zone_sort(zone_ldns);

	debug_zdb("Done.\nProcessing RRSets...\n");
	/*
	 * Walk through all RRs, separate them into zone nodes and RRSets
	 * and create a linked list of nodes in canonical order.
	 *
	 * Some idiot implemented ldns_rr_list_pop_rrset() to return the LAST
	 * RRSet so we will fill the zone from the last node to the first.
	 */
	zn_node_t *act_node = NULL;
	zn_node_t *last_node = NULL;

	uint rr_count = ldns_zone_rr_count(zone_ldns);
	uint i = 0;
	uint step = rr_count / 10;
	uint next = step;
	log_info("Processed: ");

	while (i < rr_count) {
		ldns_rr_list *rrset = ldns_rr_list_pop_rrset(
				ldns_zone_rrs(zone_ldns));
		i += ldns_rr_list_rr_count(rrset);

		if (i >= next) {
			log_info("%.0f%% ", 100 *((float)next / rr_count));
			next += step;
		}

		if (rrset == NULL) {
			log_error("Unknown error while processing zone %s.\n",
			          ldns_rdf2str(zone->zone_name));
			// ignore rest of the zone
			break;
		}
		debug_zdb("Processing RRSet with owner %s and type %s.\n",
		          ldns_rdf2str(ldns_rr_list_owner(rrset)),
		          ldns_rr_type2str(ldns_rr_list_type(rrset)));

		if (act_node != NULL
			&& ldns_dname_compare(ldns_rr_list_owner(rrset),
					      act_node->owner) == 0) {
			// same owner, insert into the same node
			debug_zdb("Inserting into node with owner %s.\n",
			          ldns_rdf2str(act_node->owner));
			if (zn_add_rrset(act_node, rrset) != 0) {
				log_error("Error while processing zone %s: "
					  "Cannot add RRSet to a zone node.\n",
					  ldns_rdf2str(zone->zone_name));
				// ignore rest of the zone
				break;
			}
		} else {
			// create a new node, add the RRSet and connect to the
			// list
			debug_zdb("Creating new node.\n");
			zn_node_t *new_node = zn_create();
			if (new_node == NULL) {
				log_error("Error while processing zone %s: "
					  "Cannot create new zone node.\n",
					  ldns_rdf2str(zone->zone_name));
				// ignore rest of the zone
				break;
			}
			if (zn_add_rrset(new_node, rrset) != 0) {
				log_error("Error while processing zone %s: "
					  "Cannot add RRSet to a zone node.\n",
					  ldns_rdf2str(zone->zone_name));
				// ignore rest of the zone
				free(new_node);
				break;
			}
			new_node->next = act_node;
			if (act_node != NULL) {
				act_node->prev = new_node;
			} else {
				last_node = new_node;
			}
			act_node = new_node;	// continue with the next node
			++nodes;
		}
	}

	log_info("(%d RRs)\n", i);

	debug_zdb("Processing of RRSets done.\nLast node created (should be "
		  "zone apex): %s, last node of the list: %s.\n",
	         ldns_rdf2str(act_node->owner), ldns_rdf2str(last_node->owner));

	// connect last node to the apex, creating cyclic list
	last_node->next = act_node;
	act_node->prev = last_node;
	// save the zone apex
	zone->apex = act_node;

	debug_zdb("Done.\nAdding SOA RR to the apex node...\n");

	if (zn_add_rr(zone->apex, ldns_rr_clone(ldns_zone_soa(zone_ldns))) != 0
	                || skip_empty(zone->apex->rrsets) == 0) {
		log_error("Error while processing zone %s: Cannot insert SOA RR"
			  "into the zone apex node.\n",
			  ldns_rdf2str(zone->zone_name));
		free(zone->apex);
		return nodes;
	}

	return nodes;
}

/*----------------------------------------------------------------------------*/

static uint zdb_common_labels(const ldns_rdf *dname1, const ldns_rdf *dname2)
{
	uint common = 0;
	ldns_rdf *dname1r = ldns_dname_reverse(dname1);
	ldns_rdf *dname2r = ldns_dname_reverse(dname2);

	uint8_t *c1 = ldns_rdf_data(dname1r);
	uint8_t *c2 = ldns_rdf_data(dname2r);

	while (*c1 != '\0' && *c1 == *c2
	       && strncmp((char *)c1 + 1, (char *)c2 + 1, *c1) == 0) {
		debug_zdb("Comparing labels of length %u: %.*s and %.*s\n",
		          *c1, *c1, (char *)c1 + 1, *c1, (char *)c2 + 1);
		c1 += *c1 + 1;
		c2 += *c2 + 1;
		++common;
	}

	ldns_rdf_deep_free(dname1r);
	ldns_rdf_deep_free(dname2r);

	return common;
}

/*----------------------------------------------------------------------------*/

static void zdb_connect_node(zn_node_t *next, zn_node_t *node)
{
	node->prev = next->prev;
	node->next = next;
	next->prev->next = node;
	next->prev = node;
}

/*----------------------------------------------------------------------------*/

static int zdb_add_empty_nonterminals(zdb_zone_t *zone)
{
	debug_zdb("\nCreating empty non-terminals in the zone...\n");
	int created = 0;

	zn_node_t *current = zone->apex->next;
	zn_node_t *parent = zone->apex;
	uint8_t apex_labels = ldns_dname_label_count(parent->owner);

	while (current != zone->apex) {
		zn_node_t *prev = current->prev;
		ldns_rdf *curr_name = current->owner;

		debug_zdb("Current node: %s\n", ldns_rdf2str(curr_name));

		if (ldns_dname_is_subdomain(curr_name, prev->owner)) {
			// descendant of the previous node
			parent = prev;
		} else if (parent != prev
		        && !ldns_dname_is_subdomain(curr_name, parent->owner)) {
			// we must find appropriate parent
			// number of labels matching between current and parent
			uint common = zdb_common_labels(curr_name,
							parent->owner);
			debug_zdb("Common labels with parent node (%s): %u\n",
			          ldns_rdf2str(parent->owner), common);
			assert(common < ldns_dname_label_count(parent->owner));
			assert(common >= ldns_dname_label_count(
					zone->apex->owner));

			if (common == apex_labels) {
				parent = zone->apex;
			} else {
				while (ldns_dname_label_count(parent->owner)
					> common) {
					parent = parent->prev;
				}
			}
		}

		uint d = ldns_dname_label_count(curr_name)
		         - ldns_dname_label_count(parent->owner);

		debug_zdb("Parent node: %s, difference in label counts: %u\n",
		          ldns_rdf2str(parent->owner), d);

		prev = current;

		// if the difference in label length is more than one, create
		// the empty non-terminal nodes
		if (d > 1) {
			do {
				ldns_rdf *new_name = ldns_dname_left_chop(
						curr_name);
				if (new_name == NULL) {
					log_error("Unknown error in "
						  "ldns_dname_left_chop().\n");
					return -1;
				}
				zn_node_t *new_node = zn_create();
				if (new_node == NULL) {
					ldns_rdf_deep_free(new_name);
					return -2;
				}
				new_node->owner = new_name;

				debug_zdb("Inserting new node with owner %s to "
					 "the list.\n",ldns_rdf2str(new_name));
				zdb_connect_node(current, new_node);
				++created;

				current = new_node;
				curr_name = new_name;
				--d;
			} while (d > 1);

			// save the created node with most labels as new parent
			parent = prev->prev;
		}

		// if no new nodes were created, the parent remains the same

		current = prev->next;
	}

	debug_zdb("Done, created nodes: %d\n\n", created);

	return created;
}

/*----------------------------------------------------------------------------*/

static void zdb_delete_list_items(zdb_zone_t *zone)
{
	zn_node_t *node = zone->apex;
	zn_node_t *old_node;
	while (node->next != node) {
		old_node = node;
		node = node->next;

		assert(old_node->prev != NULL);

		old_node->prev->next = old_node->next;
		old_node->next->prev = old_node->prev;
		zn_destroy(&old_node);
	}

	zn_destroy(&node);
}

/*----------------------------------------------------------------------------*/

static zn_node_t *zdb_find_name_in_zone_nc(const zdb_zone_t *zone,
                                         const ldns_rdf *dname)
{
	assert(zone != NULL);
	// start of RCU reader critical section
	rcu_read_lock();

	zn_node_t *found = zds_find(zone->zone, dname);

	// end of RCU reader critical section
	rcu_read_unlock();

	return found;
}

/*----------------------------------------------------------------------------*/

//static zn_node_t *zdb_find_name_in_list(const zdb_zone *zone, ldns_rdf *name)
//{
//	zn_node_t *node = zone->apex;
//	int cmp;
//	while ((cmp = ldns_dname_match_wildcard(name, node->owner)) != 1
//	       && node->next != zone->apex) {
//		node = node->next;
//	}

//	return (cmp == 1) ? node : NULL;
//}

/*----------------------------------------------------------------------------*/

static zn_node_t *zdb_find_name_or_wildcard(const zdb_zone_t *zone,
                                            ldns_rdf *name)
{
	assert(ldns_rdf_get_type(name) == LDNS_RDF_TYPE_DNAME);
	debug_zdb("zdb_find_name_or_wildcard(), name: %s.", ldns_rdf2str(name));
	zn_node_t *node = zdb_find_name_in_zone_nc(zone, name);

	if (node == NULL) {
		ldns_rdf *name_orig = ldns_dname_clone_from(name, 0);
		uint labels = ldns_dname_label_count(name_orig);

		do {
			debug_zdb("Chopping leftmost label from name %s.\n",
			          ldns_rdf2str(name_orig));
			ldns_rdf *name_new = ldns_dname_left_chop(name_orig);
			assert(ldns_rdf_get_type(name_new)
			       == LDNS_RDF_TYPE_DNAME);
			// replace last label with * and search
			ldns_rdf *wildcard = ldns_dname_new_frm_str("*");

			if (ldns_dname_cat(wildcard, name_new)
				!= LDNS_STATUS_OK) {
				log_error("Unknown error occured.\n");
				ldns_rdf_deep_free(wildcard);
				ldns_rdf_deep_free(name_new);
				break;
			}

			assert(ldns_rdf_get_type(wildcard)
			       == LDNS_RDF_TYPE_DNAME);
			debug_zdb("Searching for name %s in the hash table.\n",
			          ldns_rdf2str(wildcard));
			node = zdb_find_name_in_zone_nc(zone, wildcard);

			ldns_rdf_deep_free(wildcard);
			ldns_rdf_deep_free(name_orig);
			name_orig = name_new;
			--labels;
		} while (node == NULL && labels > 0);

		ldns_rdf_deep_free(name_orig);
	}

	return node;
}

/*----------------------------------------------------------------------------*/

static int zdb_adjust_cname(zdb_zone_t *zone, zn_node_t *node)
{
	int res = 0;
	ldns_rr_list *cname_rrset = zn_find_rrset(node, LDNS_RR_TYPE_CNAME);
	if (cname_rrset != NULL) {
		res = 1;
		// retreive the canonic name
		debug_zdb("Found CNAME, resolving...\n");
		ldns_rdf *cname = ldns_rr_rdf(
				ldns_rr_list_rr(cname_rrset, 0), 0);
		assert(ldns_rdf_get_type(cname) == LDNS_RDF_TYPE_DNAME);
		debug_zdb("Canonical name for alias %s is %s\n",
		          ldns_rdf2str(node->owner), ldns_rdf2str(cname));

		zn_node_t *cname_node = zdb_find_name_or_wildcard(zone, cname);

		if (cname_node
		    && zn_add_referrer_cname(cname_node, node) != 0) {
			log_error("Error saving referrer node to node %s\n",
			          ldns_rdf2str(cname_node->owner));
			return -1;
		}
		zn_set_ref_cname(node, cname_node);

		debug_zdb("Found node: %s\n\n", (node->ref.cname)
		          ? ldns_rdf2str(node->ref.cname->owner)
		          : "(nil)");
	}
	return res;
}

/*----------------------------------------------------------------------------*/
/*!
 * \todo We should remove the reference from the node, as we will be never able
 *       to clear it once the referred node gets deleted.
 *
 * \note Must be called after inserting all nodes into the zone data structure.
 */
static void zdb_adjust_additional(zdb_zone_t *zone, zn_node_t *node,
                                  ldns_rr_type type)
{
	ldns_rr_list *rrset = zn_find_rrset(node, type);
	if (rrset == NULL) {
		return;
	}

	// for each MX RR find the appropriate node in the zone (if any)
	// and save a reference to it in the zone node
	debug_zdb("\nFound %s, searching for corresponding A/AAAA "
		  "records...\n", ldns_rr_type2str(type));
	int count = ldns_rr_list_rr_count(rrset);
	for (int i = 0; i < count; ++i) {
		ldns_rdf *name;

		switch (type) {
		case LDNS_RR_TYPE_MX:
			name = ldns_rr_mx_exchange(ldns_rr_list_rr(rrset, i));
			break;
		case LDNS_RR_TYPE_NS:
			name = ldns_rr_ns_nsdname(ldns_rr_list_rr(rrset, i));
			break;
		case LDNS_RR_TYPE_SRV:
			name = ldns_rr_rdf(ldns_rr_list_rr(
					rrset, i), 3);	// constant
			if (ldns_dname_label_count(name) == 0) {
				// ignore
				debug_zdb("SRV with empty name as a "
					  "target: %s\n",
					  ldns_rr2str(ldns_rr_list_rr(
							  rrset, i)));
				return;
			}
			assert(ldns_rdf_get_type(name) == LDNS_RDF_TYPE_DNAME);
			break;
		default:
			assert(0);
		}

		assert(name != NULL);
		debug_zdb("Searching for A/AAAA for %s name %s.\n",
			  ldns_rr_type2str(type), ldns_rdf2str(name));

		// the authoritative nodes should already be in the hash table
		zn_node_t *found = zdb_find_name_or_wildcard(zone, name);

		if (found == NULL) {
			return;
		}

		debug_zdb("Found node: %s\n\n", (found)
			  ? ldns_rdf2str(found->owner) : "(nil)");

		if (zn_find_rrset(found, LDNS_RR_TYPE_CNAME) != NULL) {
			debug_zdb("Found CNAME within the node, saving.\n");
			if (zn_add_ref(node, name, type, NULL, found) != 0) {
				log_error("Error occured while saving A RRSet "
					  "for %s record in node %s\n\n",
					  ldns_rr_type2str(type),
					  ldns_rdf2str(node->owner));
			}
			if (zn_add_referrer(found, node, type) != 0) {
				log_error("Error occured while saving referrer "
					  "node to node %s\n",
					  ldns_rdf2str(found->owner));
			}
			debug_zdb("Done.\n\n");
			continue;
		}

		ldns_rr_list *rrset = zn_find_rrset(found, LDNS_RR_TYPE_A);
		if (rrset != NULL) {
			debug_zdb("Found A RRSet within the node, saving.\n");
			if (zn_add_ref(node, name, type, rrset, NULL) != 0) {
				log_error("Error occured while saving A RRSet "
					  "for %s record in node %s\n\n",
					  ldns_rr_type2str(type),
					  ldns_rdf2str(node->owner));
				return;
			}
			if (zn_add_referrer(found, node, type) != 0) {
				log_error("Error occured while saving referrer "
					  "node to node %s\n",
					  ldns_rdf2str(found->owner));
			}
		}

		rrset = zn_find_rrset(found, LDNS_RR_TYPE_AAAA);
		if (rrset != NULL) {
			debug_zdb("Found AAAA RRSet within the node, saving\n");
			if (zn_add_ref(node, name, type, rrset, NULL) != 0) {
				log_error("Error occured while saving AAAA "
					  "RRSet for %s record in node %s\n\n",
					  ldns_rr_type2str(type),
					  ldns_rdf2str(node->owner));
				return;
			}
			if (zn_add_referrer(found, node, type) != 0) {
				log_error("Error occured while saving referrer "
					  "node to node %s\n",
					  ldns_rdf2str(found->owner));
			}
		}
		debug_zdb("Done.\n\n");
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \note Must be called after inserting all nodes into the zone data structure.
 */
static void zdb_adjust_additional_apex(zdb_zone_t *zone, zn_node_t *node)
{
	zdb_adjust_additional(zone, node, LDNS_RR_TYPE_MX);
	zdb_adjust_additional(zone, node, LDNS_RR_TYPE_NS);
	zdb_adjust_additional(zone, node, LDNS_RR_TYPE_SRV);
}

/*----------------------------------------------------------------------------*/
/*!
 * \note Must be called after inserting all nodes into the zone data structure.
 */
static void zdb_adjust_additional_all(zdb_zone_t *zone, zn_node_t *node)
{
	zdb_adjust_additional(zone, node, LDNS_RR_TYPE_MX);
	// no need to adjust NS, as they may be only in zone apex
	//zdb_adjust_additional(zone, node, LDNS_RR_TYPE_NS);
	zdb_adjust_additional(zone, node, LDNS_RR_TYPE_SRV);
}

/*----------------------------------------------------------------------------*/
/*!
 * \return Found matching domain name even if \a name is a wildcard, or NULL
 *         if not found.
 */
static ldns_rdf *zdb_dname_list_find(ldns_rdf **list, size_t count,
                                     ldns_rdf *name)
{
	int i = 0;
	int found = 0;
	while (i < count
	       && (found = ldns_dname_match_wildcard(list[i], name)) != 1) {
		++i;
	}
	if (found == 1) {
		return list[i];
	} else {
		return NULL;
	}
}

/*----------------------------------------------------------------------------*/

//static ldns_rdf **zdb_extract_ns(ldns_rr_list *ns_rrset, size_t count)
//{
//	assert(ldns_is_rrset(ns_rrset));
//	ldns_rdf **ns_rrs = malloc(count * sizeof(ldns_rr_list *));
//	if (ns_rrs == NULL) {
//		ERR_ALLOC_FAILED;
//		return NULL;
//	}
//	for (int i = 0; i < count; ++i) {
//		ns_rrs[i] = ldns_rr_rdf(ldns_rr_list_rr(ns_rrset, i), 0);
//		debug_zdb("NS RR #%d: %s\n", i, ldns_rdf2str(ns_rrs[i]));
//	}
//	return ns_rrs;
//}

/*----------------------------------------------------------------------------*/

static int zdb_rr_list_contains_dname(const ldns_rr_list *rrset,
                                      const ldns_rdf *dname, size_t pos)
{
	assert(ldns_rdf_get_type(dname) == LDNS_RDF_TYPE_DNAME);
	for (int i = 0; i < ldns_rr_list_rr_count(rrset); ++i) {
		if (ldns_dname_match_wildcard(ldns_rr_rdf(ldns_rr_list_rr(
				rrset, i), pos), dname)) {
			return 1;
		}
	}
	return 0;
}

/*----------------------------------------------------------------------------*/

static int zdb_process_nonauth(zn_node_t *node, ldns_rr_list *ns_rrset,
                               ldns_rdf **processed, size_t *count,
                               zn_node_t *deleg)
{
	zn_set_non_authoritative(node);

	if (zn_is_empty(node) == 0) {
		return 0;
	}

	if (!zdb_rr_list_contains_dname(ns_rrset, node->owner, 0)) {
		log_error("Zone contains non-authoritative domain name %s,"
		          " which is not referenced in %s NS records!\n",
		         ldns_rdf2str(node->owner), ldns_rdf2str(deleg->owner));
		return -3;
	}
	if (processed != NULL) {
		assert(count != NULL);
		// save the dname as processed
		processed[(*count)++] = node->owner;
	}

	debug_zdb("Saving glues from node %s\n", ldns_rdf2str(node->owner));
	// push the glues to the delegation point node
	int res = zn_push_glue(deleg, zn_find_rrset(node, LDNS_RR_TYPE_A));
	res += zn_push_glue(deleg, zn_find_rrset(node, LDNS_RR_TYPE_AAAA));

	if (res != 0) {
		log_error("Error while saving glue records for delegation point"
		          " %s\n", ldns_rdf2str(deleg->owner));
		return -4;
	}

	debug_zdb("Saved %d glue records.\n",
	          ldns_rr_list_rr_count(zn_get_glues(deleg)));

	return 0;
}

/*----------------------------------------------------------------------------*/
/*!
 * \note Must be called after inserting all nodes into the zone data structure.
 */
static int zdb_find_other_glues(const zdb_zone_t *zone, zn_node_t *deleg_point,
                                ldns_rr_list *ns_rrset, ldns_rdf **processed,
                                size_t proc_count)
{
	debug_zdb("Some NS names are probably elsewhere in the zone, or "
	          "outside the zone\n");
	size_t ns_count = ldns_rr_list_rr_count(ns_rrset);
	int i = 0;
	while (proc_count < ns_count && i < ns_count) {
		ldns_rdf *ns = /*ldns_rr_owner(ldns_rr_list_rr(ns_rrset, i));*/
		        ldns_rr_rdf(ldns_rr_list_rr(ns_rrset, i), 0);
		assert(ldns_rdf_get_type(ns) == LDNS_RDF_TYPE_DNAME);
		if (zdb_dname_list_find(processed, proc_count, ns) == NULL) {
			debug_zdb("NS name %s not found under deleg point %s\n",
			          ldns_rdf2str(ns),
				  ldns_rdf2str(deleg_point->owner));

			// we must search in the list as the other nodes may not
			// be inserted into the table yet
			//zn_node *ns_node = zdb_find_name_in_list(zone, ns);
			zn_node_t *ns_node =
					zdb_find_name_or_wildcard(zone, ns);

			if (ns_node != NULL &&
			    !zn_is_non_authoritative(ns_node)) {
				debug_zdb("Found in authoritative data, "
					  "extracting glues.\n");
				int res = zn_push_glue(deleg_point,
				                zn_find_rrset(ns_node,
							      LDNS_RR_TYPE_A));
				res += zn_push_glue(deleg_point,
				              zn_find_rrset(ns_node,
							    LDNS_RR_TYPE_AAAA));
				if (res != 0) {
					log_error("Error while saving glues "
						  "for delegation point %s\n",
					      ldns_rdf2str(deleg_point->owner));
					return -4;
				}
			}
			processed[proc_count++] = ns;
		}
		++i;
	}
	return 0;
}

/*----------------------------------------------------------------------------*/

static void zdb_set_delegation_point(zn_node_t **node)
{
	debug_zdb("Setting %s to be a delegation point and skipping its "
		  "subdomains\n", ldns_rdf2str((*node)->owner));
	zn_set_delegation_point(*node);
	zn_node_t *deleg = *node;
	while (ldns_dname_is_subdomain((*node)->next->owner, deleg->owner)) {
		(*node) = (*node)->next;
	}
}

/*----------------------------------------------------------------------------*/

static int zdb_adjust_delegation_point(const zdb_zone_t *zone, zn_node_t **node)
{
	int res = 0;

	ldns_rr_list *ns_rrset = zn_find_rrset(*node, LDNS_RR_TYPE_NS);
	if (ns_rrset != NULL) {
		//zn_set_delegation_point(*node);
		res = 1;

		debug_zdb("\nAdjusting delegation point %s\n",
		          ldns_rdf2str((*node)->owner));

		size_t ns_count = ldns_rr_list_rr_count(ns_rrset);

		// mark all subsequent nodes which are subdomains of this node's
		// owner as non authoritative and extract glue records from them
		zn_node_t *deleg = *node;
		ldns_rdf **processed = malloc(ns_count * sizeof(ldns_rdf *));
		memset(processed, 0, ns_count * sizeof(ldns_rdf *));
		size_t proc_count = 0;

		while (ldns_dname_is_subdomain((*node)->next->owner,
					       deleg->owner)) {
			(*node) = (*node)->next;
			if ((res = zdb_process_nonauth(*node, ns_rrset,
					processed, &proc_count, deleg)) < 0) {
				break;
			}
		}

		if (proc_count < ns_count
		                && zdb_find_other_glues(zone, deleg, ns_rrset,
					processed, proc_count) != 0) {
			res = -1;
		}

		free(processed);
		// set to last processed node
		debug_zdb("Done.\n\n");
	}
	return res;
}

/*----------------------------------------------------------------------------*/

static int zdb_insert_node_to_zone(zdb_zone_t *zone, zn_node_t *node)
{
	zn_node_t *n = zone->apex;
	int cmp;
	zn_node_t *deleg = NULL;

	// if there is no zone apex, only node with SOA record may be inserted
	if (zone->apex == NULL) {
		ldns_rr_list *soa_rrset = zn_find_rrset(node, LDNS_RR_TYPE_SOA);
		if (soa_rrset == NULL) {
			log_error("Trying to insert node %s with not SOA record"
				  "to an empty zone!\n",
				  ldns_rdf2str(node->owner));
			return -1;
		}
		if (ldns_rr_list_rr_count(soa_rrset) > 1) {
			log_info("More than one SOA record in node %s, ignoring"
				 "other.\n", ldns_rdf2str(node->owner));
		}
		if (ldns_dname_compare(zone->zone_name, node->owner) != 0) {
			log_error("Trying to insert node %s with SOA record to "
				  "zone with different name %s.\n",
				  ldns_rdf2str(node->owner),
			          ldns_rdf2str(zone->zone_name));
			return -2;
		}
		zone->apex = node;

		// insert the node into the zone data structure
		if (zds_insert(zone->zone, node) != 0) {
			return -6;
		}

		return 0;
	}

	// find right place for the node to be connected
	while ((cmp = ldns_dname_compare(n->owner, node->owner)) < 0) {
		if (deleg == NULL && zn_is_delegation_point(n)) {
			// start of delegated nodes
			deleg = n;
		} else if (deleg != NULL && !zn_is_delegation_point(n)) {
			// end of delegated nodes
			deleg = NULL;
		}
		n = n->next;
		if (n == zone->apex) {
			// all nodes come before the inserted node, we would get
			// into cycle
			break;
		}
	}

	if (cmp == 0) {
		log_error("Trying to insert node with owner %s already present "
			  "in the zone\n", ldns_rdf2str(node->owner));
		return -5;	// node exists in the zone
	}

	int res = 0;
	ldns_rr_list *ns_rrset = NULL;

	// check if the node's owner is not child of delegation point
	if (deleg && ldns_dname_is_subdomain(node->owner, deleg->owner)) {
		// mark the node as non-authoritative and save glue records
		ns_rrset = zn_find_rrset(deleg, LDNS_RR_TYPE_NS);
		assert(ns_rrset != NULL);
		res = zdb_process_nonauth(node, ns_rrset, NULL, NULL, deleg);
		if (res == 0) {
			// if everything went well, connect the node before n
			zdb_connect_node(n, node);
		}
		// do not insert the node into the zone data structure
	} else {
		if ((ns_rrset = zn_find_rrset(node, LDNS_RR_TYPE_NS)) != NULL) {
			// delegation point; must connect to the list and then
			// adjust the following nodes if needed
			zdb_connect_node(n, node);
			zn_node_t *d = node;
			res = zdb_adjust_delegation_point(zone, &d);
		} else {
			// not a non-authoritative node or delegation point
			// check if it has CNAME RR
			if (zdb_adjust_cname(zone, node) == 0) {
				// if not, adjust additional data if any needed
				zdb_adjust_additional_all(zone, node);
			}
			zdb_connect_node(n, node);
		}

		// insert the node into the zone data structure
		if (res == 0 && zds_insert(zone->zone, node) != 0) {
			res = -6;
		}
	}

	return res;
}

#ifdef ZDB_DEBUG_INSERT_CHECK
static ldns_rdf **inserted_nodes;
#endif
/*----------------------------------------------------------------------------*/
/*!
 * \brief Inserts all nodes from list starting with \a head to the zone data
 *        structure.
 *
 * \param zone Zone data structure to insert to.
 * \param head In: first item in the list of nodes to be inserted. Out: the same
 *             if successful, the first non-inserted node if a failure occured.
 *
 * \retval 0 On success.
 * \retval -1 On failure. \a head will point to the first item not inserted.
 */
static int zdb_insert_nodes_into_zds(zdb_zone_t *z, uint *nodes,
                                     zn_node_t **node)
{
	assert((*node) != NULL);
	assert((*node)->prev != NULL);
	zn_node_t *head = *node;

	// insert zone apex (no checking)
	assert(zn_find_rrset(*node, LDNS_RR_TYPE_SOA) != NULL);
	if (zds_insert(z->zone, *node) != 0) {
		log_error("Error inserting zone apex to the zone data structure"
			  ".\n");
		return -1;
	}
	uint i = 1;
	uint step = *nodes / 10;
	uint next = step;
	log_info("Inserted: ");

#ifdef ZDB_DEBUG_INSERT_CHECK
	inserted_nodes = (ldns_rdf **)malloc(*nodes * sizeof(ldns_rdf *));
#endif

	do {
		*node = (*node)->next;

#ifdef ZDB_DEBUG_INSERT_CHECK
		inserted_nodes[i - 1] = (*node)->owner;
#endif

		debug_zdb("Inserting node with key %s...\n",
		          ldns_rdf2str((*node)->owner));

		if (zds_insert(z->zone, *node) != 0) {
			log_error("Error filling the zone data structure.\n");
			return -1;
		}
		if (++i == next) {
			log_info("%.0f%% ", 100 *((float)next / *nodes));
			next += step;
		}

		if (zn_find_rrset(*node, LDNS_RR_TYPE_NS) != NULL) {
			// this function will also skip non-authoritative nodes
			zdb_set_delegation_point(node);
		}

		assert((*node)->next != NULL);
	} while ((*node)->next != head);

	log_info("100%% (%d nodes)\n", i);
	return 0;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Inserts the zone into the list of zones in \a database in right order.
 *
 * \param database Zone database to insert the zone into.
 * \param zone Zone to be inserted.
 *
 * The zones are kept in reverse canonical order of their zone names.
 */
static void zdb_insert_zone(zdb_database_t *database, zdb_zone_t *zone)
{
	zdb_zone_t *z = database->head;
	zdb_zone_t *prev = NULL;

	while (z != NULL
	       && ldns_dname_compare(z->zone_name, zone->zone_name) > 0) {
		prev = z;
		z = z->next;
	}

	zone->next = z;
	if (prev == NULL) {
		database->head = zone;
	} else {
		prev->next = zone;
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adjusts the zone structures for faster lookup.
 *
 * \param zone Zone to be adjusted.
 *
 * \retval 0 if successful.
 * \retval -1 if an error occured.
 *
 * \todo Maybe also check for bogus data:
 *        - other RRSets in node with CNAME RR
 *        - more CNAMEs in one node
 *        - other RRSets in delegation point
 */
static int zdb_adjust_zone(zdb_zone_t *zone, uint nodes)
{
	debug_zdb("\nAdjusting zone %s for faster lookup...\n",
	          ldns_rdf2str(zone->zone_name));

	zn_node_t *node = zone->apex;
	debug_zdb("Adjusting zone apex: %s\n", ldns_rdf2str(node->owner));
	zdb_adjust_additional_apex(zone, node);

	uint i = 1;
	uint step = nodes / 10;
	uint next = step;
	log_info("Adjusted nodes: ");

#ifdef ZDB_DEBUG_INSERT_CHECK
	uint dif = 0;
#endif

	while (node->next != zone->apex) {

		node = node->next;

#ifdef ZDB_DEBUG_INSERT_CHECK
		if (inserted_nodes[i - dif - 1] != node->owner) {
			printf("Adjusting node which is not inserted to ZDS: "
			       "%s\n", ldns_rdf2str(node->owner));
			++dif;
		}
#endif

		if (++i == next) {
			log_info("%.0f%% ", 100 *((float)next / nodes));
			next += step;
		}

		debug_zdb("Adjusting node %s\n", ldns_rdf2str(node->owner));
		if (zdb_adjust_cname(zone, node) != 0) {
			// no other records when CNAME
			continue;
		}
		if (zdb_adjust_delegation_point(zone, &node) != 0) {
			// no other records when delegation point
			continue;
		}
		zdb_adjust_additional_all(zone, node);
	}

	log_debug("100%% (%d nodes)\n", i);
	return 0;
}

/*----------------------------------------------------------------------------*/

static void zdb_destroy_zone(zdb_zone_t **zone)
{
	// free the zone data structure but do not delete the zone nodes in it
	zds_destroy(&(*zone)->zone, NULL);
	// free the zone name
	ldns_rdf_deep_free((*zone)->zone_name);

	// free all zone nodes from the list
	zn_node_t *node = (*zone)->apex;
	// disconnect the last item
	node->prev->next = NULL;
	while (node != NULL) {
		zn_node_t *n = node;
		node = node->next;
		// do not bother with adjusting the pointers
		zn_destroy(&n);
	}

	free((*zone));
	*zone = NULL;
}

#ifdef ZDB_DEBUG
/*----------------------------------------------------------------------------*/

static void zdb_print_list(const zdb_zone *zone)
{
	int count = 0;
	debug_zdb("Zone listing in canonical order. Zone '%s'\n\n",
	          ldns_rdf2str(zone->zone_name));
	zn_node *node = zone->apex;
	do {
		debug_zdb("%s\n", ldns_rdf2str(node->owner));
		node = node->next;
		++count;
	} while (node != zone->apex);
	debug_zdb("Nodes: %d\n\n", count);
}
#endif

/*----------------------------------------------------------------------------*/
/* Public functions                                                           */
/*----------------------------------------------------------------------------*/

zdb_database_t *zdb_create()
{
	zdb_database_t *db = malloc(sizeof(zdb_database_t));

	if (db == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	db->head = NULL;
	return db;
}

/*----------------------------------------------------------------------------*/

int zdb_add_zone(zdb_database_t *database, ldns_zone *zone)
{
	zdb_zone_t *new_zone = malloc(sizeof(zdb_zone_t));

	if (new_zone == NULL) {
		ERR_ALLOC_FAILED;
		return -1;
	}

	// get the zone name
	assert(ldns_zone_soa(zone) != NULL);
	new_zone->zone_name =
			ldns_rdf_clone(ldns_rr_owner(ldns_zone_soa(zone)));
	log_info("Adding zone %s to Zone database...\n",
	         ldns_rdf2str(new_zone->zone_name));
	log_info("Creating zone list...\n");
	// create a linked list of zone nodes and get their count
	uint nodes = zdb_create_list(new_zone, zone);
	// get rid of the zone structure (no longer needed)
	ldns_zone_deep_free(zone);

	log_info("Creating empty non-terminal zone nodes...\n");
	// create empty non-terminals
	int nonterm = zdb_add_empty_nonterminals(new_zone);
	if (nonterm < -1) {
		zdb_delete_list_items(new_zone);
		ldns_rdf_deep_free(new_zone->zone_name);
		return -2;
	}

	nodes += nonterm;

#ifdef ZDB_DEBUG
	zdb_print_list(new_zone);
#endif

	log_info("Creating Zone data structure (%d nodes)...\n", nodes);
	// create the zone data structure
	new_zone->zone = zds_create(nodes);
	if (new_zone->zone == NULL) {
		// destroy the list and all its contents
		zdb_delete_list_items(new_zone);
		ldns_rdf_deep_free(new_zone->zone_name);
		return -3;
	}

	// add created nodes to the zone data structure for lookup
	log_info("Inserting zone nodes to the Zone data structure...\n");
	zn_node_t *node = new_zone->apex;
	if (zdb_insert_nodes_into_zds(new_zone, &nodes, &node) != 0) {
		// destroy the rest of the nodes in the list
		// (from node to zone apex)
		while (node != new_zone->apex) {
			zn_node_t *prev = node;
			node = node->next;
			assert(node != NULL);
			zn_destroy(&prev);
		}
		// and destroy the partially filled zone data structure
		zds_destroy(&new_zone->zone, NULL);
		return -4;
	}

	log_info("Adjusting zone (%d nodes)...\n", nodes);
	zdb_adjust_zone(new_zone, nodes);

	log_info("Inserting the zone to the Zone database...\n");
	// Insert into the database on the proper place, i.e. in reverse
	// canonical order of zone names.
	zdb_insert_zone(database, new_zone);

	log_info("Done.\n");

	return 0;
}

/*----------------------------------------------------------------------------*/

int zdb_create_zone(zdb_database_t *database, ldns_rdf *zone_name, uint items)
{
	// add some lock to avoid multiple zone creations?
	// add some check if the zone is not already in db?

	zdb_zone_t *zone = malloc(sizeof(zdb_zone_t));

	if (zone == NULL) {
		ERR_ALLOC_FAILED;
		return -1;
	}

	zone->apex = NULL;
	zone->zone_name = ldns_rdf_clone(zone_name);

	if (zone->zone_name == NULL) {
		ERR_ALLOC_FAILED;
		free(zone);
		return -1;
	}

	zone->zone = zds_create(items);

	if (zone->zone == NULL) {
		log_error("Could not create zone data structure for zone %s\n",
		          ldns_rdf_data(zone_name));
		ldns_rdf_deep_free(zone->zone_name);
		free(zone);
		return -1;
	}

	// insert it into the right place in the database
	zdb_insert_zone(database, zone);

	return 0;
}
/*----------------------------------------------------------------------------*/

int zdb_remove_zone(zdb_database_t *database, ldns_rdf *zone_name)
{
	// add some lock to avoid multiple removals

	zdb_zone_t *z = NULL, *zp = NULL;
	zdb_find_zone(database, zone_name, &z, &zp);

	if (z == NULL) {
		debug_zdb("Zone not found!\n");
		return -1;
	}

	zdb_disconnect_zone(database, z, zp);

	// wait for all readers to finish
	synchronize_rcu();

	zds_destroy(&z->zone, NULL);
	assert(z->zone == NULL);
	ldns_rdf_deep_free(z->zone_name);
	free(z);

	return 0;
}

/*----------------------------------------------------------------------------*/

int zdb_insert_name(zdb_database_t *database, ldns_rdf *zone_name,
                    zn_node_t *node)
{
	zdb_zone_t *z = NULL, *zp = NULL;

	// start of RCU reader critical section (the zone should not be removed)
	rcu_read_lock();
	zdb_find_zone(database, zone_name, &z, &zp);

	if (z == NULL) {
		debug_zdb("Zone not found!\n");
		return -2;
	}
	debug_zdb("Found zone: %.*s\n", ldns_rdf_size(z->zone_name),
	          ldns_rdf_data(z->zone_name));

	int res = zdb_insert_node_to_zone(z, node);

	// end of RCU reader critical section
	rcu_read_unlock();
	return res;
}

/*----------------------------------------------------------------------------*/

const zdb_zone_t *zdb_find_zone_for_name(zdb_database_t *database,
                                       const ldns_rdf *dname)
{
	zdb_zone_t *z = database->head;

	// start of RCU reader critical section
	rcu_read_lock();

	while (z != NULL && ldns_dname_compare(z->zone_name, dname) > 0) {
		z = z->next;
	}
	// now z's zone name is either equal to dname or there is no other zone
	// to search
	if (z != NULL
	    && ldns_dname_compare(z->zone_name, dname) != 0
	    && !ldns_dname_is_subdomain(dname, z->zone_name)) {
		z = NULL;
	}
	// end of RCU reader critical section
	rcu_read_unlock();

	return z;
}

/*----------------------------------------------------------------------------*/

const zn_node_t *zdb_find_name_in_zone(const zdb_zone_t *zone,
                                     const ldns_rdf *dname)
{
	return zdb_find_name_in_zone_nc(zone, dname);
}

/*----------------------------------------------------------------------------*/

void zdb_destroy(zdb_database_t **database)
{
	// add some lock to avoid multiple destroys

	zdb_zone_t *z;

	while ((*database)->head != NULL) {
		z = (*database)->head;
		// disconnect the first zone
		(*database)->head = z->next;
		// wait for all readers to finish
		synchronize_rcu();
		// destroy zone
		zdb_destroy_zone(&z);
	}

	free(*database);
	*database = NULL;
}
