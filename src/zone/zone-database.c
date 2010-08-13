#include "zone-database.h"
#include "common.h"

#include <stdio.h>
#include <assert.h>
#include <ldns/ldns.h>
#include <urcu.h>

#include "dns-utils.h"

/*----------------------------------------------------------------------------*/
/* Private functions          					                              */
/*----------------------------------------------------------------------------*/

void zdb_find_zone( zdb_database *database, ldns_rdf *zone_name,
					zdb_zone **zone, zdb_zone **prev )
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

void zdb_disconnect_zone( zdb_database *database, zdb_zone *z, zdb_zone *prev )
{
	// disconect the zone from the list
	if (prev != NULL) {
		prev->next = z->next;
	} else {
		database->head = z->next;
	}
}

/*----------------------------------------------------------------------------*/

int zdb_create_list( zdb_zone *zone, ldns_zone *zone_ldns )
{
	int nodes = 0;

	debug_zdb("Creating linked list of zone nodes...\n");

	// sort the zone so we obtain RRSets
	ldns_zone_sort(zone_ldns);

	debug_zdb("Done.\nProcessing RRSets...\n");
	/*
	 * Walk through all RRs, separate them into zone nodes and RRSets
	 * and create a linked list of nodes in canonical order.
	 *
	 * Some idiot implemented ldns_rr_list_pop_rrset() to return the LAST RRSet
	 * so we will fill the zone from the last node to the first.
	 */
	zn_node *act_node = NULL;
	zn_node *last_node = NULL;
	while (ldns_zone_rr_count(zone_ldns) != 0) {
		ldns_rr_list *rrset = ldns_rr_list_pop_rrset(ldns_zone_rrs(zone_ldns));
		if (rrset == NULL) {
			log_error("Unknown error while processing zone %s.\n",
					 ldns_rdf2str(zone->zone_name));
			// ignore rest of the zone
			break;
		}
		debug_zdb("Processing RRSet with owner %s and type %s.\n",
				  ldns_rdf2str(ldns_rr_list_owner(rrset)),
				  ldns_rr_type2str(ldns_rr_list_type(rrset)));

		if (act_node != NULL &&
				ldns_dname_compare(ldns_rr_list_owner(rrset), act_node->owner)
				== 0) {
			// same owner, insert into the same node
			debug_zdb("Inserting into node with owner %s.\n",
					  ldns_rdf2str(act_node->owner));
			if (zn_add_rrset(act_node, rrset) != 0) {
				log_error("Error while processing zone %s: Cannot add RRSet to"
						"a zone node.\n", ldns_rdf2str(zone->zone_name));
				// ignore rest of the zone
				break;
			}
		} else {
			// create a new node, add the RRSet and connect to the list
			debug_zdb("Creating new node.\n");
			zn_node *new_node = zn_create();
			if (new_node == NULL) {
				log_error("Error while processing zone %s: Cannot create new"
						"zone node.\n", ldns_rdf2str(zone->zone_name));
				// ignore rest of the zone
				break;
			}
			if (zn_add_rrset(new_node, rrset) != 0) {
				log_error("Error while processing zone %s: Cannot add RRSet to"
						"a zone node.\n", ldns_rdf2str(zone->zone_name));
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

	debug_zdb("Processing of RRSets done.\nLast node created (should be zone "
			  "apex): %s, last node of the list: %s.\n",
			  ldns_rdf2str(act_node->owner), ldns_rdf2str(last_node->owner));

	// connect last node to the apex, creating cyclic list
	last_node->next = act_node;
	act_node->prev = last_node;
	// save the zone apex
	zone->apex = act_node;

	debug_zdb("Done.\nAdding SOA RR to the apex node...\n");

	if (zn_add_rr(zone->apex, ldns_rr_clone(ldns_zone_soa(zone_ldns))) != 0
		|| skip_empty(zone->apex->rrsets) == 0) {
		log_error("Error while processing zone %s: Cannot insert SOA RR into "
				"the zone apex node.\n", ldns_rdf2str(zone->zone_name));
		free(zone->apex);
		return nodes;
	}
	++nodes;

	ldns_zone_deep_free(zone_ldns);

	return nodes;
}

/*----------------------------------------------------------------------------*/

void zdb_delete_list_items( zdb_zone *zone )
{
	zn_node *node = zone->apex;
	zn_node *old_node;
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

zn_node *zdb_find_name_in_zone_nc( const zdb_zone *zone, const ldns_rdf *dname )
{
	assert(zone != NULL);
	// start of RCU reader critical section
	rcu_read_lock();

	zn_node *found = zds_find(zone->zone, dname);

	// end of RCU reader critical section
	rcu_read_unlock();

	return found;
}

/*----------------------------------------------------------------------------*/

void zdb_adjust_cname( zdb_zone *zone, zn_node *node )
{
	ldns_rr_list *cname_rrset = zn_find_rrset(node, LDNS_RR_TYPE_CNAME);
	if (cname_rrset != NULL) {
		// retreive the canonic name
		ldns_rdf *cname = ldns_rr_rdf(ldns_rr_list_rr(cname_rrset, 0), 0);
		assert(ldns_rdf_get_type(cname) == LDNS_RDF_TYPE_DNAME);
		node->ref.cname = zdb_find_name_in_zone_nc(zone, cname);
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * @retval 0 if found, -1 or 1 if not found.
 */
int zdb_dname_list_contains( ldns_rdf **list, size_t count, ldns_rdf *name )
{
	int i = 0;
	int found;
	while (i < count && (found = ldns_dname_compare(list[i], name)) != 0) {
		++i;
	}
	return found;
}

/*----------------------------------------------------------------------------*/

ldns_rdf **zdb_extract_ns( ldns_rr_list *ns_rrset )
{
	assert(ldns_is_rrset(ns_rrset));
	ldns_rdf **ns_rrs = malloc(ldns_rr_list_rr_count(ns_rrset)
							   * sizeof(ldns_rr_list *));
	if (ns_rrs == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	for (int i = 0; i < ldns_rr_list_rr_count(ns_rrset); ++i) {
		ns_rrs[i] = ldns_rr_rdf(ldns_rr_list_rr(ns_rrset, i), 0);
		debug_zdb("NS RR #%d: %s\n", i, ldns_rdf2str(ns_rrs[i]));
	}
	return ns_rrs;
}

/*----------------------------------------------------------------------------*/

int zdb_process_nonauth( zn_node *node, ldns_rdf **ns_rrs, size_t ns_count,
						 zn_node *deleg )
{
	zn_set_non_authoritative(node);

	int found = zdb_dname_list_contains(ns_rrs, ns_count, deleg->owner);
	if (found == 0) {
		log_error("Zone contains non-authoritative domain name %s,"
				  " which is not referenced in %s NS records!\n",
				  ldns_rdf2str(node->owner),
				  ldns_rdf2str(deleg->owner));
		free(ns_rrs);
		return -3;
	}

	debug_zdb("Saving glues from node %s\n",
			  ldns_rdf2str(node->owner));
	// push the glues to the delegation point node
	int res = zn_push_glue(
			deleg, zn_find_rrset(node, LDNS_RR_TYPE_A));
	res += zn_push_glue(
			deleg, zn_find_rrset(node, LDNS_RR_TYPE_AAAA));

	if (res != 0) {
		log_error("Error while saving glue records for delegation point"
				  " %s\n", ldns_rdf2str(deleg->owner));
		free(ns_rrs);
		return -4;
	}

	debug_zdb("Saved %d glue records.\n",
			  ldns_rr_list_rr_count(zn_get_glues(deleg)));

	return 0;
}

/*----------------------------------------------------------------------------*/

int zdb_adjust_delegation_point( zn_node **node )
{
	int res = 0;

	ldns_rr_list *ns_rrset = zn_find_rrset(*node, LDNS_RR_TYPE_NS);
	if (ns_rrset != NULL) {
		zn_set_delegation_point(*node);

		debug_zdb("Adjusting delegation point %s\n",
				  ldns_rdf2str((*node)->owner));

		// extract all NS domain names from the node
		ldns_rdf **ns_rrs = zdb_extract_ns(ns_rrset);

		// mark all subsequent nodes which are subdomains of this node's owner
		// as non authoritative and extract glue records from them
		zn_node *deleg = *node;
		(*node) = (*node)->next;

		while (ldns_dname_is_subdomain((*node)->owner, deleg->owner)) {
			if ((res = zdb_process_nonauth(*node, ns_rrs,
							ldns_rr_list_rr_count(ns_rrset), deleg)) != 0) {
				break;
			}
			(*node) = (*node)->next;
		}

		free(ns_rrs);
	}
	return res;
}

/*----------------------------------------------------------------------------*/

void zdb_connect_node( zn_node *next, zn_node *node )
{
	node->prev = next->prev;
	node->next = next;
	next->prev->next = node;
	next->prev = node;
}

/*----------------------------------------------------------------------------*/

int zdb_insert_node_to_zone( zdb_zone *zone, zn_node *node )
{
	zn_node *n = zone->apex;
	int cmp;
	zn_node *deleg = NULL;

	// if there is no zone apex, only node with SOA record may be inserted
	if (zone->apex == NULL) {
		ldns_rr_list *soa_rrset = zn_find_rrset(node, LDNS_RR_TYPE_SOA);
		if (soa_rrset == NULL) {
			log_error("Trying to insert node %s with not SOA record to an empty"
					  "zone!\n", ldns_rdf2str(node->owner));
			return -1;
		}
		if (ldns_rr_list_rr_count(soa_rrset) > 1) {
			log_info("More than one SOA record in node %s, ignoring other.\n",
					 ldns_rdf2str(node->owner));
		}
		if (ldns_dname_compare(zone->zone_name, node->owner) != 0) {
			log_error("Trying to insert node %s with SOA record to zone with"
					  "different name %s.\n", ldns_rdf2str(node->owner),
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
			// all nodes come before the inserted node, we would get into cycle
			break;
		}
	}

	if (cmp == 0) {
		log_error("Trying to insert node with owner %s already present in the"
				  "zone\n", ldns_rdf2str(node->owner));
		return -5;	// node exists in the zone
	}

	int res = 0;
	ldns_rr_list *ns_rrset = NULL;

	// check if the node's owner is not child of delegation point
	if (deleg && ldns_dname_is_subdomain(node->owner, deleg->owner)) {
		// mark the node as non-authoritative and save glue records
		ns_rrset = zn_find_rrset(deleg, LDNS_RR_TYPE_NS);
		assert(ns_rrset != NULL);
		ldns_rdf **ns_rrs = zdb_extract_ns(ns_rrset);
		res = zdb_process_nonauth(node, ns_rrs, ldns_rr_list_rr_count(ns_rrset),
								  deleg);
		free(ns_rrs);
		if (res == 0) {	// if everything went well, connect the node before n
			zdb_connect_node(n, node);
		}
		// do not insert the node into the zone data structure
	} else {
		if ((ns_rrset = zn_find_rrset(node, LDNS_RR_TYPE_NS)) != NULL) {
			// delegation point; must connect to the list and then adjust
			// the following nodes if needed
			zdb_connect_node(n, node);
			zn_node *d = node;
			res = zdb_adjust_delegation_point(&d);
		} else {	// not a non-authoritative node or delegation point
			// check if it has CNAME RR
			zdb_adjust_cname(zone, node);
			zdb_connect_node(n, node);
		}

		// insert the node into the zone data structure
		if (res == 0 && zds_insert(zone->zone, node) != 0) {
			res = -6;
		}
	}

	return res;
}

/*----------------------------------------------------------------------------*/
/*!
 * @brief Inserts all nodes from list starting with @a head to the zone data
 *        structure.
 *
 * @param zone Zone data structure to insert to.
 * @param head In: first item in the list of nodes to be inserted. Out: the same
 *             if successful, the first non-inserted node if a failure occured.
 *
 * @retval 0 On success.
 * @retval -1 On failure. @a head will point to the first item not inserted.
 */
int zdb_insert_nodes_into_zds( zds_zone *zone, zn_node **head )
{
	assert((*head) != NULL);
	assert((*head)->prev != NULL);
	zn_node *node = (*head)->prev;
	do {
		node = node->next;
		if (zn_is_non_authoritative(node)) {
			debug_zdb("Skipping non-authoritative name: %s...\n",
					  ldns_rdf2str(node->owner));
			continue;
		}
		debug_zdb("Inserting node with key %s...\n", ldns_rdf2str(node->owner));
		if (zds_insert(zone, node) != 0) {
			log_error("Error filling the zone data structure.\n");
			return -1;
		}
		debug_zdb("Done.\n");
		assert(node->next != NULL);
	} while (node->next != (*head));

	return 0;
}

/*----------------------------------------------------------------------------*/
/*!
 * @brief Inserts the zone into the list of zones in @a database in right order.
 *
 * @param database Zone database to insert the zone into.
 * @param zone Zone to be inserted.
 *
 * The zones are kept in reverse canonical order of their zone names.
 */
void zdb_insert_zone( zdb_database *database, zdb_zone *zone )
{
	zdb_zone *z = database->head;
	zdb_zone *prev = NULL;

	while (z != NULL && ldns_dname_compare(z->zone_name, zone->zone_name) > 0) {
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
 * @brief Adjusts the zone structures for faster lookup.
 *
 * @param zone Zone to be adjusted.
 *
 * @retval 0 if successful.
 * @retval -1 if an error occured.
 *
 * @todo Maybe also check for bogus data:
 *        - other RRSets in node with CNAME RR
 *        - more CNAMEs in one node
 *        - other RRSets in delegation point
 */
int zdb_adjust_zone( zdb_zone *zone )
{
	debug_zdb("\nAdjusting zone %s for faster lookup...\n",
			  ldns_rdf2str(zone->zone_name));
	// walk through the nodes in the list and check for delegations and CNAMEs
	zn_node *node = zone->apex;
	while (node->next != zone->apex) {
		node = node->next;
		zdb_adjust_cname(zone, node);
		zdb_adjust_delegation_point(&node);
	}

	debug_zdb("\nDone.\n");
	return 0;
}

/*----------------------------------------------------------------------------*/
/* Public functions          					                              */
/*----------------------------------------------------------------------------*/

zdb_database *zdb_create()
{
    zdb_database *db = malloc(sizeof(zdb_database));

    if (db == NULL) {
        ERR_ALLOC_FAILED;
        return NULL;
    }

    db->head = NULL;
    return db;
}

/*----------------------------------------------------------------------------*/

int zdb_add_zone( zdb_database *database, ldns_zone *zone )
{
	zdb_zone *new_zone = malloc(sizeof(zdb_zone));

	if (new_zone == NULL) {
		ERR_ALLOC_FAILED;
		return -1;
	}

	// get the zone name
	assert(ldns_zone_soa(zone) != NULL);
	new_zone->zone_name = ldns_rdf_clone(ldns_rr_owner(ldns_zone_soa(zone)));

	// create a linked list of zone nodes and get their count
	int nodes = zdb_create_list(new_zone, zone);

	// create the zone data structure
	new_zone->zone = zds_create(nodes);
	if (new_zone->zone == NULL) {
		// destroy the list and all its contents
		zdb_delete_list_items(new_zone);
		ldns_rdf_deep_free(new_zone->zone_name);
		return -2;
	}

	zdb_adjust_zone(new_zone);

	// add all created nodes to the zone data structure for lookup
	zn_node *node = new_zone->apex;
	if (zdb_insert_nodes_into_zds(new_zone->zone, &node) != 0) {
		// destroy the rest of the nodes in the list (from node to zone apex)
		while (node != new_zone->apex) {
			zn_node *prev = node;
			node = node->next;
			assert(node != NULL);
			zn_destroy(&prev);
		}
		// and destroy the partially filled zone data structure
		zds_destroy(&new_zone->zone);
		return -3;
	}

	// Insert into the database on the proper place, i.e. in reverse canonical
	// order of zone names.
	zdb_insert_zone(database, new_zone);

	return 0;
}

/*----------------------------------------------------------------------------*/

int zdb_create_zone( zdb_database *database, ldns_rdf *zone_name, uint items )
{
	// add some lock to avoid multiple zone creations?
	// add some check if the zone is not already in db?

    zdb_zone *zone = malloc(sizeof(zdb_zone));

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

int zdb_remove_zone( zdb_database *database, ldns_rdf *zone_name )
{
	// add some lock to avoid multiple removals

    zdb_zone *z = NULL, *zp = NULL;
    zdb_find_zone(database, zone_name, &z, &zp);

    if (z == NULL) {
        debug_zdb("Zone not found!\n");
        return -1;
    }

	zdb_disconnect_zone(database, z, zp);

	// wait for all readers to finish
	synchronize_rcu();

    zds_destroy(&z->zone);
    assert(z->zone == NULL);
	ldns_rdf_deep_free(z->zone_name);
    free(z);

    return 0;
}

/*----------------------------------------------------------------------------*/

int zdb_insert_name( zdb_database *database, ldns_rdf *zone_name,
					 zn_node *node )
{
    zdb_zone *z = NULL, *zp = NULL;

	// start of RCU reader critical section (the zone should not be removed)
	rcu_read_lock();
    zdb_find_zone(database, zone_name, &z, &zp);

    if (z == NULL) {
        debug_zdb("Zone not found!\n");
		return -2;
    }
	debug_zdb("Found zone: %*s\n", ldns_rdf_size(z->zone_name),
			  ldns_rdf_data(z->zone_name));

	int res = zdb_insert_node_to_zone(z, node);

	// end of RCU reader critical section
	rcu_read_unlock();
	return res;
}

/*----------------------------------------------------------------------------*/

const zdb_zone *zdb_find_zone_for_name( zdb_database *database,
										const ldns_rdf *dname )
{
	zdb_zone *z = database->head;

	// start of RCU reader critical section
	rcu_read_lock();

	while (z != NULL && ldns_dname_compare(z->zone_name, dname) > 0) {
		z = z->next;
	}
	// now z's zone name is either equal to dname
	if (ldns_dname_compare(z->zone_name, dname) != 0
		&& !ldns_dname_is_subdomain(dname, z->zone_name)) {
		z = NULL;
	}
	// end of RCU reader critical section
	rcu_read_unlock();

	return z;
}

/*----------------------------------------------------------------------------*/

const zn_node *zdb_find_name_in_zone( const zdb_zone *zone,
									  const ldns_rdf *dname )
{
	return zdb_find_name_in_zone_nc(zone, dname);
}

/*----------------------------------------------------------------------------*/

void zdb_destroy( zdb_database **database )
{
	// add some lock to avoid multiple destroys

	zdb_zone *z;

	while ((*database)->head != NULL) {
		z = (*database)->head;
		// disconnect the first zone
		(*database)->head = z->next;
		// wait for all readers to finish
		synchronize_rcu();
		// destroy zone
		zds_destroy(&z->zone);
		ldns_rdf_deep_free(z->zone_name);
		free(z);
    }
}
