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

zdb_zone *zdb_find_zone_for_name( zdb_database *database, ldns_rdf *dname )
{
	zdb_zone *z = database->head, *best = NULL;
	uint most_matched = 0;

	// start of RCU reader critical section
	// maybe not needed, called only from zdb_find_name()
	rcu_read_lock();

	while (z != NULL) {
		uint matched = dnsu_subdomain_labels(dname, z->zone_name);
		if (matched > most_matched) {
			most_matched = matched;
			best = z;
		}
		z = z->next;
	}

	// end of RCU reader critical section
	rcu_read_unlock();

	return best;
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

	// zone created, insert into the database
	new_zone->next = database->head;
	database->head = new_zone;

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

    // insert it to the beginning of the list
    zone->next = database->head;
    database->head = zone;

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

	int res = zds_insert(z->zone, node);

	// end of RCU reader critical section
	rcu_read_unlock();
	return res;
}

/*----------------------------------------------------------------------------*/

const zn_node *zdb_find_name( zdb_database *database, ldns_rdf *dname )
{
	// start of RCU reader critical section
	rcu_read_lock();

    zdb_zone *z = zdb_find_zone_for_name(database, dname);

    if (z == NULL) {
        debug_zdb("Zone not found!\n");
        return NULL;
    }

	debug_zdb("Found zone: %*s\n", ldns_rdf_size(z->zone_name),
			  ldns_rdf_data(z->zone_name));

	const zn_node *found = zds_find(z->zone, dname);

	// end of RCU reader critical section
	rcu_read_unlock();

	return found;
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
