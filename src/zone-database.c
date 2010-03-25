#include "zone-database.h"
#include "common.h"

#include <stdio.h>
#include <assert.h>

//#define ZDB_DEBUG

/*----------------------------------------------------------------------------*/

zdb_database *zdb_create()
{
    zdb_database *db = malloc(sizeof(zdb_database));

    if (db == NULL) {
        fprintf(stderr, "zdb_create(): Allocation failed.\n");
        return NULL;
    }

    db->head = NULL;
    return db;
}

/*----------------------------------------------------------------------------*/

int zdb_create_zone( zdb_database *database, dnss_dname_wire zone_name,
                     uint items )
{
    zdb_zone *zone = malloc(sizeof(zdb_zone));

    if (zone == NULL) {
        fprintf(stderr, "zdb_create_zone(): Allocation failed.\n");
        return -1;
    }

    zone->zone_name = dnss_dname_wire_copy(zone_name);

    if (zone->zone_name == NULL) {
        fprintf(stderr, "zdb_create_zone(): Allocation failed.\n");
        free(zone);
        return -1;
    }

    zone->zone = zds_create(items);

    if (zone->zone == NULL) {
        fprintf(stderr, "zdb_create_zone(): Allocation failed.\n");
        free(zone->zone_name);
        free(zone);
        return -1;
    }

    // insert it to the beginning of the list
    zone->next = database->head;
    database->head = zone;

    return 0;
}

/*----------------------------------------------------------------------------*/

void zdb_find_zone( zdb_database *database, dnss_dname_wire zone_name,
                    zdb_zone **zone, zdb_zone **prev )
{
    *zone = database->head;
    *prev = NULL;

    while ((*zone) != NULL
           && dnss_dname_wire_cmp((*zone)->zone_name, zone_name) != 0) {
        (*prev) = (*zone);
        (*zone) = (*zone)->next;
    }
}

/*----------------------------------------------------------------------------*/

int zdb_remove_zone( zdb_database *database, dnss_dname_wire zone_name )
{
    zdb_zone *z = NULL, *zp = NULL;
    zdb_find_zone(database, zone_name, &z, &zp);

    if (z == NULL) {
#ifdef ZDB_DEBUG
        printf("Zone not found!\n");
#endif
        return -1;
    }

    // disconect the zone from the list
    if (zp != NULL) {
        zp->next = z->next;
    } else {
        database->head = z->next;
    }

    zds_destroy(&z->zone);
    assert(z->zone == NULL);
    dnss_dname_wire_destroy(&z->zone_name);
    assert(z->zone_name == NULL);

    free(z);

    return 0;
}

/*----------------------------------------------------------------------------*/

int zdb_insert_name( zdb_database *database, dnss_dname_wire zone_name,
                     dnss_dname_wire dname, zn_node *node )
{
    zdb_zone *z = NULL, *zp = NULL;
    zdb_find_zone(database, zone_name, &z, &zp);

    if (z == NULL) {
#ifdef ZDB_DEBUG
        printf("Zone not found!\n");
#endif
        return -1;
    }
#ifdef ZDB_DEBUG
    printf("Found zone: ");
    hex_print(z->zone_name, strlen(z->zone_name) + 1);
#endif

    return zds_insert(z->zone, dname, node);
}

/*----------------------------------------------------------------------------*/

zdb_zone *zdb_find_zone_for_name( zdb_database *database,
                                  dnss_dname_wire dname )
{
    zdb_zone *z = database->head, *best = NULL;
    uint most_matched = 0;

    while (z != NULL) {
        uint matched = dnss_dname_wire_match(&dname, &z->zone_name);
        if (matched > most_matched) {
            most_matched = matched;
            best = z;
        }
        z = z->next;
    }

    return best;
}

/*----------------------------------------------------------------------------*/

const zn_node *zdb_find_name( zdb_database *database, dnss_dname_wire dname )
{
    zdb_zone *z = zdb_find_zone_for_name(database, dname);

    if (z == NULL) {
#ifdef ZDB_DEBUG
        printf("Zone not found!\n");
#endif
        return NULL;
    }
#ifdef ZDB_DEBUG
    printf("Found zone: ");
    hex_print(z->zone_name, strlen(z->zone_name) + 1);
#endif

    return zds_find(z->zone, dname);
}

/*----------------------------------------------------------------------------*/

void zdb_destroy( zdb_database **database )
{
    zdb_zone *z = (*database)->head;
    zdb_zone *zp = NULL;

    while (z != NULL) {
        zp = z;
        z = z->next;
        zds_destroy(&zp->zone);
        dnss_dname_wire_destroy(&zp->zone_name);
        free(zp);
    }
}
