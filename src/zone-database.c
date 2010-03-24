#include "zone-database.h"

#include <stdio.h>
#include <assert.h>

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
        printf("Zone not found!\n");
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
        printf("Zone not found!\n");
        return -1;
    }

    return zds_insert(z->zone, dname, node);
}

/*----------------------------------------------------------------------------*/

const zn_node *zdb_find_name( zdb_database *database, dnss_dname_wire dname )
{
    zdb_zone *z = NULL, *zp = NULL;
    zdb_find_zone(database, dname, &z, &zp);

    if (z == NULL) {
        printf("Zone not found!\n");
        return NULL;
    }

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
