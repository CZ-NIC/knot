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
#include <stdlib.h>
#include <assert.h>

#include <urcu.h>

#include "common/binsearch.h"
#include "libknot/common.h"
#include "libknot/zone/zone.h"
#include "libknot/zone/zonedb.h"
#include "libknot/dname.h"
#include "libknot/util/wire.h"
#include "libknot/zone/node.h"
#include "libknot/util/debug.h"

/* Array sorter generator. */
static int knot_zonedb_cmp(const knot_dname_t* d1, const knot_dname_t *d2);
#define ASORT_PREFIX(X) knot_zonedb_##X
#define ASORT_KEY_TYPE knot_zone_t* 
#define ASORT_LT(x, y) (knot_zonedb_cmp((x)->name, (y)->name) < 0)
#include "common/array-sort.h"

/* Defines */
#define BSEARCH_THRESHOLD 8 /* >= N for which binary search is favoured */

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

/*! \brief Discard zone in zone database. */
static void delete_zone_from_db(knot_zone_t *zone)
{
	synchronize_rcu();
	knot_zone_set_flag(zone, KNOT_ZONE_DISCARDED, 1);
	knot_zone_release(zone);
}

/*! \brief Zone database zone name compare function. */
static int knot_zonedb_cmp(const knot_dname_t* d1, const knot_dname_t *d2)
{
	int a_labels = knot_dname_labels(d1, NULL);
	int b_labels = knot_dname_labels(d2, NULL);
	
	/* Lexicographic order. */
	if (a_labels == b_labels) {
		return knot_dname_cmp(d1, d2);
	}
	
	/* Name with more labels goes first. */
	return b_labels - a_labels;
}

/*! \brief Find an equal name in sorted array (binary search). */
#define ZONEDB_LEQ(arr,i,x) (knot_zonedb_cmp(((arr)[i])->name, (x)) <= 0)
static long knot_zonedb_binsearch(knot_zone_t **arr, unsigned count,
                                  const knot_dname_t *name)
{
	int k = BIN_SEARCH_FIRST_GE_CMP(arr, count, ZONEDB_LEQ, name) - 1;
	if (k > -1 && knot_dname_is_equal(arr[k]->name, name)) {
			return k;
	}

	return -1;

}

/*! \brief Find an equal name in an array (linear search).
 *  \note Linear search uses simple name equality test which could be
 *        faster than canonical compare and therefore more efficient for
 *        smaller arrays.
 */
static long knot_zonedb_linear_search(knot_zone_t **arr, unsigned count,
                               const knot_dname_t *name) {
	for (unsigned i = 0; i < count; ++i) {
		if (knot_dname_is_equal(arr[i]->name, name)) {
			return i;
		}
	}
	return -1;
}

/*! \brief Zone array search. */
static long knot_zonedb_array_search(knot_zone_t **arr, unsigned count,
                               const knot_dname_t *name)
{
	if (count < BSEARCH_THRESHOLD) {
		return knot_zonedb_linear_search(arr, count, name);
	} else {
		return knot_zonedb_binsearch(arr, count, name);
	}
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_zonedb_t *knot_zonedb_new(unsigned size)
{
	knot_zonedb_t *db = malloc(sizeof(knot_zonedb_t));
	CHECK_ALLOC_LOG(db, NULL);

	memset(db, 0, sizeof(knot_zonedb_t));
	db->reserved = size;
	db->array = malloc(size * sizeof(knot_zone_t*));
	if (db->array == NULL) {
		free(db);
		return NULL;
	}

	return db;
}

/*----------------------------------------------------------------------------*/

int knot_zonedb_add_zone(knot_zonedb_t *db, knot_zone_t *zone)
{
	if (db == NULL || zone == NULL) {
		return KNOT_EINVAL;
	}

	/*! \todo Why is this check here? */
	int ret = KNOT_EOK;
	if (knot_zone_contents(zone)) {
		ret = knot_zone_contents_load_nsec3param(
				knot_zone_get_contents(zone));
		if (ret != KNOT_EOK) {
			log_zone_error("NSEC3 signed zone has invalid or no "
			               "NSEC3PARAM record.\n");
			return ret;
		}
	}

	/* Invalidate search index. */
	db->stack_height = 0;

	/* Create new record. */
	assert(db->count < db->reserved); /* Should be already checked. */
	db->array[db->count++] = zone;

	return ret;
}

/*----------------------------------------------------------------------------*/

knot_zone_t *knot_zonedb_remove_zone(knot_zonedb_t *db,
                                     const knot_dname_t *zone_name)
{
	if (db == NULL || zone_name == NULL) {
		return NULL;
	}
	
	/* Find the possible zone to remove. */
	int pos = knot_zonedb_array_search(db->array, db->count, zone_name);
	if (pos < 0) {
		return NULL;
	}

	/* Invalidate search index. */
	db->stack_height = 0;
	
	/* Move rest of the array to not break the ordering. */
	knot_zone_t *removed_zone = db->array[pos];
	unsigned remainder = (db->count - (pos + 1)) * sizeof(knot_zone_t*);
	memmove(db->array + pos, db->array + pos + 1, remainder);
	--db->count;
	
	return removed_zone;
}

/*----------------------------------------------------------------------------*/

int knot_zonedb_build_index(knot_zonedb_t *db)
{
	if (!db) {
		return KNOT_EINVAL;
	}

	/* First, sort all zones based on the label count first and lexicographic
	 * order second. The name with most labels goes first. 
	 * i.e. {a, a.b, a.c, b } -> {a.b, a.c, a, b} */
	knot_zonedb_sort(db->array, db->count);
	
	/* Scan the array and group names with the same label count together. */
	int prev_label_count = -1;
	int current_label_count = -1;
	knot_zone_t **endp = db->array + db->count;
	knot_zonedb_stack_t *stack_top = db->stack - 1; /* Before actual stack. */
	db->stack_height = 0;
	
	for (knot_zone_t **zone = db->array; zone != endp; ++zone) {
		/* Insert into current label count group. */
		current_label_count = knot_dname_labels((*zone)->name, NULL);
		if (current_label_count == prev_label_count) {
			++stack_top->count;
			continue;
		}
		
		/* Begin new label count group. */
		++stack_top;
		++db->stack_height;
		stack_top->count = 1;
		stack_top->labels = current_label_count;
		stack_top->array = zone;
		prev_label_count = current_label_count;
		
	}
	
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

knot_zone_t *knot_zonedb_find_zone(knot_zonedb_t *db,
                                       const knot_dname_t *zone_name)
{
	if (!db || !zone_name) {
		return NULL;
	}

	int pos = knot_zonedb_array_search(db->array, db->count, zone_name);
	if (pos < 0) {
		return NULL;
	}

	return db->array[pos];
}

/*----------------------------------------------------------------------------*/

knot_zone_t *knot_zonedb_find_zone_for_name(knot_zonedb_t *db,
                                            const knot_dname_t *dname)
{
	int zone_labels = knot_dname_labels(dname, NULL);
	if (db == NULL || zone_labels < 0) {
		return NULL;
	}
	
	/* Walk down the stack, from the most labels to least. */
	knot_zonedb_stack_t *sp = db->stack, *endp = db->stack + db->stack_height;
	for (; sp != endp; ++sp) {
		/* Inspect only zones with <= labels than zone_labels. */
		if (sp->labels > zone_labels) {
			continue;
		}

		/* Skip non-matched labels. */
		while (sp->labels < zone_labels) {
			dname = knot_wire_next_label(dname, NULL);
			--zone_labels;
		}

		/* Possible candidate, search the array. */
		int k = knot_zonedb_array_search(sp->array, sp->count, dname);
		if (k > -1) {
			return sp->array[k];
		}
	}

	return NULL;
}

/*----------------------------------------------------------------------------*/

knot_zone_contents_t *knot_zonedb_expire_zone(knot_zonedb_t *db,
                                              const knot_dname_t *zone_name)
{
	
	if (db == NULL || zone_name == NULL) {
		return NULL;
	}

	// Remove the contents from the zone, but keep the zone in the zonedb.

	knot_zone_t *zone = knot_zonedb_find_zone(db, zone_name);
	if (zone == NULL) {
		return NULL;
	}

	return knot_zone_switch_contents(zone, NULL);
}

/*----------------------------------------------------------------------------*/

size_t knot_zonedb_zone_count(const knot_zonedb_t *db)
{
	return db->count;
}

/*----------------------------------------------------------------------------*/

const knot_zone_t **knot_zonedb_zones(const knot_zonedb_t *db)
{
	if (db == NULL) {
		return NULL;
	}
	
	return (const knot_zone_t **)db->array;
}

/*----------------------------------------------------------------------------*/

void knot_zonedb_free(knot_zonedb_t **db)
{
	free((*db)->array);
	free(*db);
	*db = NULL;
}

/*----------------------------------------------------------------------------*/

void knot_zonedb_deep_free(knot_zonedb_t **db)
{
	dbg_zonedb("Deleting zone db (%p).\n", *db);
	for (unsigned i = 0; i < (*db)->count; ++i) {
		delete_zone_from_db((*db)->array[i]);
	}

	knot_zonedb_free(db);
}
