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
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>	// tolower()

#include "common.h"
#include "util/error.h"
#include "dname.h"
#include "consts.h"
#include "util/tolower.h"
#include "util/debug.h"
#include "util/utils.h"
#include "util/wire.h"

/*! \todo dnames allocated from TLS cache will be discarded after thread
 *        termination. This shouldn't happpen.
 */
#if 0
/*
 * Memory cache.
 */
#include "common/slab/slab.h"
#include <stdio.h>
#include <pthread.h>

/*! \brief TLS unique key for each thread cache. */
static pthread_key_t dname_ckey;
static pthread_once_t dname_once = PTHREAD_ONCE_INIT;

/*! \brief Destroy thread dname cache (automatically called). */
static void knot_dname_cache_free(void *ptr)
{
	slab_cache_t* cache = (slab_cache_t*)ptr;
	if (cache) {
		slab_cache_destroy(cache);
		free(cache);
	}
}

/*! \brief Cleanup for main() TLS. */
static void knot_dname_cache_main_free()
{
	knot_dname_cache_free(pthread_getspecific(dname_ckey));
}

static void knot_dname_cache_init()
{
	(void) pthread_key_create(&dname_ckey, knot_dname_cache_free);
	atexit(knot_dname_cache_main_free); // Main thread cleanup
}
#endif

/*!
 * \brief Allocate item from thread cache.
 * \retval Allocated dname instance on success.
 * \retval NULL on error.
 */
static knot_dname_t* knot_dname_alloc()
{
	return malloc(sizeof(knot_dname_t));

	/*! \todo dnames allocated from TLS cache will be discarded after thread
	 *        termination. This shouldn't happpen.
	 */
#if 0
	/* Initialize dname cache TLS key. */
	(void)pthread_once(&dname_once, knot_dname_cache_init);

	/* Create cache if not exists. */
	slab_cache_t* cache = pthread_getspecific(dname_ckey);
	if (unlikely(!cache)) {
		cache = malloc(sizeof(slab_cache_t));
		if (!cache) {
			return 0;
		}

		/* Initialize cache. */
		slab_cache_init(cache, sizeof(knot_dname_t));
		(void)pthread_setspecific(dname_ckey, cache);
	}

	return slab_cache_alloc(cache);
#endif
}

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static int knot_dname_set(knot_dname_t *dname, uint8_t *wire,
                            short wire_size, const uint8_t *labels,
                            short label_count)
{
	dname->name = wire;
	dname->size = wire_size;
	dname->label_count = label_count;

	assert(label_count >= 0);

	dname->labels = (uint8_t *)malloc(dname->label_count * sizeof(uint8_t));
	CHECK_ALLOC_LOG(dname->labels, -1);
	memcpy(dname->labels, labels, dname->label_count);

	return 0;
}

/*!
 * \brief Converts domain name from string representation to wire format.
 *
 * This function also allocates the space for the wire format.
 *
 * \param name Domain name in string representation (presentation format).
 * \param size Size of the given domain name in characters (not counting the
 *             terminating 0 character.
 * \param dname Domain name where to store the wire format.
 *
 * \return Size of the wire format of the domain name in octets. If 0, no
 *         space has been allocated.
 *
 * \todo handle \X and \DDD (RFC 1035 5.1) or it can be handled by the parser?
 */
static int knot_dname_str_to_wire(const char *name, uint size,
                                    knot_dname_t *dname)
{
	if (size > KNOT_MAX_DNAME_LENGTH) {
		return -1;
	}

	uint wire_size;
	int root = (*name == '.' && size == 1);
	// root => different size
	if (root) {
		wire_size = 1;
	} else {
		wire_size = size + 1;
	}

	uint8_t *wire;
	uint8_t labels[KNOT_MAX_DNAME_LABELS];
	short label_count = 0;

	// signed / unsigned issues??
	wire = (uint8_t *)malloc(wire_size * sizeof(uint8_t));
	if (wire == NULL) {
		return -1;
	}

	dbg_dname_verb("Allocated space for wire format of dname: %p\n", wire);

	if (root) {
		*wire = '\0';
		label_count = 0;
		return knot_dname_set(dname, wire, wire_size, labels,
		                        label_count);
	}

	const uint8_t *ch = (const uint8_t *)name;
	uint8_t *label_start = wire;
	uint8_t *w = wire + 1;
	uint8_t label_length = 0;

	while (ch - (const uint8_t *)name < size) {
		assert(w - wire - 1 == ch - (const uint8_t *)name);

		if (*ch == '.') {
			dbg_dname_detail("Position %zd (%p): "
			                 "label length: %u\n",
			                 label_start - wire,
			                 label_start, label_length);
			*label_start = label_length;
			labels[label_count++] = label_start - wire;
			label_start = w;
			label_length = 0;
		} else {
			assert(w - wire < wire_size);
			dbg_dname_detail("Position %zd (%p): character: %c\n",
			                 w - wire, w, *ch);
			*w = *ch;
			++label_length;
		}

		++w;
		++ch;
		assert(ch >= (const uint8_t *)name);
	}

	--ch;
	if (*ch == '.') { // put 0 for root label if the name ended with .
		--w;
		dbg_dname_detail("Position %zd (%p): character: (null)\n",
		                 w - wire, w);
		*w = 0;
	} else { // otherwise we did not save the last label length
		dbg_dname_detail("Position %zd (%p): label length: %u\n",
		                 label_start - wire,
		                 label_start, label_length);
		*label_start = label_length;
		labels[label_count++] = label_start - wire;
	}

	return knot_dname_set(dname, wire, wire_size, labels, label_count);
}

/*----------------------------------------------------------------------------*/

static inline int knot_dname_tolower(uint8_t c, int cs)
{
	return (cs) ? c : knot_tolower(c);
}

/*----------------------------------------------------------------------------*/

static int knot_dname_compare_labels(const uint8_t *label1,
                                       const uint8_t *label2, int cs)
{
	const uint8_t *pos1 = label1;
	const uint8_t *pos2 = label2;

	int label_length = (*pos1 < *pos2) ? *pos1 : *pos2;
	int i = 0;

	while (i < label_length
	       && knot_dname_tolower(*(++pos1), cs)
	          == knot_dname_tolower(*(++pos2), cs)) {
		++i;
	}

	if (i < label_length) {  // difference in some octet
		return (knot_dname_tolower(*pos1, cs)
		        - knot_dname_tolower(*pos2, cs));
	}

	return (label1[0] - label2[0]);
}

/*----------------------------------------------------------------------------*/

static int knot_dname_find_labels(knot_dname_t *dname, int alloc)
{
	const uint8_t *name = dname->name;
	const uint8_t *pos = name;
	const uint size = dname->size;

	uint8_t labels[KNOT_MAX_DNAME_LABELS];
	short label_count = 0;

	while (pos - name < size && *pos != '\0' && label_count < KNOT_MAX_DNAME_LABELS ) {
		labels[label_count++] = pos - name;
		pos += *pos + 1;
	}

	// TODO: how to check if the domain name has right format?
	if (label_count == KNOT_MAX_DNAME_LABELS) {
		dbg_dname("Wrong wire format of domain name!\n");
		dbg_dname("Too many labels: %s\n", name);
		return -1;
	}

	if (pos - name > size || *pos != '\0' ) {
		dbg_dname("Wrong wire format of domain name!\n");
		dbg_dname("Position: %d, character: %d, expected size: %d\n",
		          pos - name, *pos, size);
		return -1;
	}

	if (alloc) {
		dname->labels
			= (uint8_t *)malloc(label_count * sizeof(uint8_t));
		CHECK_ALLOC_LOG(dname->labels, KNOT_ENOMEM);
	}

	memcpy(dname->labels, labels, label_count);
	dname->label_count = label_count;

	return 0;
}

/*----------------------------------------------------------------------------*/

static int knot_dname_cmp(const knot_dname_t *d1, const knot_dname_t *d2,
                            int cs)
{
dbg_dname_exec_verb(
	char *name1 = knot_dname_to_str(d1);
	char *name2 = knot_dname_to_str(d2);

	dbg_dname_verb("Comparing dnames %s and %s\n", name1, name2);

	for (int i = 0; i < strlen(name1); ++i) {
		name1[i] = knot_tolower(name1[i]);
	}
	for (int i = 0; i < strlen(name2); ++i) {
		name2[i] = knot_tolower(name2[i]);
	}

	dbg_dname_detail("After to lower: %s and %s\n", name1, name2);

	free(name1);
	free(name2);
);

	if (!cs && d1 == d2) {
		return 0;
	}

	int l1 = d1->label_count;
	int l2 = d2->label_count;
	dbg_dname_detail("Label counts: %d and %d\n", l1, l2);
	assert(l1 >= 0);
	assert(l2 >= 0);

	// compare labels from last to first
	while (l1 > 0 && l2 > 0) {
		dbg_dname_detail("Comparing labels %d and %d\n",
		                 l1 - 1, l2 - 1);
		dbg_dname_detail(" at offsets: %d and %d\n",
		                 d1->labels[l1 - 1], d2->labels[l2 - 1]);
		int res = knot_dname_compare_labels(
		                   &d1->name[d1->labels[--l1]],
		                   &d2->name[d2->labels[--l2]],
		                   cs);
		if (res != 0) {
			return res;
		} // otherwise the labels are identical, continue with previous
	}

	// if all labels matched, the shorter name is first
	if (l1 == 0 && l2 > 0) {
		return -1;
	}

	if (l1 > 0 && l2 == 0) {
		return 1;
	}

	return 0;
}

/*! \brief Destructor for reference counter. */
static void knot_dname_dtor(struct ref_t *p)
{
	knot_dname_t *dname = (knot_dname_t *)p;
	knot_dname_free(&dname);
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_new()
{
	knot_dname_t *dname = knot_dname_alloc();
	dname->name = NULL;
	dname->size = 0;
	dname->node = NULL;
	dname->labels = NULL;
	dname->label_count = -1;
	dname->id = 0;

	/* Initialize reference counting. */
	ref_init(&dname->ref, knot_dname_dtor);

	/* Set reference counter to 1, caller should release it after use. */
	knot_dname_retain(dname);

	return dname;
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_new_from_str(const char *name, uint size,
                                          struct knot_node *node)
{
	if (name == NULL || size == 0) {
		return NULL;
	}

//	knot_dname_t *dname = knot_dname_alloc();
	knot_dname_t *dname = knot_dname_new();

	if (dname == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	/*! \todo The function should return error codes. */
	int ret = knot_dname_str_to_wire(name, size, dname);
	if (ret != 0) {
		dbg_dname("Failed to create domain name from string.\n");
		knot_dname_free(&dname);
		return NULL;
	}

dbg_dname_exec_verb(
	dbg_dname_verb("Created dname with size: %d\n", dname->size);
	dbg_dname_verb("Label offsets: ");
	for (int i = 0; i < dname->label_count; ++i) {
		dbg_dname_verb("%d, ", dname->labels[i]);
	}
	dbg_dname_verb("\n");
);

	if (dname->size <= 0) {
		dbg_dname("Could not parse domain name "
		          "from string: '%.*s'\n", size, name);
	}
	assert(dname->name != NULL);

	dname->node = node;
	dname->id = 0;

	return dname;
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_new_from_wire(const uint8_t *name, uint size,
                                           struct knot_node *node)
{
	if (name == NULL) { /* && size != 0) { !OS: Nerozumjaju */
		dbg_dname("No name given!\n");
		return NULL;
	}

	knot_dname_t *dname = knot_dname_new();

	if (dname == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	dname->name = (uint8_t *)malloc(size * sizeof(uint8_t));
	if (dname->name == NULL) {
		ERR_ALLOC_FAILED;
		knot_dname_free(&dname);
		return NULL;
	}

	memcpy(dname->name, name, size);
	dname->size = size;

	if (knot_dname_find_labels(dname, 1) != 0) {
		dbg_dname("Could not find labels in dname (new from wire).\n");
		knot_dname_free(&dname);
		return NULL;
	}

	dname->node = node;
	dname->id = 0;

	return dname;
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_parse_from_wire(const uint8_t *wire,
                                             size_t *pos, size_t size,
                                             knot_node_t *node)
{
	uint8_t name[KNOT_MAX_DNAME_LENGTH];
	uint8_t labels[KNOT_MAX_DNAME_LABELS];

	short l = 0;
	size_t i = 0, p = *pos;
	int pointer_used = 0;

	while (p < size && wire[p] != 0) {
		/* Check maximum number of labels (may overflow). */
		if (l == KNOT_MAX_DNAME_LABELS) {
			return NULL;
		}
		labels[l] = i;
		dbg_dname_detail("Next label (%d.) position: %zu\n", l, i);

		if (knot_wire_is_pointer(wire + p)) {
			// pointer.
			size_t ptr = knot_wire_get_pointer(wire + p);

			/* Check that the pointer points backwards
			 * otherwise it could result in infinite loop
			 */
			if (ptr >= p) {
				return NULL;
			}

			p = ptr;

			if (!pointer_used) {
				*pos += 2;
				pointer_used = 1;
			}
			if (p >= size) {
				return NULL;
			}
		} else {
			// label; first byte is label length
			uint8_t length = *(wire + p);
			/* Check label length (maximum 63 bytes allowed). */
			if (length > 63) {
				return NULL;
			}
			/* Check if there's enough space. */
			if (i + length + 2 > KNOT_MAX_DNAME_LENGTH) {
				return NULL;
			}
			//printf("Label %d (max %d), length: %u.\n", l, KNOT_MAX_DNAME_LABELS, length);
			memcpy(name + i, wire + p, length + 1);
			p += length + 1;
			i += length + 1;
			if (!pointer_used) {
				*pos += length + 1;
			}
			++l;
		}
	}
	if (p >= size) {
		return NULL;
	}

	name[i] = 0;
	if (!pointer_used) {
		*pos += 1;
	}

	knot_dname_t *dname = knot_dname_new();

	if (dname == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	dname->name = (uint8_t *)malloc((i + 1) * sizeof(uint8_t));
	if (dname->name == NULL) {
		ERR_ALLOC_FAILED;
		knot_dname_free(&dname);
		return NULL;
	}

	memcpy(dname->name, name, i + 1);
	dname->size = i + 1;

	/*! \todo Why l + 1 ?? */
	dname->labels = (uint8_t *)malloc((l + 1) * sizeof(uint8_t));
	if (dname->labels == NULL) {
		ERR_ALLOC_FAILED;
		knot_dname_free(&dname);
		return NULL;
	}
	memcpy(dname->labels, labels, l + 1);

	dname->label_count = l;

	dname->node = node;

	return dname;
}

/*----------------------------------------------------------------------------*/

int knot_dname_from_wire(const uint8_t *name, uint size,
                           struct knot_node *node, knot_dname_t *target)
{
	if (name == NULL || target == NULL) {
		return KNOT_EBADARG;
	}

	memcpy(target->name, name, size);
	target->size = size;
	target->node = node;
	target->id = 0;

	return knot_dname_find_labels(target, 0);
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_deep_copy(const knot_dname_t *dname)
{
	//return knot_dname_new_from_wire(dname->name, dname->size, dname->node);
	/* dname_new_from_wire() does not accept non-FQDN dnames, so we
	 * do the copy by hand. It's faster anyway */

	if (dname == NULL) {
		return NULL;
	}

	knot_dname_t *copy = knot_dname_new();
	CHECK_ALLOC(copy, NULL);

	copy->labels = (uint8_t *)(malloc(dname->label_count));

	if (copy->labels == NULL) {
		knot_dname_free(&copy);
		return NULL;
	}

	copy->name = (uint8_t *)(malloc(dname->size));
	if (copy->name == NULL) {
		knot_dname_free(&copy);
		return NULL;
	}

	memcpy(copy->labels, dname->labels, dname->label_count);
	copy->label_count = dname->label_count;

	memcpy(copy->name, dname->name, dname->size);
	copy->size = dname->size;

	copy->node = dname->node;

	return copy;
}

/*----------------------------------------------------------------------------*/

char *knot_dname_to_str(const knot_dname_t *dname)
{
	if (!dname || dname->size == 0) {
		return 0;
	}

	char *name;

	// root => special treatment
	if (dname->size == 1) {
		assert(dname->name[0] == 0);
		name = (char *)malloc(2 * sizeof(char));
		name[0] = '.';
		name[1] = '\0';
		return name;
	}

	name = (char *)malloc(dname->size * sizeof(char));
	if (name == NULL) {
		return NULL;
	}

	uint8_t *w = dname->name;
	char *ch = name;
	int i = 0;

	do {
		assert(*w != 0);
		int label_size = *(w++);
		// copy the label
		memcpy(ch, w, label_size);
		i += label_size;
		ch += label_size;
		w += label_size;
		if (w - dname->name < dname->size) { // another label following
			*(ch++) = '.';
			++i;
		}
	} while (i < dname->size - 1);

	*ch = 0;
	assert(ch - name == dname->size - 1);

	return name;
}

/*----------------------------------------------------------------------------*/

int knot_dname_to_lower(knot_dname_t *dname)
{
	if (dname == NULL) {
		return KNOT_EBADARG;
	}
	
	for (int i = 0; i < dname->size; ++i) {
		dname->name[i] = knot_tolower(dname->name[i]);
	}
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_dname_to_lower_copy(const knot_dname_t *dname, char *name, 
                             size_t size)
{
	if (dname == NULL || name == NULL || size < dname->size) {
		return KNOT_EBADARG;
	}
	
	for (int i = 0; i < dname->size; ++i) {
		name[i] = knot_tolower(dname->name[i]);
	}
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

const uint8_t *knot_dname_name(const knot_dname_t *dname)
{
	return dname->name;
}

/*----------------------------------------------------------------------------*/

uint knot_dname_size(const knot_dname_t *dname)
{
	return dname->size;
}

/*----------------------------------------------------------------------------*/

unsigned int knot_dname_id(const knot_dname_t *dname)
{
	return dname->id;
}

/*----------------------------------------------------------------------------*/

uint8_t knot_dname_size_part(const knot_dname_t *dname, int labels)
{
	assert(labels < dname->label_count);
	assert(dname->labels != NULL);
	return (dname->labels[labels]);
}

/*----------------------------------------------------------------------------*/

const struct knot_node *knot_dname_node(const knot_dname_t *dname)

{
	return knot_dname_get_node(dname);
}

/*----------------------------------------------------------------------------*/

struct knot_node *knot_dname_get_node(const knot_dname_t *dname)
{
	if (dname == NULL) {
		return NULL;
	}

	knot_node_t *node = dname->node;

	/*
	 * If the zone contains new zone contents (during an update), we should
	 * return new node. Check if the node has the new node set. If it does
	 * not, it means this is already the new node. If it has, return the
	 * new node. If the new node is empty, return NULL, as the node will be
	 * deleted later.
	 */
dbg_dname_exec_detail(
	dbg_dname_detail("Getting node from dname: node: %p, zone: %p\n", node,
			 knot_node_zone(node));
	if (node != NULL && knot_node_zone(node) != NULL
	    && knot_zone_contents(knot_node_zone(node)) != NULL) {
		dbg_dname_detail("zone contents gen: %d, new node of the node: "
			 "%p, is empty: %d\n",
			 knot_zone_contents_gen_is_new(knot_zone_contents(
							 knot_node_zone(node))),
			 knot_node_new_node(node),
			 knot_node_new_node(node)
			       ? knot_node_is_empty(knot_node_new_node(node))
			       : -1);
	}
);
	
	if (node && knot_node_zone(node)
	    && knot_zone_contents(knot_node_zone(node))
	    && knot_zone_contents_gen_is_new(knot_zone_contents(
		knot_node_zone(node)))
	    && knot_node_new_node(node) != NULL) {
		node = knot_node_get_new_node(node);
		if (knot_node_is_empty(node)) {
			node = NULL;
		}
	}

	return node;
}

/*----------------------------------------------------------------------------*/

void knot_dname_set_node(knot_dname_t *dname, knot_node_t *node)
{
	dname->node = node;
}

/*----------------------------------------------------------------------------*/

void knot_dname_update_node(knot_dname_t *dname)
{
dbg_dname_exec_detail(
	char *name = knot_dname_to_str(dname);
	dbg_dname_detail("Updating node pointer in dname %p: %s. Before: %p\n",
	                 dname, name, dname->node);
	free(name);
);

	knot_node_update_ref(&dname->node);
	dbg_dname_detail("After: %p\n", dname->node);

	if (knot_node_is_empty(dname->node)) {
		dbg_dname_detail("Node is empty, setting to NULL.\n");
		dname->node = NULL;
	}
}

/*----------------------------------------------------------------------------*/

int knot_dname_is_fqdn(const knot_dname_t *dname)
{
	return (dname->name[dname->size - 1] == '\0');
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_left_chop(const knot_dname_t *dname)
{
	if (dname == NULL ||
		/* Root domain. */
		((knot_dname_label_count(dname) == 0) &&
		 (knot_dname_is_fqdn(dname)))) {
		return NULL;
	}
	
	knot_dname_t *parent = knot_dname_new();
	if (parent == NULL) {
		return NULL;
	}
	
	// last label, the result should be root domain
	if (dname->label_count == 1) {
		dbg_dname_verb("Chopping last label.\n");
		parent->label_count = 0;
		
		parent->name = (uint8_t *)malloc(1);
		if (parent->name == NULL) {
			ERR_ALLOC_FAILED;
			knot_dname_free(&parent);
			return NULL;
		}
		
		*parent->name = 0;
		
		parent->size = 1;
		
		return parent;
	}

	parent->size = dname->size - dname->name[0] - 1;
	parent->name = (uint8_t *)malloc(parent->size);
	if (parent->name == NULL) {
		ERR_ALLOC_FAILED;
		knot_dname_free(&parent);
		return NULL;
	}

	parent->labels = (uint8_t *)malloc(dname->label_count - 1);
	if (parent->labels == NULL) {
		ERR_ALLOC_FAILED;
		free(parent->name);
		knot_dname_free(&parent);
		return NULL;
	}

	memcpy(parent->name, &dname->name[dname->name[0] + 1], parent->size);
	

	short first_label_length = dname->labels[1];

	for (int i = 0; i < dname->label_count - 1; ++i) {
		parent->labels[i] = dname->labels[i + 1] - first_label_length;
	}
	parent->label_count = dname->label_count - 1;

	return parent;
}

/*----------------------------------------------------------------------------*/

void knot_dname_left_chop_no_copy(knot_dname_t *dname)
{
	// copy the name
	if (dname->label_count > 1) {
		short first_label_length = dname->labels[1];

		memmove(dname->name, &dname->name[dname->labels[1]],
			dname->size - first_label_length);
		// adjust labels
		for (int i = 0; i < dname->label_count - 1; ++i) {
			dname->labels[i] = dname->labels[i + 1]
			                   - first_label_length;
		}
		dname->label_count = dname->label_count - 1;
		dname->size -= first_label_length;
	} else {
		dname->name[0] = '\0';
		dname->size = 1;
		dname->label_count = 0;
	}
}

/*----------------------------------------------------------------------------*/

int knot_dname_is_subdomain(const knot_dname_t *sub,
                              const knot_dname_t *domain)
{
dbg_dname_exec_verb(
	char *name1 = knot_dname_to_str(sub);
	char *name2 = knot_dname_to_str(domain);

	dbg_dname_verb("Checking if %s is subdomain of %s\n", name1, name2);
	free(name1);
	free(name2);
);

	if (sub == domain) {
		return 0;
	}

	// if one of the names is fqdn and the other is not
	if ((sub->name[sub->size - 1] == '\0'
	      && domain->name[domain->size - 1] != '\0')
	    || (sub->name[sub->size - 1] != '\0'
		&& domain->name[domain->size - 1] == '\0')) {
		return 0;
	}

	int l1 = sub->label_count;
	int l2 = domain->label_count;

	dbg_dname_detail("Label counts: %d and %d\n", l1, l2);

	if (l1 <= l2) {  // if sub does not have more labes than domain
		return 0;  // it is not its subdomain
	}

	// compare labels from last to first
	while (l1 > 0 && l2 > 0) {
		dbg_dname_detail("Comparing labels %d and %d\n",
		                 l1 - 1, l2 - 1);
		dbg_dname_detail(" at offsets: %d and %d\n",
		                 sub->labels[l1 - 1], domain->labels[l2 - 1]);
		// if some labels do not match
		if (knot_dname_compare_labels(&sub->name[sub->labels[--l1]],
		                    &domain->name[domain->labels[--l2]], 0)
		    != 0) {
			return 0;  // sub is not a subdomain of domain
		} // otherwise the labels are identical, continue with previous
	}

	// if all labels matched, it should be subdomain (more labels)
	assert(l1 > l2);

	return 1;
}

/*----------------------------------------------------------------------------*/

int knot_dname_is_wildcard(const knot_dname_t *dname)
{
	return (dname->size >= 2
		&& dname->name[0] == 1
		&& dname->name[1] == '*');
}

/*----------------------------------------------------------------------------*/

int knot_dname_matched_labels(const knot_dname_t *dname1,
                                const knot_dname_t *dname2)
{
	int l1 = dname1->label_count;
	int l2 = dname2->label_count;

	// compare labels from last to first
	int matched = 0;
	while (l1 > 0 && l2 > 0) {
		int res = knot_dname_compare_labels(
		               &dname1->name[dname1->labels[--l1]],
		               &dname2->name[dname2->labels[--l2]], 0);
		if (res == 0) {
			++matched;
		} else  {
			break;
		}
	}

	return matched;
}

/*----------------------------------------------------------------------------*/

int knot_dname_label_count(const knot_dname_t *dname)
{
	return dname->label_count;
}

/*----------------------------------------------------------------------------*/

uint8_t knot_dname_label_size(const knot_dname_t *dname, int i)
{
	assert(i >= 0);
	assert(dname->size == 1 || i + 1 == dname->label_count
	       || dname->labels[i + 1] - dname->labels[i] - 1
	          == dname->name[dname->labels[i]]);
	return dname->name[dname->labels[i]];
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_replace_suffix(const knot_dname_t *dname, int size,
                                        const knot_dname_t *suffix)
{
dbg_dname_exec_verb(
	char *name = knot_dname_to_str(dname);
	dbg_dname_verb("Replacing suffix of name %s, size %d with ", name,
	               size);
	free(name);
	name = knot_dname_to_str(suffix);
	dbg_dname_verb("%s (size %d)\n", name, suffix->size);
	free(name);
);
	knot_dname_t *res = knot_dname_new();
	CHECK_ALLOC(res, NULL);

	res->size = dname->size - size + suffix->size;

	dbg_dname_detail("Allocating %d bytes...\n", res->size);
	res->name = (uint8_t *)malloc(res->size);
	if (res->name == NULL) {
		knot_dname_free(&res);
		return NULL;
	}

	dbg_dname_hex((char *)res->name, res->size);

	dbg_dname_detail("Copying %d bytes from the original name.\n",
	                 dname->size - size);
	memcpy(res->name, dname->name, dname->size - size);
	dbg_dname_hex((char *)res->name, res->size);

	dbg_dname_detail("Copying %d bytes from the suffix.\n", suffix->size);
	memcpy(res->name + dname->size - size, suffix->name, suffix->size);

	dbg_dname_hex((char *)res->name, res->size);

	knot_dname_find_labels(res, 1);

	return res;
}

/*----------------------------------------------------------------------------*/

void knot_dname_free(knot_dname_t **dname)
{
	if (dname == NULL || *dname == NULL) {
		return;
	}

	if ((*dname)->name != NULL) {
		free((*dname)->name);
	}

	if((*dname)->labels != NULL) {
		free((*dname)->labels);
	}


//	slab_free(*dname);
	free(*dname);
	*dname = NULL;
}

/*----------------------------------------------------------------------------*/

int knot_dname_compare(const knot_dname_t *d1, const knot_dname_t *d2)
{
	return knot_dname_cmp(d1, d2, 0);
}

/*----------------------------------------------------------------------------*/

int knot_dname_compare_cs(const knot_dname_t *d1, const knot_dname_t *d2)
{
	return knot_dname_cmp(d1, d2, 1);
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_cat(knot_dname_t *d1, const knot_dname_t *d2)
{
	if (d2->size == 0) {
		return d1;
	}

	if (knot_dname_is_fqdn(d1)) {
		return NULL;
	}

	// allocate new space
	uint8_t *new_dname = (uint8_t *)malloc(d1->size + d2->size);
	CHECK_ALLOC_LOG(new_dname, NULL);

	uint8_t *new_labels = (uint8_t *)malloc(d1->label_count
	                                        + d2->label_count);
	if (new_labels == NULL) {
		ERR_ALLOC_FAILED;
		free(new_dname);
		return NULL;
	}

	dbg_dname_detail("1: copying %d bytes from adress %p to %p\n",
	                 d1->size, d1->name, new_dname);

	memcpy(new_dname, d1->name, d1->size);

	dbg_dname_detail("2: copying %d bytes from adress %p to %p\n",
	                 d2->size, d2->name, new_dname + d1->size);

	memcpy(new_dname + d1->size, d2->name, d2->size);

	// update labels
	memcpy(new_labels, d1->labels, d1->label_count);
	for (int i = 0; i < d2->label_count; ++i) {
		new_labels[d1->label_count + i] = d2->labels[i] + d1->size;
	}

	uint8_t *old_labels = d1->labels;
	d1->labels = new_labels;
	free(old_labels);
	d1->label_count += d2->label_count;

	uint8_t *old_name = d1->name;
	d1->name = new_dname;
	free(old_name);

	d1->size += d2->size;

	return d1;
}

void knot_dname_set_id(knot_dname_t *dname, unsigned int id)
{
	dname->id = id;
}

unsigned int knot_dname_get_id(const knot_dname_t *dname)
{
	if (dname != NULL) {
		return dname->id;
	} else {
		return 0; /* 0 should never be used and is reserved for err. */
	}
}
