#include <config.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>	// tolower()

#include "dnslib/dnslib-common.h"
#include "dnslib/error.h"
#include "dnslib/dname.h"
#include "dnslib/consts.h"
#include "dnslib/tolower.h"
#include "dnslib/debug.h"
#include "dnslib/utils.h"
#include "dnslib/wire.h"

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
static void dnslib_dname_cache_free()
{
	slab_cache_t* cache = pthread_getspecific(dname_ckey);
	if (cache) {
		slab_cache_destroy(cache);
		free(cache);
        (void) pthread_setspecific(dname_ckey, 0);
	}
}

static void dnslib_dname_cache_init()
{
	(void) pthread_key_create(&dname_ckey, dnslib_dname_cache_free);
    atexit(dnslib_dname_cache_free); // Main thread cleanup
}

/*!
 * \brief Allocate item from thread cache.
 * \retval Allocated dname instance on success.
 * \retval NULL on error.
 */
static dnslib_dname_t* dnslib_dname_alloc()
{
	/* Initialize dname cache TLS key. */
	(void) pthread_once(&dname_once, dnslib_dname_cache_init);

	/* Create cache if not exists. */
	slab_cache_t* cache = pthread_getspecific(dname_ckey);
	if (unlikely(!cache)) {
		cache = malloc(sizeof(slab_cache_t));
		if (!cache) {
			return 0;
		}

		/* Initialize cache. */
		slab_cache_init(cache, sizeof(dnslib_dname_t));
		(void) pthread_setspecific(dname_ckey, cache);
	}

	return slab_cache_alloc(cache);
}

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static int dnslib_dname_set(dnslib_dname_t *dname, uint8_t *wire,
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
static int dnslib_dname_str_to_wire(const char *name, uint size,
                                    dnslib_dname_t *dname)
{
	if (size > DNSLIB_MAX_DNAME_LENGTH) {
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
	uint8_t labels[DNSLIB_MAX_DNAME_LABELS];
	short label_count = 0;

	// signed / unsigned issues??
	wire = (uint8_t *)malloc(wire_size * sizeof(uint8_t));
	if (wire == NULL) {
		return -1;
	}

	debug_dnslib_dname("Allocated space for wire format of dname: %p\n",
	                   wire);

	if (root) {
		*wire = '\0';
		label_count = 0;
		return dnslib_dname_set(dname, wire, wire_size, labels,
		                        label_count);
	}

	const uint8_t *ch = (const uint8_t *)name;
	uint8_t *label_start = wire;
	uint8_t *w = wire + 1;
	uint8_t label_length = 0;

	while (ch - (const uint8_t *)name < size) {
		assert(w - wire - 1 == ch - (const uint8_t *)name);

		if (*ch == '.') {
			debug_dnslib_dname("Position %zd (%p): "
			                   "label length: %u\n",
			                   label_start - wire,
			                   label_start, label_length);
			*label_start = label_length;
			labels[label_count++] = label_start - wire;
			label_start = w;
			label_length = 0;
		} else {
			assert(w - wire < wire_size);
			debug_dnslib_dname("Position %zd (%p): character: %c\n",
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
		debug_dnslib_dname("Position %zd (%p): character: (null)\n",
				   w - wire, w);
		*w = 0;
	} else { // otherwise we did not save the last label length
		debug_dnslib_dname("Position %zd (%p): "
		                   "label length: %u\n",
		                   label_start - wire,
		                   label_start, label_length);
		*label_start = label_length;
		labels[label_count++] = label_start - wire;
	}

	return dnslib_dname_set(dname, wire, wire_size, labels, label_count);
}

/*----------------------------------------------------------------------------*/

static inline int dnslib_dname_tolower(uint8_t c, int cs)
{
	return (cs) ? c : dnslib_tolower(c);
}

/*----------------------------------------------------------------------------*/

static int dnslib_dname_compare_labels(const uint8_t *label1,
                                       const uint8_t *label2, int cs)
{
	const uint8_t *pos1 = label1;
	const uint8_t *pos2 = label2;

	int label_length = (*pos1 < *pos2) ? *pos1 : *pos2;
	int i = 0;

	while (i < label_length
	       && dnslib_dname_tolower(*(++pos1), cs)
	          == dnslib_dname_tolower(*(++pos2), cs)) {
		++i;
	}

	if (i < label_length) {  // difference in some octet
		return (dnslib_dname_tolower(*pos1, cs)
		        - dnslib_dname_tolower(*pos2, cs));
	}

	return (label1[0] - label2[0]);
}

/*----------------------------------------------------------------------------*/

static int dnslib_dname_find_labels(dnslib_dname_t *dname, int alloc)
{
	const uint8_t *name = dname->name;
	const uint8_t *pos = name;
	const uint size = dname->size;

	uint8_t labels[DNSLIB_MAX_DNAME_LABELS];
	short label_count = 0;

	while (pos - name < size && *pos != '\0') {
		labels[label_count++] = pos - name;
		pos += *pos + 1;
	}

	// TODO: how to check if the domain name has right format?
//	if (pos - name < size && *pos != '0') {
//		debug_dnslib_dname("Wrong wire format of domain name!\n");
//		debug_dnslib_dname("Position: %d, character: %d, expected"
//				   " size: %d\n", pos - name, *pos, size);
//		return -1;
//	}

	if (alloc) {
		dname->labels
			= (uint8_t *)malloc(label_count * sizeof(uint8_t));
		CHECK_ALLOC_LOG(dname->labels, DNSLIB_ENOMEM);
	}

	memcpy(dname->labels, labels, label_count);
	dname->label_count = label_count;

	return 0;
}

/*----------------------------------------------------------------------------*/

static int dnslib_dname_cmp(const dnslib_dname_t *d1, const dnslib_dname_t *d2,
                            int cs)
{
DEBUG_DNSLIB_DNAME(
	char *name1 = dnslib_dname_to_str(d1);
	char *name2 = dnslib_dname_to_str(d2);

	debug_dnslib_dname("Comparing dnames %s and %s\n",
	                   name1, name2);

	for (int i = 0; i < strlen(name1); ++i) {
		name1[i] = dnslib_tolower(name1[i]);
	}
	for (int i = 0; i < strlen(name2); ++i) {
		name2[i] = dnslib_tolower(name2[i]);
	}

	debug_dnslib_dname("After to lower: %s and %s\n",
	                   name1, name2);

	free(name1);
	free(name2);
);

	if (!cs && d1 == d2) {
		return 0;
	}

	int l1 = d1->label_count;
	int l2 = d2->label_count;
	debug_dnslib_dname("Label counts: %d and %d\n", l1, l2);
	assert(l1 >= 0);
	assert(l2 >= 0);

	// compare labels from last to first
	while (l1 > 0 && l2 > 0) {
		debug_dnslib_dname("Comparing labels %d and %d\n",
				   l1 - 1, l2 - 1);
		debug_dnslib_dname(" at offsets: %d and %d\n",
				   d1->labels[l1 - 1], d2->labels[l2 - 1]);
		int res = dnslib_dname_compare_labels(
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

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_new()
{
	dnslib_dname_t *dname = dnslib_dname_alloc();
	dname->name = NULL;
	dname->size = 0;
	dname->node = NULL;
	dname->labels = NULL;
	dname->label_count = -1;
	dname->id = 0;

	return dname;
}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_new_from_str(const char *name, uint size,
                                          struct dnslib_node *node)
{
	if (name == NULL || size == 0) {
		return NULL;
	}

//	dnslib_dname_t *dname = dnslib_dname_alloc();
	dnslib_dname_t *dname = dnslib_dname_new();

	if (dname == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	dnslib_dname_str_to_wire(name, size, dname);
	assert(dname->label_count >= 0);
	debug_dnslib_dname("Created dname with size: %d\n", dname->size);
	debug_dnslib_dname("Label offsets: ");
	for (int i = 0; i < dname->label_count; ++i) {
		debug_dnslib_dname("%d, ", dname->labels[i]);
	}
	debug_dnslib_dname("\n");

	if (dname->size <= 0) {
		fprintf(stderr, "Could not parse domain name "
		        "from string: '%.*s'\n", size, name);
	}
	assert(dname->name != NULL);

	dname->node = node;
	dname->id = 0;

	return dname;
}

/*----------------------------------------------------------------------------*/

//int dnslib_dname_from_wire(dnslib_dname_t *dname, const uint8_t *name,
//                           uint size)
//{
//	int i = 0;
//	uint8_t labels[DNSLIB_MAX_DNAME_LABELS];
//	int label_i = 0;

//	while (name[i] != 0) {
//		labels[label_i++] = i;
//		uint8_t label_length = name[i];
//		if (i + label_length >= size) {
//			return -2;
//		}
//		for (int j = 1; j <= label_length; ++j) {
//		}
//	}
//}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_new_from_wire(const uint8_t *name, uint size,
                                           struct dnslib_node *node)
{
	if (name == NULL) { /* && size != 0) { !OS: Nerozumjaju */
		debug_dnslib_dname("No name given!\n");
		return NULL;
	}

	dnslib_dname_t *dname = dnslib_dname_alloc();

	if (dname == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	dname->name = (uint8_t *)malloc(size * sizeof(uint8_t));
	if (dname->name == NULL) {
		ERR_ALLOC_FAILED;
		dnslib_dname_free(&dname);
		return NULL;
	}

	memcpy(dname->name, name, size);
	dname->size = size;

	if (dnslib_dname_find_labels(dname, 1) != 0) {
		dnslib_dname_free(&dname);
		return NULL;
	}
	assert(dname->label_count >= 0);

	dname->node = node;
	dname->id = 0;

	return dname;
}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_parse_from_wire(const uint8_t *wire,
                                             size_t *pos, size_t size,
                                             dnslib_node_t *node)
{
	uint8_t name[DNSLIB_MAX_DNAME_LENGTH];
	uint8_t labels[DNSLIB_MAX_DNAME_LABELS];

	short l = 0;
	size_t i = 0, p = *pos;
	int pointer_used = 0;

	while (p < size && wire[p] != 0) {
		labels[l] = i;

		if (dnslib_wire_is_pointer(wire + p)) {
			// pointer.
			p = dnslib_wire_get_pointer(wire + p);
			*pos += 2;
			pointer_used = 1;
			if (p >= size) {
				return NULL;
			}
		} else {
			// label; first byte is label length
			uint8_t length = *(wire + p);
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

	dnslib_dname_t *dname = dnslib_dname_alloc();

	if (dname == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	dname->name = (uint8_t *)malloc((i + 1) * sizeof(uint8_t));
	if (dname->name == NULL) {
		ERR_ALLOC_FAILED;
		dnslib_dname_free(&dname);
		return NULL;
	}

	memcpy(dname->name, name, i + 1);
	dname->size = i + 1;

	dname->labels = (uint8_t *)malloc(l * sizeof(uint8_t));
	if (dname->labels == NULL) {
		ERR_ALLOC_FAILED;
		dnslib_dname_free(&dname);
		return NULL;
	}
	memcpy(dname->labels, labels, l);

	dname->label_count = l - 1;

	dname->node = node;

	return dname;
}

/*----------------------------------------------------------------------------*/

int dnslib_dname_from_wire(const uint8_t *name, uint size,
                           struct dnslib_node *node, dnslib_dname_t *target)
{
	if (name == NULL || target == NULL) {
		return DNSLIB_EBADARG;
	}

	memcpy(target->name, name, size);
	target->size = size;
	target->node = node;
	target->id = 0;

	return dnslib_dname_find_labels(target, 0);
}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_copy(const dnslib_dname_t *dname)
{
	return dnslib_dname_new_from_wire(dname->name, dname->size,
	                                  dname->node);
}

/*----------------------------------------------------------------------------*/

char *dnslib_dname_to_str(const dnslib_dname_t *dname)
{
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

const uint8_t *dnslib_dname_name(const dnslib_dname_t *dname)
{
	return dname->name;
}

/*----------------------------------------------------------------------------*/

uint dnslib_dname_size(const dnslib_dname_t *dname)
{
	return dname->size;
}

/*----------------------------------------------------------------------------*/

uint8_t dnslib_dname_size_part(const dnslib_dname_t *dname, int labels)
{
	assert(labels < dname->label_count);
	assert(dname->labels != NULL);
	return (dname->labels[labels]);
}

/*----------------------------------------------------------------------------*/

const struct dnslib_node *dnslib_dname_node(const dnslib_dname_t *dname)
{
	return dname->node;
}

/*----------------------------------------------------------------------------*/

int dnslib_dname_is_fqdn(const dnslib_dname_t *dname)
{
	return (dname->name[dname->size - 1] == '\0');
}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_left_chop(const dnslib_dname_t *dname)
{
	dnslib_dname_t *parent = dnslib_dname_new();
	if (parent == NULL) {
		return NULL;
	}

	parent->size = dname->size - dname->name[0] - 1;
	parent->name = (uint8_t *)malloc(parent->size);
	if (parent->name == NULL) {
		ERR_ALLOC_FAILED;
		dnslib_dname_free(&parent);
		return NULL;
	}

	parent->labels = (uint8_t *)malloc(dname->label_count - 1);
	if (parent->labels == NULL) {
		ERR_ALLOC_FAILED;
		free(parent->name);
		dnslib_dname_free(&parent);
		return NULL;
	}

	memcpy(parent->name, &dname->name[dname->name[0] + 1], parent->size);

	short first_label_length = dname->labels[1];

	for (int i = 0; i < dname->label_count - 1; ++i) {
		parent->labels[i] = dname->labels[i + 1] - first_label_length;
	}
	parent->label_count = dname->label_count - 1;
	assert(dname->label_count >= 0);

	return parent;
}

/*----------------------------------------------------------------------------*/

void dnslib_dname_left_chop_no_copy(dnslib_dname_t *dname)
{
	// copy the name
	short first_label_length = dname->labels[1];

	if (dname->label_count > 1) {
		memmove(dname->name, &dname->name[dname->labels[1]],
			dname->size - first_label_length);
		// adjust labels
		for (int i = 0; i < dname->label_count - 1; ++i) {
			dname->labels[i] = dname->labels[i + 1]
			                   - first_label_length;
		}
		dname->label_count = dname->label_count - 1;
		dname->size -= first_label_length;
		assert(dname->label_count >= 0);
	} else {
		dname->name[0] = '\0';
		dname->size = 1;
		dname->label_count = 0;
	}
}

/*----------------------------------------------------------------------------*/

int dnslib_dname_is_subdomain(const dnslib_dname_t *sub,
                              const dnslib_dname_t *domain)
{
DEBUG_DNSLIB_DNAME(
	char *name1 = dnslib_dname_to_str(sub);
	char *name2 = dnslib_dname_to_str(domain);

	debug_dnslib_dname("Checking if %s is subdomain of %s\n",
	                   name1, name2);
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

	debug_dnslib_dname("Label counts: %d and %d\n", l1, l2);

	if (l1 <= l2) {  // if sub does not have more labes than domain
		return 0;  // it is not its subdomain
	}

	// compare labels from last to first
	while (l1 > 0 && l2 > 0) {
		debug_dnslib_dname("Comparing labels %d and %d\n",
				   l1 - 1, l2 - 1);
		debug_dnslib_dname(" at offsets: %d and %d\n",
				   sub->labels[l1 - 1], domain->labels[l2 - 1]);
		// if some labels do not match
		if (dnslib_dname_compare_labels(&sub->name[sub->labels[--l1]],
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

int dnslib_dname_is_wildcard(const dnslib_dname_t *dname)
{
	return (dname->size >= 2
		&& dname->name[0] == 1
		&& dname->name[1] == '*');
}

/*----------------------------------------------------------------------------*/

int dnslib_dname_matched_labels(const dnslib_dname_t *dname1,
                                const dnslib_dname_t *dname2)
{
	int l1 = dname1->label_count;
	int l2 = dname2->label_count;

	// compare labels from last to first
	int matched = 0;
	while (l1 > 0 && l2 > 0) {
		int res = dnslib_dname_compare_labels(
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

int dnslib_dname_label_count(const dnslib_dname_t *dname)
{
	assert(dname->label_count >= 0);
	return dname->label_count;
}

/*----------------------------------------------------------------------------*/

uint8_t dnslib_dname_label_size(const dnslib_dname_t *dname, int i)
{
//	printf("Returning size of %d. label starting on %d\n",
//	       i, dname->labels[i]);
//	printf("Label count: %d, size of %d. label: %d, size of %d.label: %d\n",
//	       dname->label_count, i, dname->labels[i], i + 1,
//	       dname->labels[i+1]);
//	printf("Size from the name: %u\n", dname->name[dname->labels[i]]);
//	printf("Size from label offsets: %u\n",
//	       dname->labels[i + 1] - dname->labels[i]);

	assert(i >= 0);
	assert(dname->size == 1 || i + 1 == dname->label_count
	       || dname->labels[i + 1] - dname->labels[i] - 1
	          == dname->name[dname->labels[i]]);
	return dname->name[dname->labels[i]];
}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_replace_suffix(const dnslib_dname_t *dname,
                                            int size,
                                            const dnslib_dname_t *suffix)
{
DEBUG_DNSLIB_DNAME(
	char *name = dnslib_dname_to_str(dname);
	debug_dnslib_dname("Replacing suffix of name %s, size %d with ", name,
	                   size);
	free(name);
	name = dnslib_dname_to_str(suffix);
	debug_dnslib_dname("%s (size %d)\n", name, suffix->size);
	free(name);
);
	dnslib_dname_t *res = dnslib_dname_new();
	CHECK_ALLOC(res, NULL);

	res->size = dname->size - size + suffix->size;

	debug_dnslib_dname("Allocating %d bytes...\n", res->size);
	res->name = (uint8_t *)malloc(res->size);
	if (res->name == NULL) {
		dnslib_dname_free(&res);
		return NULL;
	}

	debug_dnslib_dname_hex((char *)res->name, res->size);

	debug_dnslib_dname("Copying %d bytes from the original name.\n",
	                   dname->size - size);
	memcpy(res->name, dname->name, dname->size - size);
	debug_dnslib_dname_hex((char *)res->name, res->size);

	debug_dnslib_dname("Copying %d bytes from the suffix.\n", suffix->size);
	memcpy(res->name + dname->size - size, suffix->name, suffix->size);

	debug_dnslib_dname_hex((char *)res->name, res->size);

	dnslib_dname_find_labels(res, 1);

	assert(res->label_count >= 0);

	return res;
}

/*----------------------------------------------------------------------------*/

void dnslib_dname_free(dnslib_dname_t **dname)
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
	*dname = NULL;
}

/*----------------------------------------------------------------------------*/

int dnslib_dname_compare(const dnslib_dname_t *d1, const dnslib_dname_t *d2)
{
	return dnslib_dname_cmp(d1, d2, 0);
}

/*----------------------------------------------------------------------------*/

int dnslib_dname_compare_cs(const dnslib_dname_t *d1, const dnslib_dname_t *d2)
{
	return dnslib_dname_cmp(d1, d2, 1);
}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_cat(dnslib_dname_t *d1, const dnslib_dname_t *d2)
{
	if (d2->size == 0) {
		return d1;
	}

	if (dnslib_dname_is_fqdn(d1)) {
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

	debug_dnslib_dname("1: copying %d bytes from adress %p to %p\n",
	                   d1->size, d1->name, new_dname);

	memcpy(new_dname, d1->name, d1->size);

	debug_dnslib_dname("2: copying %d bytes from adress %p to %p\n",
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

	assert(d1->label_count >= 0);

	return d1;
}

void dnslib_dname_set_id(dnslib_dname_t *dname, unsigned int id)
{
	dname->id = id;
}

unsigned int dnslib_dname_get_id(const dnslib_dname_t *dname)
{
	if (dname != NULL) {
		return dname->id;
	} else {
		return 0; /* 0 should never be used and is reserved for err. */
	}
}
