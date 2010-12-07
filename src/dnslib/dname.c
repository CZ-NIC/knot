#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>	// tolower()

#include "dname.h"
#include "common.h"
#include "consts.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Converts domain name from string representation to wire format.
 *
 * This function also allocates the space for the wire format.
 *
 * \param name Domain name in string representation (presentation format).
 * \param size Size of the given domain name in characters (not counting the
 *             terminating 0 character.
 * \param wire [in/out] Pointer to position where the wire format of the domain
 *             name will be stored.
 *
 * \return Size of the wire format of the domain name in octets. If 0, no
 *         space has been allocated.
 *
 * \todo handle \X and \DDD (RFC 1035 5.1) or it can be handled by the parser?
 */
static uint dnslib_dname_str_to_wire(const char *name, uint size,
                                     uint8_t **wire)
{
	if (size > DNSLIB_MAX_DNAME_LENGTH) {
		return 0;
	}

	uint wire_size;
	// root => different size
	if (*name == '.' && size == 1) {
		wire_size = 1;
	} else {
		wire_size = size + 1;
	}

	// signed / unsigned issues??
	*wire = (uint8_t *)malloc(wire_size * sizeof(uint8_t));
	if (*wire == NULL) {
		return 0;
	}

	debug_dnslib_dname("Allocated space for wire format of dname: %p\n",
	                   *wire);

	const uint8_t *ch = (const uint8_t *)name;
	uint8_t *label_start = *wire;
	uint8_t *w = *wire + 1;
	uint8_t label_length = 0;

	while (ch - (const uint8_t *)name < size) {
		assert(w - *wire - 1 == ch - (const uint8_t *)name);

		if (*ch == '.') {
			debug_dnslib_dname("Position %u (%p): "
			                   "label length: %u\n",
			                   label_start - *wire,
			                   label_start, label_length);
			*label_start = label_length;
			label_start = w;
			label_length = 0;
		} else {
			assert(w - *wire < wire_size);
			debug_dnslib_dname("Position %u (%p): character: %c\n",
			                   w - *wire, w, *ch);
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
		debug_dnslib_dname("Position %u (%p): character: (null)\n",
				   w - *wire, w);
		*w = 0;
	} else { // otherwise we did not save the last label length
		debug_dnslib_dname("Position %u (%p): "
		                   "label length: %u\n",
		                   label_start - *wire,
		                   label_start, label_length);
		*label_start = label_length;
	}

	//memcpy(*wire, name, size);
	return wire_size;
}

/*----------------------------------------------------------------------------*/

static int dnslib_dname_compare_labels(const uint8_t *label1,
                                       const uint8_t *label2)
{
	const uint8_t *pos1 = label1;
	const uint8_t *pos2 = label2;

	int label_length = (*pos1 < *pos2) ? *pos1 : *pos2;
	int i = 0;

	while (i < label_length &&
	       tolower(*(++pos1)) == tolower(*(++pos2))) {
		++i;
	}

	if (i < label_length) {  // difference in some octet
		if (tolower(*pos1) < tolower(*pos2)) {
			return -1;
		} else {
			assert(tolower(*pos1) > tolower(*pos2));
			return 1;
		}
	}

	if (label1[0] < label2[0]) {  // one label shorter
		return -1;
	} else if (label1[0] > label2[0]) {
		return 1;
	}

	return 0;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_new()
{
	dnslib_dname_t *dname = 
	(dnslib_dname_t *)malloc(sizeof(dnslib_dname_t));

	if (dname == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	dname->name = NULL;
	dname->size = 0;
	dname->node = NULL;

	return dname;
}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_new_from_str(char *name, uint size,
                                          struct dnslib_node *node)
{
	if (name == NULL || size == 0) {
		return NULL;
	}

	dnslib_dname_t *dname =
	(dnslib_dname_t *)malloc(sizeof(dnslib_dname_t));

	if (name == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	dname->size = dnslib_dname_str_to_wire(name, size, &dname->name);
	debug_dnslib_dname("Creating dname with size: %d\n", dname->size);

	if (dname->size <= 0) {
		log_warning("Could not parse domain name from string: '%.*s'\n",
		            size, name);
	}
	assert(dname->name != NULL);

	dname->node = node;

	return dname;
}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_new_from_wire(uint8_t *name, uint size,
                                           struct dnslib_node *node)
{
	if (name == NULL && size != 0) {
		debug_dnslib_dname("No name given!\n");
		return NULL;
	}

	dnslib_dname_t *dname =
	    (dnslib_dname_t *)malloc(sizeof(dnslib_dname_t));

	if (dname == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	dname->name = (uint8_t *)malloc(size * sizeof(uint8_t));
	if (dname->name == NULL) {
		ERR_ALLOC_FAILED;
		free(dname);
		return NULL;
	}

	memcpy(dname->name, name, size);
	dname->size = size;
	dname->node = node;

	return dname;
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

const struct dnslib_node *dnslib_dname_node(const dnslib_dname_t *dname) {
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

	memcpy(parent->name, &dname->name[dname->name[0] + 1], parent->size);

	return parent;
}

/*----------------------------------------------------------------------------*/

int dnslib_dname_is_subdomain(const dnslib_dname_t *sub,
                              const dnslib_dname_t *domain)
{
	if (sub == domain) {
		return 0;
	}

	// jump to the last label and store addresses of labels
	// on the way there
	// TODO: consider storing label offsets in the domain name structure
	const uint8_t *labels1[DNSLIB_MAX_DNAME_LABELS];
	const uint8_t *labels2[DNSLIB_MAX_DNAME_LABELS];
	int l1 = 0;
	int l2 = 0;

	const uint8_t *name1 = dnslib_dname_name(sub);
	const uint8_t *pos1 = name1;
	const uint size1 = dnslib_dname_size(sub);

	const uint8_t *name2 = dnslib_dname_name(domain);
	const uint8_t *pos2 = name2;
	const uint size2 = dnslib_dname_size(domain);

	while (pos1 - name1 < size1 && *pos1 != '\0') {
		labels1[l1++] = pos1;
		pos1 += *pos1 + 1;
	}

	while (pos2 - name2 < size2 && *pos2 != '\0') {
		labels2[l2++] = pos2;
		pos2 += *pos2 + 1;
	}

	if (l1 <= l2) {  // if sub does not have more labes than domain
		return 0;  // it is not its subdomain
	}

	// compare labels from last to first
	while (l1 > 0 && l2 > 0) {
		// if some labels do not match
		if (dnslib_dname_compare_labels(labels1[--l1],
		                                labels2[--l2]) != 0) {
			return 0;  // sub is not a subdomain of domain
		} // otherwise the labels are identical, continue with previous
	}

	// if all labels matched, it should be subdomain (more labels)
	assert(l1 > l2);

	return 1;
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
	free(*dname);
	*dname = NULL;
}

/*----------------------------------------------------------------------------*/

int dnslib_dname_compare(const dnslib_dname_t *d1, const dnslib_dname_t *d2)
{
	if (d1 == d2) {
		return 0;
	}

	// jump to the last label and store addresses of labels
	// on the way there
	// TODO: consider storing label offsets in the domain name structure
	const uint8_t *labels1[DNSLIB_MAX_DNAME_LABELS];
	const uint8_t *labels2[DNSLIB_MAX_DNAME_LABELS];
	int l1 = 0;
	int l2 = 0;

	const uint8_t *pos1 = d1->name;
	const uint8_t *pos2 = d2->name;
	int i = 0;

	while (i < d1->size && *pos1 != '\0') {
		labels1[l1++] = pos1;
		pos1 += *pos1 + 1;
		++i;
	}

	i = 0;
	while (i < d2->size && *pos2 != '\0') {
		labels2[l2++] = pos2;
		pos2 += *pos2 + 1;
		++i;
	}

	// compare labels from last to first
	while (l1 > 0 && l2 > 0) {
		int res = dnslib_dname_compare_labels(labels1[--l1],
		                                      labels2[--l2]);
		if (res != 0) {
			return res;
		} // otherwise the labels are identical, continue with previous

//		pos1 = labels1[--i1];
//		pos2 = labels2[--i2];

//		int label_length = (*pos1 < *pos2) ? *pos1 : *pos2;
//		int i = 0;

//		while (i < label_length &&
//		       tolower(*(++pos1)) == tolower(*(++pos2))) {
//			++i;
//		}

//		if (i < label_length) {	// difference in some octet
//			if (tolower(*pos1) < tolower(*pos2)) {
//				return -1;
//			} else {
//				assert(tolower(*pos1) > tolower(*pos2));
//				return 1;
//			}
//		}

//		if (*(labels1[i1]) < *(labels2[i2])) {	// one label shorter
//			return -1;
//		} else if (*(labels1[i1]) > *(labels2[i2])) {
//			return 1;
//		}
		// otherwise the labels are 
		// identical, continue with previous labels
	}

	// if all labels matched, the shorter name is first
	if (l1 == 0 && l2 > 0) {
		return 1;
	}

	if (l1 > 0 && l2 == 0) {
		return -1;
	}

	return 0;
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
	if (new_dname == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	debug_dnslib_dname("1: copying %d bytes from adress %p to %p\n",
	                   d1->size, d1->name, new_dname);

	memcpy(new_dname, d1->name, d1->size);

	debug_dnslib_dname("2: copying %d bytes from adress %p to %p\n",
	                   d2->size, d2->name, new_dname + d1->size);

	memcpy(new_dname + d1->size, d2->name, d2->size);

	uint8_t *old_name = d1->name;
	d1->name = new_dname;
	d1->size += d2->size;
	free(old_name);

	return d1;
}
