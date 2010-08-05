#include "dns-utils.h"
#include <ldns/rdata.h>
#include "common.h"
#include <string.h>
#include <assert.h>
#include <ctype.h>

static const uint MAX_LABELS = 127;

/*----------------------------------------------------------------------------*/

uint dnsu_subdomain_labels( const ldns_rdf *sub, const ldns_rdf *parent )
{
	uint8_t *labels_sub[MAX_LABELS], *labels_par[MAX_LABELS];	// 254 B

	assert(ldns_rdf_get_type(sub) == LDNS_RDF_TYPE_DNAME);
	assert(ldns_rdf_get_type(parent) == LDNS_RDF_TYPE_DNAME);

	size_t sub_size = ldns_rdf_size(sub);
	size_t par_size = ldns_rdf_size(parent);

	if (sub_size == 0 || par_size == 0) {
		return 0;
	}

	uint8_t *sub_data = ldns_rdf_data(sub);
	uint8_t *par_data = ldns_rdf_data(parent);

	/*
	 * walk the domain names from left to right and save labels start/end
	 * positions
	 */
	// walk sub
	uint8_t *pos_sub = sub_data;
	uint8_t len = *pos_sub;
	uint label_sub_i = 0;

	assert(sub_data[sub_size - 1] == '\0');

	while (len != 0) {
		++pos_sub;
		labels_sub[label_sub_i++] = pos_sub;
		pos_sub += len;
		len = *pos_sub;
	}
	// save the pointer to the terminating 0
	labels_sub[label_sub_i] = pos_sub;

	assert(labels_sub[label_sub_i] == sub_data + sub_size - 1);
	assert(len == 0);
	assert(pos_sub == sub_data + sub_size - 1);

	// walk parent
	uint8_t *pos_par = par_data;
	len = *pos_par;
	uint label_par_i = 0;

	assert(par_data[par_size - 1] == '\0');

	while (len != 0) {
		labels_par[label_par_i++] = pos_par;
		++pos_par;
		pos_par += len;
		len = *pos_par;
	}
	// save the pointer to the terminating 0
	labels_par[label_par_i] = pos_par;

	assert(labels_par[label_par_i] == par_data + par_size - 1);
	assert(len == 0);
	assert(pos_par == par_data + par_size - 1);

	// if parent has more labels than sub, then sub cannot be subdomain or the
	// same domain
	if (label_par_i > label_sub_i) {
		return 0;
	}

	/*
	 * Now we know that sub may be a subdomain of parent.
	 * Walk through labels from end to start and count labels which are equal
	 * case-insensitive. The characters in labels are walked from right to left.
	 */
	uint matched = 0;
	while (label_par_i > 0) {
		// set positions on the end of labels
		pos_sub = labels_sub[label_sub_i];
		pos_par = labels_par[label_par_i];

		--label_par_i;
		--label_sub_i;

		uint8_t *pos_par_next = labels_par[label_par_i];

		do {
			// in first iteration we skip the labels' length / the last 0
			--pos_sub;
			--pos_par;
		} while (pos_par != pos_par_next
				 && (tolower(*pos_par) == tolower(*pos_sub)));

		// if the whole label was matched, we should be at the end of the next
		// label
		if (pos_par != pos_par_next) {
			return matched;
		}
		// so just continue
		++matched;
	}

	return matched;
}
