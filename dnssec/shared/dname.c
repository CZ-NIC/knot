#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "dname.h"

/*!
 * Get length of a domain name in wire format.
 */
size_t dname_length(const uint8_t *dname)
{
	if (!dname) {
		return 0;
	}

	const uint8_t *scan = dname;
	uint8_t label_len;
	do {
		label_len = *scan;
		scan += 1 + label_len;
	} while (label_len > 0);

	assert(scan > dname);

	size_t length = scan - dname;
	assert(length <= DNAME_MAX_LENGTH);
	return length;
}

/*!
 * Copy domain name in wire format.
 */
uint8_t *dname_copy(const uint8_t *dname)
{
	if (!dname) {
		return NULL;
	}

	size_t length = dname_length(dname);
	assert(length > 0);

	uint8_t *copy = malloc(length);
	if (!copy) {
		return NULL;
	}

	memmove(copy, dname, length);
	return copy;
}

/*!
 * Normalize domain name in wire format.
 */
void dname_normalize(uint8_t *dname)
{
	if (!dname) {
		return;
	}

	size_t length = dname_length(dname);
	assert(length > 0);

	uint8_t *scan = dname;
	for (size_t i = 0; i < length; i++) {
		*scan = tolower(*scan);
		scan += 1;
	}
}

/*!
 * Convert domain name to human readable ASCII representation.
 */
char *dname_to_ascii(const uint8_t *dname)
{
	if (!dname) {
		return NULL;
	}

	uint8_t *copy = dname_copy(dname);
	if (!copy) {
		return NULL;
	}

	dname_normalize(copy);

	// perform in place conversion

	uint8_t *scan = copy;
	for (;;) {
		uint8_t label_len = *scan;
		if (label_len == 0) {
			break;
		}

		memmove(scan, scan + 1, label_len);
		scan += label_len;
		*scan = '.';
		scan += 1;
	}

	return (char *)copy;
}
