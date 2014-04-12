#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "dname.h"
#include "shared.h"

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
	if (length > DNAME_MAX_LENGTH) {
		return 0;
	}

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
	if (length == 0) {
		return NULL;
	}

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

	if (scan > copy) {
		*(scan - 1) = '\0';
	}

	return (char *)copy;
}

/*!
 * Compute real length of a domain name in ASCII.
 */
static size_t ascii_length(const char *name)
{
	size_t length = strlen(name);
	while (length > 0 && name[length - 1] == '.') {
		length -= 1;
	}

	if (length + 1 > DNAME_MAX_LENGTH) {
		return 0;
	}

	return length;
}

/*!
 * Convert ASCII domain name to wire format.
 */
uint8_t *dname_from_ascii(const char *_name)
{
	if (!_name) {
		return NULL;
	}

	// real length without rightmost empty labels

	size_t length = ascii_length(_name);
	if (length == 0) {
		return NULL;
	}

	_cleanup_free_ char *name = strndup(_name, length);
	if (!name) {
		return NULL;
	}

	// allocate result (zero terminated)

	uint8_t *dname = malloc(length + 1);
	if (!dname) {
		return NULL;
	}

	uint8_t *write = dname;
	char *save = NULL;
	char *label = strtok_r(name, ".", &save);
	while (label) {
		size_t label_len = strlen(label);
		if (label_len > DNAME_MAX_LABEL_LENGTH) {
			free(dname);
			return NULL;
		}

		*write = (uint8_t)label_len;
		write += 1;

		memcpy(write, label, label_len);
		write += label_len;

		label = strtok_r(NULL, ".", &save);
	}

	*write = '\0';

	return dname;
}

/*!
 * Normalize ASCII domain name.
 */
void dname_ascii_normalize(char *name)
{
	if (!name) {
		return;
	}

	size_t length = ascii_length(name);
	if (length == 0) {
		return;
	}

	for (size_t i = 0; i < length; i++) {
		name[i] = tolower(name[i]);
	}

	name[length] = '\0';
}

/*!
 * Check if two dnames are equal.
 */
bool dname_equal(const uint8_t *one, const uint8_t *two)
{
	if (!one || !two) {
		return false;
	}

	return (strcasecmp((char *)one, (char *)two) == 0);
}
