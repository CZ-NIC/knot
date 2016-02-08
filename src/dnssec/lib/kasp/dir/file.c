/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "error.h"
#include "kasp/dir/escape.h"
#include "shared.h"

static const char *SUFFIX = ".json";

/* -- internal API --------------------------------------------------------- */

/*!
 * Get zone configuration file name.
 */
char *file_from_entity(const char *dir, const char *type, const char *name)
{
	assert(dir);
	assert(type);
	assert(name);

	// escape entity name

	_cleanup_free_ char *escaped = NULL;
	int r = escape_entity_name(name, &escaped);
	if (r != DNSSEC_EOK) {
		return NULL;
	}

	// build full path

	char *config = NULL;
	int result = asprintf(&config, "%s/%s_%s%s", dir, type, escaped, SUFFIX);
	if (result == -1) {
		return NULL;
	}

	return config;
}

/*!
 * Get a configuration entity name from a file name.
 */
char *file_to_entity(const char *type, const char *basename)
{
	assert(type);
	assert(basename);

	// basename components

	size_t basename_len = strlen(basename);
	size_t prefix_len = strlen(type) + 1;
	size_t suffix_len = strlen(SUFFIX);

	if (basename_len < prefix_len + suffix_len) {
		return NULL;
	}

	size_t name_len = basename_len - suffix_len - prefix_len;

	const char *basename_prefix = basename;
	const char *basename_name   = basename_prefix + prefix_len;
	const char *basename_suffix = basename_name + name_len;

	// prefix and suffix match

	char prefix[prefix_len + 1];
	if (snprintf(prefix, sizeof(prefix), "%s_", type) != prefix_len) {
		return NULL;
	}

	if (memcmp(basename_prefix, prefix, prefix_len) != 0 ||
	    memcmp(basename_suffix, SUFFIX, suffix_len) != 0
	) {
		return NULL;
	}

	// unescape zone name

	_cleanup_free_ char *escaped = strndup(basename_name, name_len);
	if (!escaped) {
		return NULL;
	}

	char *name = NULL;
	int r = unescape_entity_name(escaped, &name);
	if (r != DNSSEC_EOK) {
		free(name);
		return NULL;
	}

	return name;
}
