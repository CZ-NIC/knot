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

#pragma once

#include <stdbool.h>

#include "utils/knot1to2/includes.h"
#include "utils/knot1to2/scheme.h"
#include "contrib/hat-trie/hat-trie.h"

typedef struct {
	FILE *out;
	bool have_sections[S_LAST - S_FIRST + 1];
	hattrie_t *ifaces;
	hattrie_t *groups;
	hattrie_t *remotes;
	hattrie_t *acl_xfer;
	hattrie_t *acl_notify;
	hattrie_t *acl_update;
	hattrie_t *acl_control;
} share_t;

/*!
 * \brief Custom data held within the parser context.
 */
typedef struct {
	bool error;                // Indicates that error was set.
	conf_includes_t *includes; // Used to handle filenames in includes.
	int run;                   // Current run number.
	share_t *share;            // Variables shared among all runs.
	hattrie_t *current_trie;
	const char *current_key;
} conf_extra_t;

/*!
 * \brief Init structure with custom data for config parser.
 *
 * \param file                Name of the main configuration file.
 *
 * \return Initialized stucture or NULL.
 */
conf_extra_t *conf_extra_init(const char *file, int run, share_t *share);

/*!
 * \brief Free structure with custom data for config parser.
 *
 * \param extra  Structure to be freed.
 */
void conf_extra_free(conf_extra_t *extra);
