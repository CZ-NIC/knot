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

#pragma once

#include <string.h>

enum cmd_match {
	CMD_MATCH_NO = 0,
	CMD_MATCH_PREFIX,
	CMD_MATCH_EXACT,
};

typedef enum cmd_match cmd_match_t;

/*!
 * Try to match a command name or it's prefix.
 */
static inline cmd_match_t cmd_match(const char *cmd, const char *search)
{
	size_t cmd_len = strlen(cmd);
	size_t search_len = strlen(search);

	if (search_len > cmd_len || strncmp(search, cmd, search_len) != 0) {
		return CMD_MATCH_NO;
	}

	return search_len < cmd_len ? CMD_MATCH_PREFIX : CMD_MATCH_EXACT;
}
