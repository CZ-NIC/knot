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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "knot/other/debug.h"
#include "knot/conf/logconf.h"
#include "knot/conf/conf.h"
#include "knot/other/log.h"
#include "knot/other/error.h"
#include "common/lists.h"
#include "knot/common.h"

int log_conf_hook(const struct conf_t *conf, void *data)
{
	// Data not used
	int ret = 0;
	UNUSED(data);

	// Check if log declaration exists, otherwise ignore
	if (conf->logs_count < 1) {
		return KNOTD_EINVAL;
	}

	// Find maximum log facility id
	node *n = 0; size_t files = 0;
	WALK_LIST(n, conf->logs) {
		conf_log_t* log = (conf_log_t*)n;
		if (log->type == LOGT_FILE) {
			++files;
		}
	}

	// Initialize logsystem
	log_truncate();
	if ((ret = log_setup(files)) < 0) {
		return ret;
	}

	// Setup logs
	int loaded_sections = 0;
	n = 0;
	WALK_LIST(n, conf->logs) {

		// Calculate offset
		conf_log_t* log = (conf_log_t*)n;
		int facility = log->type;
		if (facility == LOGT_FILE) {
			facility = log_open_file(log->file);
			if (facility < 0) {
				log_server_error("Failed to open "
				                 "logfile '%s'.\n", log->file);
				continue;
			}
		}

		// Auto-assign fatal errors to syslog or stderr
		if (facility <= LOGT_STDERR) {
			int mask = LOG_MASK(LOG_FATAL);
			log_levels_add(facility, LOG_ANY, mask);
			loaded_sections |= 1 << facility;
		}

		// Setup sources mapping
		node *m = 0;
		WALK_LIST(m, log->map) {

			// Assign mapped level
			conf_log_map_t *map = (conf_log_map_t*)m;
			log_levels_add(facility, map->source, map->prios);
		}
	}

	// Load defaults for syslog or stderr
	int bmask = LOG_MASK(LOG_ERR)|LOG_MASK(LOG_FATAL);
	if (!(loaded_sections & (1 << LOGT_SYSLOG))) {
		log_levels_set(LOGT_SYSLOG, LOG_ANY, bmask);
	}
	if (!(loaded_sections & (1 << LOGT_STDERR))) {
		log_levels_set(LOGT_STDERR, LOG_ANY, bmask);
	}

	return KNOTD_EOK;
}

