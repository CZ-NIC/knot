#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "knot/conf/logconf.h"
#include "knot/conf/conf.h"
#include "knot/other/log.h"
#include "knot/lib/lists.h"

int log_conf_hook(const struct conf_t *conf)
{
	// Check if log declaration exists, otherwise ignore
	if (conf->logs_count < 1) {
		return 0;
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
	log_setup(files);

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
				log_server_error("config: Failed to open "
				                 "logfile '%s'.\n",
				                 log->file);
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

	return 0;
}

