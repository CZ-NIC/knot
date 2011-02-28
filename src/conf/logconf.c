#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "logconf.h"
#include "log.h"
#include "conf.h"
#include "lists.h"

int log_conf_hook(const struct conf_t *conf)
{
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

		// Setup sources mapping
		node *m = 0;
		WALK_LIST(m, log->map) {

			// Assign mapped level
			conf_log_map_t *map = (conf_log_map_t*)m;
			log_levels_add(facility, map->source, map->prios);
		}
	}

	return 0;
}

