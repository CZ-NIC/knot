#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "logconf.h"
#include "log.h"
#include "conf.h"
#include "lists.h"

int log_load_conf()
{
	// Initialize logsystem
	const config_t *conf = config_get();
	log_setup(conf->logs_count);

	// Setup logs
	node *n = 0;
	WALK_LIST(n, conf->logs) {

		// Calculate offset
		conf_log_t* log = (conf_log_t*)n;
		int facility = log->type;
		if (facility == LOGT_FILE) {
			facility = log_open_file(log->file);
		}

		// Setup sources mapping
		node *m = 0;
		WALK_LIST(m, log->map) {

			// Assign mapped level
			conf_log_map_t *map = (conf_log_map_t*)m;
			log_levels_add(facility, map->source, map->levels);
		}
	}

	return 0;
}

