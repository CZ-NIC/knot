#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "logconf.h"
#include "log.h"
#include "conf.h"
#include "lists.h"

/* Extern symbols from log subsystem.
 * This is required to silently extend log.c facilities.
 */
extern size_t LOG_LUT_SIZE;
extern uint8_t *LOG_LUT;

int log_load_conf()
{
	// Initialize LUT
	const config_t *conf = config_get();
	uint8_t *lp = 0;
	LOG_LUT_SIZE = conf->logs_count << 3;
	LOG_LUT = malloc(LOG_LUT_SIZE);
	memset(LOG_LUT, 0, LOG_LUT_SIZE);

	// Setup logs
	int fileno = 0;
	node *n = 0;
	WALK_LIST(n, conf->logs) {

		conf_log_t* log = (conf_log_t*)n;

		// Calculate offset
		int offset = log->type;
		if (offset == LOGT_FILE) {
			offset += fileno++;
		}
		offset <<= 3;
		lp = LOG_LUT + offset;

		// Setup sources mapping
		node *m = 0;
		WALK_LIST(m, log->map) {
			conf_log_map_t *map = (conf_log_map_t*)m;

			// Assign level if not multimask
			if (map->source != LOG_ANY) {
				*(lp + map->source) |= map->levels;
			} else {
				// Any == add to all sources
				for (int i = 0; i < LOG_ANY; ++i) {
					*(lp + i) |= map->levels;
				}
			}
		}
	}

	return 0;
}

