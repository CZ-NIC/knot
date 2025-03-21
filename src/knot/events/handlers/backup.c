/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <urcu.h>

#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/events/handlers.h"
#include "knot/zone/backup.h"

int event_backup(conf_t *conf, zone_t *zone)
{
	assert(zone);

	zone_backup_ctx_t *ctx = ATOMIC_GET(zone->backup_ctx);
	if (ctx == NULL) {
		return KNOT_EINVAL;
	}

	int ret, ret_deinit;
	bool restore = ctx->restore_mode;

	if (!restore && ctx->failed) {
		// No need to proceed with already faulty backup.
		ret = KNOT_EOK;
		goto done;
	}

	if (restore) {
		// expire zone
		zone_contents_t *expired = zone_switch_contents(zone, NULL);
		synchronize_rcu();
		knot_sem_wait(&zone->cow_lock);
		zone_contents_deep_free(expired);
		knot_sem_post(&zone->cow_lock);
		zone->zonefile.exists = false;
	}

	ret = zone_backup(conf, zone);
	if (ret == KNOT_EOK) {
		log_zone_info(zone->name, "zone %s '%s'",
		              restore ? "restored from" : "backed up to",
		              ctx->backup_dir);
	} else {
		log_zone_warning(zone->name, "zone %s failed (%s)",
		                 restore ? "restore" : "backup", knot_strerror(ret));
	}

	if (restore && ret == KNOT_EOK) {
		zone_reset(conf, zone);
	}

done:
	ret_deinit = zone_backup_deinit(ctx);
	ATOMIC_SET(zone->backup_ctx, NULL);
	return (ret != KNOT_EOK) ? ret : ret_deinit;
}
