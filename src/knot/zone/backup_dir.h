/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/zone/backup.h"

/*!
 * Prepares the backup directory - verifies it exists and creates it for backup
 * if it's needed. Verifies existence/non-existence of a lock file and a label file,
 * in the backup mode it creates them, in the restore mode, it sets ctx->backup_format
 * and ctx->in_backup.
 *
 * \param[in/out] ctx   Backup context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int backupdir_init(zone_backup_ctx_t *ctx);

/*!
 * If the backup has been successful, it creates the label file
 * and removes the lock file. It does nothing in the restore mode.
 *
 * \param[in] ctx   Backup context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int backupdir_deinit(zone_backup_ctx_t *ctx);
