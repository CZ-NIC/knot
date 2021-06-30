/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz> 
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "knot/zone/backup.h"

/*!
 * Prepares the backup directory - verifies it exists and creates it for backup
 * if it's needed. Verifies existence/non-existence of a lock file and a label file,
 * in the backup mode it creates them, in the restore mode it sets ctx->backup_format.
 *
 * \param[in/out] ctx   Backup context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int backupdir_init(zone_backup_ctx_t *ctx);

/*!
 * If the backup has been successful, it creates the label file
 * and removes the lock file. Do nothing in the restore mode.
 *
 * \param[in] ctx   Backup context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int backupdir_deinit(zone_backup_ctx_t *ctx);
