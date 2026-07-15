/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/conf/base.h"

/*!
 * Migrates from an old configuration schema.
 *
 * \param[in] conf  Configuration.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_migrate(
	conf_t *conf
);

/*!
 * Migrates from LMDB version 0.9 to the present one.
 *
 * \param[in] db_dir    Path to the migrated LMDB directory.
 * \param[in] named_db  Indication of a named database.
 *
 * \return Error code, KNOT_EOK if success.
 */
int migrate_lmdb(
	const char *db_dir,
	bool named_db
);
