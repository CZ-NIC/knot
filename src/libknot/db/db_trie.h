/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \addtogroup db
 * @{
 */

#pragma once

#include "libknot/db/db.h"

/* Native options. */
struct knot_db_trie_opts {
	unsigned unused;
};

/* Default options. */
#define KNOT_DB_TRIE_OPTS_INITIALIZER { \
	0 \
}

const knot_db_api_t *knot_db_trie_api(void);

/*! @} */
