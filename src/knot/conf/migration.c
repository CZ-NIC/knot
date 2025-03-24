/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/common/log.h"
#include "knot/conf/migration.h"
#include "knot/conf/confdb.h"

/*
static void try_unset(conf_t *conf, knot_db_txn_t *txn, yp_name_t *key0, yp_name_t *key1)
{
	int ret = conf_db_unset(conf, txn, key0, key1, NULL, 0, NULL, 0, true);
	if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
		log_warning("conf, migration, failed to unset '%s%s%s' (%s)",
		            key0 + 1,
		            (key1 != NULL) ? "/"      : "",
		            (key1 != NULL) ? key1 + 1 : "",
		            knot_strerror(ret));
	}
}

#define check_set(conf, txn, key0, key1, id, id_len, data, data_len) \
	ret = conf_db_set(conf, txn, key0, key1, id, id_len, data, data_len); \
	if (ret != KNOT_EOK && ret != KNOT_CONF_EREDEFINE) { \
		log_error("conf, migration, failed to set '%s%s%s' (%s)", \
		          key0 + 1, \
		          (key1 != NULL) ? "/"      : "", \
		          (key1 != NULL) ? key1 + 1 : "", \
		          knot_strerror(ret)); \
		return ret; \
	}

static int migrate_(
	conf_t *conf,
	knot_db_txn_t *txn)
{
	return KNOT_EOK;
}
*/

int conf_migrate(
	conf_t *conf)
{
	return KNOT_EOK;
	/*
	if (conf == NULL) {
		return KNOT_EINVAL;
	}

	knot_db_txn_t txn;
	int ret = conf->api->txn_begin(conf->db, &txn, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = migrate_(conf, &txn);
	if (ret != KNOT_EOK) {
		conf->api->txn_abort(&txn);
		return ret;
	}

	ret = conf->api->txn_commit(&txn);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return conf_refresh_txn(conf);
	*/
}
