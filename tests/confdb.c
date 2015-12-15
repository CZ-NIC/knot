/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <tap/basic.h>

#include "test_conf.h"
#include "knot/conf/confdb.c"

static void check_db_content(conf_t *conf, knot_db_txn_t *txn, int count)
{
	ok(db_check_version(conf, txn) == KNOT_EOK, "Version check");
	if (count >= 0) {
		ok(conf->api->count(txn) == 1 + count, "Check DB entries count");
	}
}

static void check_code(
	conf_t *conf,
	knot_db_txn_t *txn,
	uint8_t section_code,
	const yp_name_t *name,
	db_action_t action,
	int ret,
	uint8_t ref_code)
{
	uint8_t code;
	ok(db_code(conf, txn, section_code, name, action, &code) == ret,
	   "Compare DB code return");

	if (ret != KNOT_EOK) {
		return;
	}

	uint8_t k[64] = { section_code, 0 };
	memcpy(k + 2, name + 1, name[0]);
	knot_db_val_t key = { .data = k, .len = 2 + name[0] };
	knot_db_val_t val;

	ret = conf->api->find(txn, &key, &val, 0);
	switch (action) {
	case DB_GET:
	case DB_SET:
		ok(code == ref_code, "Compare DB code");
		ok(ret == KNOT_EOK, "Find DB code");
		ok(val.len == 1, "Compare DB code length");
		ok(((uint8_t *)val.data)[0] == code, "Compare DB code value");
		break;
	case DB_DEL:
		ok(ret == KNOT_ENOENT, "Find item code");
		break;
	}
}

static void test_db_code(conf_t *conf, knot_db_txn_t *txn)
{
	// Add codes.
	check_code(conf, txn, 0, C_SERVER, DB_SET, KNOT_EOK, KEY1_FIRST);
	check_db_content(conf, txn, 1);
	check_code(conf, txn, 0, C_LOG, DB_SET, KNOT_EOK, KEY1_FIRST + 1);
	check_db_content(conf, txn, 2);
	check_code(conf, txn, 2, C_IDENT, DB_SET, KNOT_EOK, KEY1_FIRST);
	check_db_content(conf, txn, 3);
	check_code(conf, txn, 0, C_ZONE, DB_SET, KNOT_EOK, KEY1_FIRST + 2);
	check_db_content(conf, txn, 4);
	check_code(conf, txn, 2, C_VERSION, DB_SET, KNOT_EOK, KEY1_FIRST + 1);
	check_db_content(conf, txn, 5);

	// Add existing code (no change).
	check_code(conf, txn, 0, C_SERVER, DB_SET, KNOT_EOK, KEY1_FIRST);
	check_db_content(conf, txn, 5);

	// Get codes.
	check_code(conf, txn, 0, C_SERVER, DB_GET, KNOT_EOK, KEY1_FIRST);
	check_db_content(conf, txn, 5);
	check_code(conf, txn, 0, C_RMT, DB_GET, KNOT_ENOENT, 0);
	check_db_content(conf, txn, 5);

	// Delete not existing code.
	check_code(conf, txn, 0, C_COMMENT, DB_DEL, KNOT_ENOENT, 0);
	check_db_content(conf, txn, 5);

	// Delete codes.
	check_code(conf, txn, 0, C_SERVER, DB_DEL, KNOT_EOK, 0);
	check_db_content(conf, txn, 4);
	check_code(conf, txn, 2, C_IDENT, DB_DEL, KNOT_EOK, 0);
	check_db_content(conf, txn, 3);

	// Reuse deleted codes.
	check_code(conf, txn, 0, C_ACL, DB_SET, KNOT_EOK, KEY1_FIRST);
	check_db_content(conf, txn, 4);
	check_code(conf, txn, 2, C_NSID, DB_SET, KNOT_EOK, KEY1_FIRST);
	check_db_content(conf, txn, 5);
}

static void check_set(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *key0,
	const yp_name_t *key1,
	const uint8_t *id,
	size_t id_len,
	int ret,
	const uint8_t *data,
	size_t data_len,
	const uint8_t *exp_data,
	size_t exp_data_len)
{
	ok(conf_db_set(conf, txn, key0, key1, id, id_len, data, data_len) == ret,
	   "Check set return");

	if (ret != KNOT_EOK || (key1 == NULL && id == NULL)) {
		return;
	}

	uint8_t section_code, item_code;
	ok(db_code(conf, txn, KEY0_ROOT, key0, DB_GET, &section_code) == KNOT_EOK,
	   "Get DB section code");
	if (key1 != NULL) {
		ok(db_code(conf, txn, section_code, key1, DB_GET, &item_code) == KNOT_EOK,
		   "Get DB item code");
	} else {
		item_code = KEY1_ID;
	}

	uint8_t k[64] = { section_code, item_code };
	if (id != NULL) {
		memcpy(k + 2, id, id_len);
	}
	knot_db_val_t key = { .data = k, .len = 2 + id_len };
	knot_db_val_t val;

	ok(conf->api->find(txn, &key, &val, 0) == KNOT_EOK, "Get inserted data");
	ok(val.len == exp_data_len, "Compare data length");
	ok(memcmp(val.data, exp_data, exp_data_len) == 0, "Compare data");

	check_db_content(conf, txn, -1);
}

static void test_conf_db_set(conf_t *conf, knot_db_txn_t *txn)
{
	// Set section without item - noop.
	check_set(conf, txn, C_INCL, NULL, NULL, 0, KNOT_EOK, NULL, 0, NULL, 0);

	// Set singlevalued item.
	check_set(conf, txn, C_SERVER, C_RUNDIR, NULL, 0, KNOT_EOK,
	          (uint8_t *)"\0", 1, (uint8_t *)"\0", 1);
	check_set(conf, txn, C_SERVER, C_RUNDIR, NULL, 0, KNOT_EOK,
	          (uint8_t *)"a b\0", 4, (uint8_t *)"a b\0", 4);

	// Set multivalued item.
	check_set(conf, txn, C_SERVER, C_LISTEN, NULL, 0, KNOT_EOK,
	          (uint8_t *)"\0", 1, (uint8_t *)"\x00\x01""\0", 3);
	check_set(conf, txn, C_SERVER, C_LISTEN, NULL, 0, KNOT_EOK,
	          (uint8_t *)"a\0", 2, (uint8_t *)"\x00\x01""\0""\x00\x02""a\0", 7);
	check_set(conf, txn, C_SERVER, C_LISTEN, NULL, 0, KNOT_EOK,
	          (uint8_t *)"b\0", 2, (uint8_t *)"\x00\x01""\0""\x00\x02""a\0""\x00\x02""b\0", 11);

	// Set group id.
	check_set(conf, txn, C_ZONE, NULL, (uint8_t *)"id", 2, KNOT_EOK,
	          NULL, 0, (uint8_t *)"", 0);

	// Set singlevalued item with id.
	check_set(conf, txn, C_ZONE, C_FILE, (uint8_t *)"id", 2, KNOT_EOK,
	          (uint8_t *)"\0", 1, (uint8_t *)"\0", 1);
	check_set(conf, txn, C_ZONE, C_FILE, (uint8_t *)"id", 2, KNOT_EOK,
	          (uint8_t *)"a b\0", 4, (uint8_t *)"a b\0", 4);

	// Set multivalued item with id.
	check_set(conf, txn, C_ZONE, C_MASTER, (uint8_t *)"id", 2, KNOT_EOK,
	          (uint8_t *)"\0", 1, (uint8_t *)"\x00\x01""\0", 3);
	check_set(conf, txn, C_ZONE, C_MASTER, (uint8_t *)"id", 2, KNOT_EOK,
	          (uint8_t *)"a\0", 2, (uint8_t *)"\x00\x01""\0""\x00\x02""a\0", 7);
	check_set(conf, txn, C_ZONE, C_MASTER, (uint8_t *)"id", 2, KNOT_EOK,
	          (uint8_t *)"b\0", 2, (uint8_t *)"\x00\x01""\0""\x00\x02""a\0""\x00\x02""b\0", 11);

	// ERR set invalid section.
	check_set(conf, txn, C_MASTER, NULL, NULL, 0, KNOT_YP_EINVAL_ITEM,
	          NULL, 0, NULL, 0);

	// ERR set invalid item.
	check_set(conf, txn, C_SERVER, C_DOMAIN, NULL, 0, KNOT_YP_EINVAL_ITEM,
	          NULL, 0, NULL, 0);

	// ERR redefine section id.
	check_set(conf, txn, C_ZONE, NULL, (uint8_t *)"id", 2, KNOT_CONF_EREDEFINE,
	          NULL, 0, NULL, 0);

	// ERR set singlevalued item with non-existing id.
	check_set(conf, txn, C_ZONE, C_FILE, (uint8_t *)"idx", 3, KNOT_YP_EINVAL_ID,
	          NULL, 0, NULL, 0);
}

static void check_get(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *key0,
	const yp_name_t *key1,
	const uint8_t *id,
	size_t id_len,
	int ret,
	const uint8_t *exp_data,
	size_t exp_data_len)
{
	conf_val_t val;
	ok(conf_db_get(conf, txn, key0, key1, id, id_len, &val) == ret,
	   "Check get return");

	if (ret != KNOT_EOK) {
		return;
	}

	ok(val.blob_len == exp_data_len, "Compare data length");
	ok(memcmp(val.blob, exp_data, exp_data_len) == 0, "Compare data");

	check_db_content(conf, txn, -1);
}

static void test_conf_db_get(conf_t *conf, knot_db_txn_t *txn)
{
	// Get singlevalued item.
	check_get(conf, txn, C_SERVER, C_RUNDIR, NULL, 0, KNOT_EOK,
	          (uint8_t *)"a b\0", 4);

	// Get multivalued item.
	check_get(conf, txn, C_SERVER, C_LISTEN, NULL, 0, KNOT_EOK,
	          (uint8_t *)"\x00\x01""\0""\x00\x02""a\0""\x00\x02""b\0", 11);

	// Get group id.
	check_get(conf, txn, C_ZONE, NULL, (uint8_t *)"id", 2, KNOT_EOK,
	          (uint8_t *)"", 0);

	// Get singlevalued item with id.
	check_get(conf, txn, C_ZONE, C_FILE, (uint8_t *)"id", 2, KNOT_EOK,
	          (uint8_t *)"a b\0", 4);

	// Get multivalued item with id.
	check_get(conf, txn, C_ZONE, C_MASTER, (uint8_t *)"id", 2, KNOT_EOK,
	          (uint8_t *)"\x00\x01""\0""\x00\x02""a\0""\x00\x02""b\0", 11);

	// ERR get section without item.
	check_get(conf, txn, C_INCL, NULL, NULL, 0, KNOT_EINVAL, NULL, 0);

	// ERR get invalid section.
	check_get(conf, txn, C_MASTER, NULL, NULL, 0, KNOT_YP_EINVAL_ITEM,
	          NULL, 0);

	// ERR get invalid item.
	check_get(conf, txn, C_SERVER, C_DOMAIN, NULL, 0, KNOT_YP_EINVAL_ITEM,
	          NULL, 0);

	// ERR get singlevalued item with non-existing id.
	check_get(conf, txn, C_ZONE, C_FILE, (uint8_t *)"idx", 3, KNOT_YP_EINVAL_ID,
	          NULL, 0);
}

static void check_unset(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *key0,
	const yp_name_t *key1,
	const uint8_t *id,
	size_t id_len,
	int ret,
	const uint8_t *data,
	size_t data_len,
	const uint8_t *exp_data,
	size_t exp_data_len)
{
	ok(conf_db_unset(conf, txn, key0, key1, id, id_len, data, data_len, false) == ret,
	   "Check unset return");

	if (ret != KNOT_EOK) {
		return;
	}

	uint8_t section_code, item_code;
	ok(db_code(conf, txn, KEY0_ROOT, key0, DB_GET, &section_code) == KNOT_EOK,
	   "Get DB section code");
	if (key1 != NULL) {
		ok(db_code(conf, txn, section_code, key1, DB_GET, &item_code) == KNOT_EOK,
		   "Get DB item code");
	} else {
		item_code = KEY1_ID;
	}

	uint8_t k[64] = { section_code, item_code };
	if (id != NULL) {
		memcpy(k + 2, id, id_len);
	}
	knot_db_val_t key = { .data = k, .len = 2 + id_len };
	knot_db_val_t val;

	ret = conf->api->find(txn, &key, &val, 0);
	if (exp_data != NULL) {
		ok(ret == KNOT_EOK, "Get deleted data");
		ok(val.len == exp_data_len, "Compare data length");
		ok(memcmp(val.data, exp_data, exp_data_len) == 0, "Compare data");
	} else {
		ok(ret == KNOT_ENOENT, "Get deleted data");
	}

	check_db_content(conf, txn, -1);
}

static void check_unset_key(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *key0,
	const yp_name_t *key1,
	const uint8_t *id,
	size_t id_len,
	int ret)
{
	ok(conf_db_unset(conf, txn, key0, key1, id, id_len, NULL, 0, true) == ret,
	   "Check unset return");

	if (ret != KNOT_EOK) {
		return;
	}

	uint8_t section_code, item_code;
	ret = db_code(conf, txn, KEY0_ROOT, key0, DB_GET, &section_code);
	if (key1 == NULL && id_len == 0) {
		ok(ret == KNOT_ENOENT, "Get DB section code");
	} else {
		ok(ret == KNOT_EOK, "Get DB section code");
		ret = db_code(conf, txn, section_code, key1, DB_GET, &item_code);
		ok(ret == KNOT_ENOENT, "Get DB item code");
	}

	check_db_content(conf, txn, -1);
}

static void test_conf_db_unset(conf_t *conf, knot_db_txn_t *txn)
{
	// ERR unset section without item.
	check_unset(conf, txn, C_INCL, NULL, NULL, 0, KNOT_ENOENT,
	            NULL, 0, NULL, 0);

	// ERR unset invalid section.
	check_unset(conf, txn, C_MASTER, NULL, NULL, 0, KNOT_YP_EINVAL_ITEM,
	            NULL, 0, NULL, 0);

	// ERR unset invalid item.
	check_unset(conf, txn, C_SERVER, C_DOMAIN, NULL, 0, KNOT_YP_EINVAL_ITEM,
	            NULL, 0, NULL, 0);

	// ERR unset singlevalued item with non-existing id.
	check_unset(conf, txn, C_ZONE, C_FILE, (uint8_t *)"idx", 3, KNOT_YP_EINVAL_ID,
	            NULL, 0, NULL, 0);

	// ERR unset singlevalued item invalid value.
	check_unset(conf, txn, C_SERVER, C_RUNDIR, NULL, 0, KNOT_ENOENT,
	            (uint8_t *)"x\0", 2, NULL, 0);

	// Unset singlevalued item data.
	check_unset(conf, txn, C_SERVER, C_RUNDIR, NULL, 0, KNOT_EOK,
	            (uint8_t *)"a b\0", 4, NULL, 0);
	// Unset item.
	check_unset_key(conf, txn, C_SERVER, C_RUNDIR, NULL, 0, KNOT_EOK);

	// Unset multivalued item.
	check_unset(conf, txn, C_SERVER, C_LISTEN, NULL, 0, KNOT_EOK,
	            (uint8_t *)"a", 2, (uint8_t *)"\x00\x01""\0""\x00\x02""b\0", 7);
	check_unset(conf, txn, C_SERVER, C_LISTEN, NULL, 0, KNOT_EOK,
	            (uint8_t *)"", 1, (uint8_t *)"\x00\x02""b\0", 4);
	check_unset(conf, txn, C_SERVER, C_LISTEN, NULL, 0, KNOT_EOK,
	            (uint8_t *)"b", 2, NULL, 0);
	// Unset item.
	check_unset_key(conf, txn, C_SERVER, C_LISTEN, NULL, 0, KNOT_EOK);
	// Unset section.
	check_unset_key(conf, txn, C_SERVER, NULL, NULL, 0, KNOT_EOK);

	// Unset singlevalued item with id - all data at one step.
	check_unset(conf, txn, C_ZONE, C_FILE, (uint8_t *)"id", 2, KNOT_EOK,
	            NULL, 0, NULL, 0);

	// Unset multivalued item with id - all data at one step (non-null data!).
	check_unset(conf, txn, C_ZONE, C_MASTER, (uint8_t *)"id", 2, KNOT_EOK,
	          NULL + 1, 0, NULL, 0);

	// Unset group id.
	check_unset(conf, txn, C_ZONE, NULL, (uint8_t *)"id", 2, KNOT_EOK,
	            NULL, 0, NULL, 0);
}

static void test_conf_db_iter(conf_t *conf, knot_db_txn_t *txn)
{
	const size_t total = 4;
	char names[][10] = { "alfa", "beta", "delta", "epsilon" };

	// Prepare identifiers to iterate through.
	for (size_t i = 0; i < total; i++) {
		check_set(conf, txn, C_RMT, NULL, (uint8_t *)names[i],
		          strlen(names[i]), KNOT_EOK, NULL, 0, (uint8_t *)"", 0);
	}

	// Create section iterator.
	conf_iter_t iter;
	int ret = conf_db_iter_begin(conf, txn, C_RMT, &iter);
	ok(ret == KNOT_EOK, "Create iterator");

	// Iterate through the section.
	size_t count = 0;
	while (ret == KNOT_EOK) {
		const uint8_t *id;
		size_t id_len;
		ret = conf_db_iter_id(conf, &iter, &id, &id_len);
		ok(ret == KNOT_EOK, "Get iteration id");
		ok(id_len == strlen(names[count]), "Compare iteration id length");
		ok(memcmp(id, names[count], id_len) == 0, "Compare iteration id");

		ok(conf_db_iter_del(conf, &iter) == KNOT_EOK, "Delete iteration key");

		count++;
		ret = conf_db_iter_next(conf, &iter);
	}
	ok(ret == KNOT_EOF, "Finished iteration");
	ok(count == total, "Check iteration count");

	// Check empty section.
	ret = conf_db_iter_begin(conf, txn, C_RMT, &iter);
	ok(ret == KNOT_ENOENT, "Create iterator");

	// ERR non-iterable section.
	ok(conf_db_iter_begin(conf, txn, C_SERVER, &iter) == KNOT_ENOTSUP, "Create iterator");

	// ERR empty section.
	ok(conf_db_iter_begin(conf, txn, C_ZONE, &iter) == KNOT_ENOENT, "Create iterator");

	// ERR section with no code.
	ok(conf_db_iter_begin(conf, txn, C_LOG, &iter) == KNOT_ENOENT, "Create iterator");
}

int main(int argc, char *argv[])
{
	plan_lazy();

	ok(test_conf("", NULL) == KNOT_EOK, "Prepare configuration");
	check_db_content(conf(), &conf()->read_txn, 0);

	knot_db_txn_t txn;
	ok(conf()->api->txn_begin(conf()->db, &txn, 0) == KNOT_EOK, "Begin transaction");

	diag("db_code");
	test_db_code(conf(), &txn);

	conf()->api->txn_abort(&txn);

	ok(conf()->api->txn_begin(conf()->db, &txn, 0) == KNOT_EOK, "Begin transaction");

	diag("conf_db_set");
	test_conf_db_set(conf(), &txn);

	diag("conf_db_get");
	test_conf_db_get(conf(), &txn);

	diag("conf_db_unset");
	test_conf_db_unset(conf(), &txn);

	conf()->api->txn_abort(&txn);

	ok(conf()->api->txn_begin(conf()->db, &txn, 0) == KNOT_EOK, "Begin transaction");

	diag("conf_db_iter");
	test_conf_db_iter(conf(), &txn);

	conf()->api->txn_abort(&txn);

	conf_free(conf(), false);

	return 0;
}
