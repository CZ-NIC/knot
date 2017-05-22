/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include <tap/basic.h>
#include <tap/files.h>

#include "libknot/libknot.h"
#include "test_conf.h"
#include "knot/dnssec/kasp/kasp_db.c"

#define CHARS500_1 "kTZgFfrHPP2EOSK24zRjY9GlgCUEkZNBF5UwqsTWisCxGQT4ieinitjXWT1c" \
                   "pj+OR8UX/httSugee+MFsm5yOU/4/211BpLKwwOIAt4Yf8K7Bc+oXTdk15cH" \
                   "TRZtshM1AtfjRsX9rsLDsnaFCyMXzty9AQoRxSphjxnUUC6fszfrSsRx7htl" \
                   "/Xn1PAuwp9Bfn+FxAws98LYVuwiDqUgn4BR5lELdGd16zNOZnN7v023pmPDM" \
                   "nGyvIATuqTCPbFeXTfw7aIDyx2DF+y95/kSnPtY3c1b0Yf+oCv4t3Hx2jjWT" \
                   "9zuC6H+d+PL6HWqilJBs7ysn2FVpnE/Yo44VrQ8orw8QFZr1kR6z7AOVAcMk" \
                   "ac+44swsc8orGCyJx6OlUfN5oU3YahUfLqg9ewl13+P2chmeI6wUyttKsq/4" \
                   "Ud0YQAozBabiAKr1O/Eg7sZR6bV1YkCydQyYgmR/+VOu9D8Ld6uO4DcvhiE/" \
                   "2AmTkLsKLxtpMnQqsTnx"
#define CHARS500_2 "pzqkMLvpxUYYg0KuMCcBsk9aMm4b5Ny+vJ5UnTq8DVC0jHJJyyGcljKqfpi3" \
                   "MkjfrWY0rbzXFZbZZ6i8bmhhRBcSxE+tK/3AU1LR7ZJsTuITuoJo5LKRH7Uu" \
                   "MU7RBAzFuk3o+Pcyk+9UdbiRn9p4QqPTvb+2xfYn1pJvGHofJcQsSsPEe9Hw" \
                   "ycVW+kdImvWiidn0/e1G6B2xibovnPKDUBFmTbdZIBKHb/eUUoUCNA9CWt5N" \
                   "g8MutK2ixlBJlOvA6CA1V/VW56EJpLqvMxLaoRks5VY5Ls7zWAy97GEFH0Pl" \
                   "uO/Rba1du5tsC0MAC08hljlmu9uoPhsvHdBYHUnQ7jDuYnu9GN3DN0Z6oVbV" \
                   "N01JQZYhKQK/Bl61oM5JubLydtAypryDoG3IH75LhoVC8iGxDoDkxt3zoi/Q" \
                   "PVfPZZsm5j5UOs3wrQL0KWylm2IDK42mrHK8F/XebnOYLNLQaan2a90C+fhH" \
                   "a6hvu0RorkZzGNAZkq/D"

const knot_dname_t *zone1 = (const knot_dname_t *)"\x05""zonea";
const knot_dname_t *zone2 = (const knot_dname_t *)"\x05""zoneb";

kasp_db_t *db;

const key_params_t params1 = { .id = "key id 1", .keytag = 1, .timing = { 1, 11, 111, 1111, 11111 },
                               .public_key = { 520, (uint8_t *)"pk1 plus 500 chars: " CHARS500_1 } };
const key_params_t params2 = { .id = "key id 2", .keytag = 2, .timing = { 2, 22, 222, 2222, 22222 },
                               .public_key = { 520, (uint8_t *)"pk2 plus 500 chars: " CHARS500_2 } };

bool params_eq(const key_params_t *a, const key_params_t *b)
{
	return ((a->keytag == b->keytag) && (a->public_key.size == b->public_key.size) &&
	        (a->timing.retire == b->timing.retire) && (strcmp(a->id, b->id) == 0) &&
	        (memcmp(a->public_key.data, b->public_key.data, b->public_key.size) == 0));
}

int main(int argc, char *argv[])
{
	plan_lazy();

	char *test_dir_name = test_mkdtemp();
	bool ignore = false;
	
	list_t l;
	key_params_t *params;
#define free_params free(params->id); free(params->public_key.data); params->id = NULL; params->public_key.data = NULL;

	int ret = kasp_db_init(&db, test_dir_name, 500*1024*1024);
	is_int(KNOT_EOK, ret, "kasp_db: init eok");
	ret = kasp_db_open(db);
	is_int(KNOT_EOK, ret, "kasp_db: open eok");
	ok(db->keys_db != NULL, "kasp_db: keys db notnull");

	ret = kasp_db_add_key(db, zone1, &params1);
	is_int(KNOT_EOK, ret, "kasp_db: add key 1 eok");

	ret = kasp_db_list_keys(db, zone1, &l);
	is_int(KNOT_EOK, ret, "kasp_db: list keys 1 eok");
	is_int(1, list_size(&l), "kasp_db: list keys reports one key 1");
	params = ((ptrnode_t *)HEAD(l))->d;
	ok(params_eq(params, &params1), "kasp_db: key params equal 1");
	free_params
	ptrlist_deep_free(&l, NULL);

	ret = kasp_db_list_keys(db, zone2, &l);
	is_int(KNOT_ENOENT, ret, "kasp_db: list keys 1 enoent");
	is_int(0, list_size(&l), "kasp_db: list keys reports no keys 1");
	ptrlist_deep_free(&l, NULL);

	ret = kasp_db_share_key(db, zone1, zone2, params1.id);
	is_int(KNOT_EOK, ret, "kasp_db: share key eok");

	ret = kasp_db_list_keys(db, zone2, &l);
	is_int(KNOT_EOK, ret, "kasp_db: list keys 3 eok");
	is_int(1, list_size(&l), "kasp_db: list keys reports one key 2");
	params = ((ptrnode_t *)HEAD(l))->d;
	free_params
	ptrlist_deep_free(&l, NULL);

	ret = kasp_db_add_key(db, zone2, &params2);
	is_int(KNOT_EOK, ret, "kasp_db: add key 2 eok");

	ret = kasp_db_list_keys(db, zone2, &l);
	is_int(KNOT_EOK, ret, "kasp_db: list keys 4 eok");
	is_int(2, list_size(&l), "kasp_db: list keys reports two keys 1");
	params = ((ptrnode_t *)TAIL(l))->d;
	ok(params_eq(params, &params2), "kasp_db: key params equal 2");
	free_params
	params = ((ptrnode_t *)HEAD(l))->d;
	free_params
	ptrlist_deep_free(&l, NULL);

	ret = kasp_db_delete_key(db, zone1, params1.id, &ignore);
	is_int(KNOT_EOK, ret, "kasp_db: delete key 1 eok");

	ret = kasp_db_list_keys(db, zone1, &l);
	is_int(KNOT_ENOENT, ret, "kasp_db: list keys 2 enoent");
	is_int(list_size(&l), 0, "kasp_db: list keys reports no keys 2");
	ptrlist_deep_free(&l, NULL);

	kasp_db_close(&db);

	test_rm_rf(test_dir_name);
	free(test_dir_name);

	return 0;
}

