/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

knot_lmdb_db_t _db, *db = &_db;

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

static void init_key_records(key_records_t *r)
{
	knot_rrset_init(&r->dnskey, knot_dname_copy(zone1, NULL),
	                KNOT_RRTYPE_DNSKEY, KNOT_CLASS_IN, 3600);
	knot_rrset_init(&r->cdnskey, knot_dname_copy(zone1, NULL),
	                KNOT_RRTYPE_CDNSKEY, KNOT_CLASS_IN, 0);
	knot_rrset_init(&r->cds, knot_dname_copy(zone1, NULL),
	                KNOT_RRTYPE_CDS, KNOT_CLASS_IN, 0);
	knot_rrset_init(&r->rrsig, knot_dname_copy(zone1, NULL),
	                KNOT_RRTYPE_RRSIG, KNOT_CLASS_IN, 3600);
	knot_rrset_add_rdata(&r->rrsig, (uint8_t *)CHARS500_1, 500, NULL);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	char *test_dir_name = test_mkdtemp();
	bool ignore = false;
	
	list_t l;
	key_params_t *params;
#define free_params free(params->id); free(params->public_key.data); params->id = NULL; params->public_key.data = NULL;

	knot_lmdb_init(db, test_dir_name, 500*1024*1024, 0, "keys_db");
	int ret = knot_lmdb_open(db);
	is_int(KNOT_EOK, ret, "kasp_db: open eok");
	ok(db->env != NULL, "kasp_db: lmdb env notnull");

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

	dnssec_binary_t salt1 = { 500, (uint8_t *)CHARS500_1 }, salt2 = { 0 };
	knot_time_t time;
	ret = kasp_db_store_nsec3salt(db, zone1, &salt1, 1234);
	is_int(KNOT_EOK, ret, "kasp_db: store nsec3salt");
	ret = kasp_db_load_nsec3salt(db, zone1, &salt2, &time);
	is_int(KNOT_EOK, ret, "kasp_db: load nsec3salt");
	is_int(1234, time, "kasp_db: salt_created preserved");
	is_int(0, dnssec_binary_cmp(&salt1, &salt2), "kasp_db: salt preserved");
	dnssec_binary_free(&salt2);
	salt1.size = 0;
	ret = kasp_db_store_nsec3salt(db, zone2, &salt1, 0);
	is_int(KNOT_EOK, ret, "kasp_db: store empty nsec3salt");
	ret = kasp_db_load_nsec3salt(db, zone2, &salt2, &time);
	is_int(KNOT_EOK, ret, "kasp_db: load empty nsec3salt");
	is_int(0, time, "kasp_db: empty salt_created preserved");
	is_int(0, salt2.size, "kasp_db: empty salt preserved");
	dnssec_binary_free(&salt2);

	ret = kasp_db_delete_all(db, zone2);
	is_int(KNOT_EOK, ret, "kasp_db: delete all");
	ret = kasp_db_list_keys(db, zone2, &l);
	is_int(KNOT_ENOENT, ret, "kasp_db: delete all deleted keys");
	ret = kasp_db_load_nsec3salt(db, zone2, &salt2, &time);
	is_int(KNOT_ENOENT, ret, "kasp_db: delete all removed nsec3salt");

	ret = kasp_db_store_serial(db, zone2, KASPDB_SERIAL_MASTER, 1);
	is_int(KNOT_EOK, ret, "kasp_db: store master_serial");
	ret = kasp_db_store_serial(db, zone2, KASPDB_SERIAL_LASTSIGNED, 2);
	is_int(KNOT_EOK, ret, "kasp_db: store lastsigned_serial");
	uint32_t serial = 0;
	ret = kasp_db_load_serial(db, zone2, KASPDB_SERIAL_MASTER, &serial);
	is_int(KNOT_EOK, ret, "kasp_db: load master_serial");
	is_int(1, serial, "kasp_db: master_serial preserved");
	ret = kasp_db_load_serial(db, zone2, KASPDB_SERIAL_LASTSIGNED, &serial);
	is_int(KNOT_EOK, ret, "kasp_db: load lastsigned_serial");
	is_int(2, serial, "kasp_db: lastsigned_serial preserved");

	ret = kasp_db_list_zones(db, &l);
	is_int(KNOT_EOK, ret, "kasp_db: list_zones");
	is_int(2, list_size(&l), "kasp_db: reports two zones");
	is_int(0, knot_dname_cmp(((ptrnode_t *)HEAD(l))->d, zone1) | knot_dname_cmp(((ptrnode_t *)TAIL(l))->d, zone2), "kasp_db: listed correct zones");
	ptrlist_deep_free(&l, NULL);

	assert(kasp_db_add_key(db, zone1, &params1) == KNOT_EOK);
	assert(kasp_db_add_key(db, zone2, &params2) == KNOT_EOK);

	ret = kasp_db_set_policy_last(db, "policy1", NULL, zone1, params1.id);
	is_int(KNOT_EOK, ret, "kasp_db: set policylast");
	knot_dname_t *zoneX;
	char *keyidX;
	ret = kasp_db_get_policy_last(db, "policy1", &zoneX, &keyidX);
	is_int(KNOT_EOK, ret, "kasp_db: get policylast");
	is_int(0, knot_dname_cmp(zoneX, zone1) | strcmp(keyidX, params1.id), "kasp_db: policy last preserved");
	free(zoneX);
	free(keyidX);
	ret = kasp_db_set_policy_last(db, "policy1", params1.id, zone2, params2.id);
	is_int(KNOT_EOK, ret, "kasp_db: reset policylast");
	ret = kasp_db_get_policy_last(db, "policy1", &zoneX, &keyidX);
	is_int(KNOT_EOK, ret, "kasp_db: reget policylast");
	is_int(0, knot_dname_cmp(zoneX, zone2) | strcmp(keyidX, params2.id), "kasp_db: policy last represerved");
	free(zoneX);
	free(keyidX);
	ret = kasp_db_set_policy_last(db, "policy1", params1.id, zone1, params1.id);
	is_int(KNOT_ESEMCHECK, ret, "kasp_db: refused policylast with wrong keyid");
	ret = kasp_db_get_policy_last(db, "policy1", &zoneX, &keyidX);
	is_int(KNOT_EOK, ret, "kasp_db: reget policylast2");
	is_int(0, knot_dname_cmp(zoneX, zone2) | strcmp(keyidX, params2.id), "kasp_db: policy last represerved2");
	free(zoneX);
	free(keyidX);

	key_records_t kr;
	init_key_records(&kr);
	ret = kasp_db_store_offline_records(db, 1, &kr);
	is_int(KNOT_EOK, ret, "kasp_db: store key records");
	//key_records_clear_rdatasets(&kr);
	ret = kasp_db_load_offline_records(db, zone1, 2, &time, &kr);
	is_int(KNOT_EOK, ret, "kasp_db: load key records");
	ok(kr.cds.type == KNOT_RRTYPE_CDS && kr.rrsig.rrs.count == 1, "kasp_db: key records ok");
	is_int(0, time, "kasp_db: no next key records");
	key_records_clear(&kr);
	ret = kasp_db_delete_offline_records(db, zone1, 1, 3);
	is_int(KNOT_EOK, ret, "kasp_db: delete key records");
	ret = kasp_db_load_offline_records(db, zone1, 2, &time, &kr);
	is_int(KNOT_ENOENT, ret, "kasp_db: no more key records");

	knot_lmdb_deinit(db);

	test_rm_rf(test_dir_name);
	free(test_dir_name);

	return 0;
}

