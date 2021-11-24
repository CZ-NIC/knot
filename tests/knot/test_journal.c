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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <tap/basic.h>
#include <tap/files.h>

#include "knot/journal/journal_read.h"
#include "knot/journal/journal_write.h"

#include "libknot/attribute.h"
#include "libknot/libknot.h"
#include "knot/zone/zone.h"
#include "knot/zone/zone-diff.h"
#include "test_conf.h"

#define RAND_RR_LABEL 16
#define RAND_RR_PAYLOAD 64
#define MIN_SOA_SIZE 22

char *test_dir_name;

knot_lmdb_db_t jdb;
zone_journal_t jj;

unsigned env_flag;

static unsigned lmdb_page_size(knot_lmdb_db_t *db)
{
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, false);
	MDB_stat st = { 0 };
	mdb_stat(txn.txn, txn.db->dbi, &st);
	knot_lmdb_abort(&txn);
	return st.ms_psize;
}

static void set_conf(int zonefile_sync, size_t journal_usage, const knot_dname_t *apex)
{
	(void)apex;
	char conf_str[512];
	snprintf(conf_str, sizeof(conf_str),
	         "template:\n"
	         " - id: default\n"
	         "   zonefile-sync: %d\n"
	         "   journal-max-usage: %zu\n"
	         "   journal-max-depth: 1000\n",
	         zonefile_sync, journal_usage);
	_unused_ int ret = test_conf(conf_str, NULL);
	assert(ret == KNOT_EOK);
	jj.conf = conf();
}

static void unset_conf(void)
{
	conf_update(NULL, CONF_UPD_FNONE);
}

/*! \brief Generate random string with given length. */
static int randstr(char* dst, size_t len)
{
	for (int i = 0; i < len - 1; ++i) {
		dst[i] = '0' + (int) (('Z'-'0') * (rand() / (RAND_MAX + 1.0)));
	}
	dst[len - 1] = '\0';

	return 0;
}

/*! \brief Init RRSet with type SOA and given serial. */
static void init_soa(knot_rrset_t *rr, const uint32_t serial, const knot_dname_t *apex)
{
	knot_rrset_init(rr, knot_dname_copy(apex, NULL), KNOT_RRTYPE_SOA, KNOT_CLASS_IN, 3600);

	uint8_t soa_data[MIN_SOA_SIZE] = { 0 };
	_unused_ int ret = knot_rrset_add_rdata(rr, soa_data, sizeof(soa_data), NULL);
	knot_soa_serial_set(rr->rrs.rdata, serial);
	assert(ret == KNOT_EOK);
}

/*! \brief Init RRSet with type TXT, random owner and random payload. */
static void init_random_rr(knot_rrset_t *rr , const knot_dname_t *apex)
{
	/* Create random label. */
	char owner[RAND_RR_LABEL + knot_dname_size(apex)];
	owner[0] = RAND_RR_LABEL - 1;
	randstr(owner + 1, RAND_RR_LABEL);

	/* Append zone apex. */
	memcpy(owner + RAND_RR_LABEL, apex, knot_dname_size(apex));
	knot_rrset_init(rr, knot_dname_copy((knot_dname_t *)owner, NULL),
			KNOT_RRTYPE_TXT, KNOT_CLASS_IN, 3600);

	/* Create random RDATA. */
	uint8_t txt[RAND_RR_PAYLOAD + 1];
	txt[0] = RAND_RR_PAYLOAD - 1;
	randstr((char *)(txt + 1), RAND_RR_PAYLOAD);

	_unused_ int ret = knot_rrset_add_rdata(rr, txt, RAND_RR_PAYLOAD, NULL);
	assert(ret == KNOT_EOK);
}

/*! \brief Init changeset with random changes. */
static void init_random_changeset(changeset_t *ch, const uint32_t from, const uint32_t to,
                                  const size_t size, const knot_dname_t *apex, bool is_bootstrap)
{
	// Add SOAs
	knot_rrset_t soa;

	if (is_bootstrap) {
		ch->soa_from = NULL;
		zone_contents_deep_free(ch->remove);
		ch->remove = NULL;
	} else {
		init_soa(&soa, from, apex);
		ch->soa_from = knot_rrset_copy(&soa, NULL);
		assert(ch->soa_from);
		knot_rrset_clear(&soa, NULL);
	}

	init_soa(&soa, to, apex);
	ch->soa_to = knot_rrset_copy(&soa, NULL);
	assert(ch->soa_to);
	knot_rrset_clear(&soa, NULL);

	// Add RRs to add section
	for (size_t i = 0; i < size / 2; ++i) {
		knot_rrset_t rr;
		init_random_rr(&rr, apex);
		_unused_ int ret = changeset_add_addition(ch, &rr, 0);
		assert(ret == KNOT_EOK);
		knot_rrset_clear(&rr, NULL);
	}

	// Add RRs to remove section
	for (size_t i = 0; i < size / 2 && !is_bootstrap; ++i) {
		knot_rrset_t rr;
		init_random_rr(&rr, apex);
		_unused_ int ret = changeset_add_removal(ch, &rr, 0);
		assert(ret == KNOT_EOK);
		knot_rrset_clear(&rr, NULL);
	}
}

static void changeset_set_soa_serials(changeset_t *ch, uint32_t from, uint32_t to,
				      const knot_dname_t *apex)
{
	knot_rrset_t soa;

	init_soa(&soa, from, apex);
	knot_rrset_free(ch->soa_from, NULL);
	ch->soa_from = knot_rrset_copy(&soa, NULL);
	assert(ch->soa_from);
	knot_rrset_clear(&soa, NULL);

	init_soa(&soa, to, apex);
	knot_rrset_free(ch->soa_to, NULL);
	ch->soa_to = knot_rrset_copy(&soa, NULL);
	assert(ch->soa_to);
	knot_rrset_clear(&soa, NULL);
}

/*! \brief Compare two changesets for equality. */
static bool changesets_eq(const changeset_t *ch1, changeset_t *ch2)
{
	bool bootstrap = (ch1->remove == NULL);

	if (!bootstrap && changeset_size(ch1) != changeset_size(ch2)) {
		return false;
	}

	if ((bootstrap && ch2->remove != NULL) ||
	    (!bootstrap && ch2->remove == NULL)) {
		return false;
	}

	changeset_iter_t it1;
	changeset_iter_t it2;
	if (bootstrap) {
		changeset_iter_add(&it1, ch1);
		changeset_iter_add(&it2, ch2);
	} else {
		changeset_iter_all(&it1, ch1);
		changeset_iter_all(&it2, ch2);
	}

	knot_rrset_t rr1 = changeset_iter_next(&it1);
	knot_rrset_t rr2 = changeset_iter_next(&it2);
	bool ret = true;
	while (!knot_rrset_empty(&rr1)) {
		if (!knot_rrset_equal(&rr1, &rr2, true)) {
			ret = false;
			break;
		}
		rr1 = changeset_iter_next(&it1);
		rr2 = changeset_iter_next(&it2);
	}

	changeset_iter_clear(&it1);
	changeset_iter_clear(&it2);

	return ret;
}

static bool changesets_list_eq(list_t *l1, list_t *l2)
{
	node_t *n = NULL;
	node_t *k = HEAD(*l2);
	WALK_LIST(n, *l1) {
		if (k == NULL) {
			return false;
		}

		changeset_t *ch1 = (changeset_t *) n;
		changeset_t *ch2 = (changeset_t *) k;
		if (!changesets_eq(ch1, ch2)) {
			return false;
		}

		k = k->next;
	}

	if (k->next != NULL) {
		return false;
	}

	return true;
}

/*! \brief Test a list of changesets for continuity. */
static bool test_continuity(list_t *l)
{
	node_t *n = NULL;
	uint32_t key1, key2;
	WALK_LIST(n, *l) {
		if (n == TAIL(*l)) {
			break;
		}
		changeset_t *ch1 = (changeset_t *) n;
		changeset_t *ch2 = (changeset_t *) n->next;
		key1 = knot_soa_serial(ch1->soa_to->rrs.rdata);
		key2 = knot_soa_serial(ch2->soa_from->rrs.rdata);
		if (key1 != key2) {
			return KNOT_EINVAL;
		}
	}

	return KNOT_EOK;
}

static void test_journal_db(void)
{
	env_flag = journal_env_flags(JOURNAL_MODE_ASYNC, false);
	knot_lmdb_init(&jdb, test_dir_name, 2048 * 1024, env_flag, NULL);

	int ret = knot_lmdb_open(&jdb);
	is_int(KNOT_EOK, ret, "journal: open db (%s)", knot_strerror(ret));

	ret = knot_lmdb_reconfigure(&jdb, test_dir_name, 4096 * 1024, env_flag);
	is_int(KNOT_EOK, ret, "journal: re-open with bigger mapsize (%s)", knot_strerror(ret));

	ret = knot_lmdb_reconfigure(&jdb, test_dir_name, 1024 * 1024, env_flag);
	is_int(KNOT_EOK, ret, "journal: re-open with smaller mapsize (%s)", knot_strerror(ret));

	knot_lmdb_deinit(&jdb);
}

static int load_j_list(zone_journal_t *zj, bool zij, uint32_t serial,
                       journal_read_t **read, list_t *list)
{
	changeset_t *ch;
	init_list(list);
	int ret = journal_read_begin(*zj, zij, serial, read);
	if (ret == KNOT_EOK) {
		while ((ch = calloc(1, sizeof(*ch))) != NULL &&
		       journal_read_changeset(*read, ch)) {
			add_tail(list, &ch->n);
		}
		free(ch);
		ret = journal_read_get_error(*read, KNOT_EOK);
	}
	return ret;
}

/*! \brief Test behavior with real changesets. */
static void test_store_load(const knot_dname_t *apex)
{
	set_conf(1000, 512 * 1024, apex);

	knot_lmdb_init(&jdb, test_dir_name, 1536 * 1024, env_flag, NULL);
	assert(knot_lmdb_open(&jdb) == KNOT_EOK);

	jj.db = &jdb;
	jj.zone = apex;
	list_t l, k;

	changeset_t *m_ch = changeset_new(apex), r_ch, e_ch;
	init_random_changeset(m_ch, 0, 1, 128, apex, false);
	int ret = journal_insert(jj, m_ch, NULL);
	is_int(KNOT_EOK, ret, "journal: store changeset (%s)", knot_strerror(ret));
	ret = journal_sem_check(jj);
	is_int(KNOT_EOK, ret, "journal: check after store changeset (%s)", knot_strerror(ret));
	journal_read_t *read = NULL;

	ret = load_j_list(&jj, false, changeset_from(m_ch), &read, &l);
	is_int(KNOT_EOK, ret, "journal: read single changeset (%s)", knot_strerror(ret));
	ok(1 == list_size(&l), "journal: read exactly one changeset");
	ok(changesets_eq(m_ch, HEAD(l)), "journal: changeset equal after read");
	changesets_free(&l);

	journal_read_end(read);
	ret = journal_set_flushed(jj);
	is_int(KNOT_EOK, ret, "journal: first simple flush (%s)", knot_strerror(ret));

	init_list(&k);
	uint32_t serial = 1;
	for (; ret == KNOT_EOK && serial < 40000; ++serial) {
		changeset_t *m_ch2 = changeset_new(apex);
		init_random_changeset(m_ch2, serial, serial + 1, 128, apex, false);
		ret = journal_insert(jj, m_ch2, NULL);
		if (ret != KNOT_EOK) {
			changeset_free(m_ch2);
			break;
		}
		add_tail(&k, &m_ch2->n);
	}
	is_int(KNOT_EBUSY, ret, "journal: overfill with changesets (%d inserted) (%d should= %d)",
	       serial, ret, KNOT_EBUSY);
	ret = journal_sem_check(jj);
	is_int(KNOT_EOK, ret, "journal check (%s)", knot_strerror(ret));

	ret = load_j_list(&jj, false, 1, &read, &l);
	is_int(KNOT_EOK, ret, "journal: load list (%s)", knot_strerror(ret));
	ok(changesets_list_eq(&l, &k), "journal: changeset lists equal after read");
	ok(test_continuity(&l) == KNOT_EOK, "journal: changesets are in order");
	changesets_free(&l);
	journal_read_end(read);

	ret = load_j_list(&jj, false, 1, &read, &l);
	is_int(KNOT_EOK, ret, "journal: load list 2nd (%s)", knot_strerror(ret));
	ok(changesets_list_eq(&l, &k), "journal: changeset lists equal after 2nd read");
	changesets_free(&l);
	journal_read_end(read);

	ret = journal_set_flushed(jj);
	is_int(KNOT_EOK, ret, "journal: flush after overfill (%s)", knot_strerror(ret));
	ret = journal_sem_check(jj);
	is_int(KNOT_EOK, ret, "journal check (%s)", knot_strerror(ret));

	ret = load_j_list(&jj, false, 1, &read, &l);
	is_int(KNOT_EOK, ret, "journal: load list (%s)", knot_strerror(ret));
	ok(changesets_list_eq(&l, &k), "journal: changeset lists equal after flush");
	changesets_free(&l);
	journal_read_end(read);

	changesets_free(&k);

	changeset_t ch;
	ret = changeset_init(&ch, apex);
	ok(ret == KNOT_EOK, "journal: changeset init (%d)", ret);
	init_random_changeset(&ch, serial, serial + 1, 555, apex, false);
	ret = journal_insert(jj, &ch, NULL);
	is_int(KNOT_EOK, ret, "journal: store after flush (%d)", ret);
	ret = journal_sem_check(jj);
	is_int(KNOT_EOK, ret, "journal check (%s)", knot_strerror(ret));
	ret = load_j_list(&jj, false, serial, &read, &l);
	is_int(KNOT_EOK, ret, "journal: load after store after flush after overfill (%s)", knot_strerror(ret));
	is_int(1, list_size(&l), "journal: single changeset in list");
	ok(changesets_eq(&ch, HEAD(l)), "journal: changeset corrected/not malformed (?) after overfill");
	changesets_free(&l);
	journal_read_end(read);

	changeset_clear(&ch);

	changeset_init(&ch, apex);
	init_random_changeset(&ch, 2, 3, 100, apex, false);
	ret = journal_insert(jj, &ch, NULL);
	is_int(KNOT_EOK, ret, "journal: insert discontinuous changeset (%s)", knot_strerror(ret));
	ret = journal_sem_check(jj);
	is_int(KNOT_EOK, ret, "journal check (%s)", knot_strerror(ret));
	ret = load_j_list(&jj, false, 2, &read, &l);
	is_int(KNOT_EOK, ret, "journal: read after discontinuity (%s)", knot_strerror(ret));
	is_int(1, list_size(&l), "journal: discontinuity caused journal to drop");
	changesets_free(&l);
	journal_read_end(read);

	// Test for serial number collision handling. We insert changesets
	// with valid serial sequence that overflows and then collides with itself.
	// The sequence is 0 -> 1 -> 2 -> 2147483647 -> 4294967294 -> 1 which should
	// remove changesets 0->1 and 1->2. *
	uint32_t serials[6] = { 0, 1, 2, 2147483647, 4294967294, 1 };
	for (int i = 0; i < 5; i++) {
		changeset_clear(&ch);
		changeset_init(&ch, apex);
		init_random_changeset(&ch, serials[i], serials[i + 1], 100, apex, false);
		ret = journal_insert(jj, &ch, NULL);
		is_int(i == 4 ? KNOT_EBUSY : KNOT_EOK, ret, "journal: inserting cycle (%s)", knot_strerror(ret));
		ret = journal_sem_check(jj);
		is_int(KNOT_EOK, ret, "journal check (%s)", knot_strerror(ret));
	}
	ret = journal_set_flushed(jj);
	is_int(KNOT_EOK, ret, "journal: flush in cycle (%s)", knot_strerror(ret));
	ret = journal_insert(jj, &ch, NULL);
	is_int(KNOT_EOK, ret, "journal: inserted cycle (%s)", knot_strerror(ret));
	ret = journal_sem_check(jj);
	is_int(KNOT_EOK, ret, "journal check (%s)", knot_strerror(ret));
	ret = journal_read_begin(jj, false, 0, &read);
	is_int(KNOT_ENOENT, ret, "journal: cycle removed first changeset (%d should= %d)", ret, KNOT_ENOENT);
	ret = journal_read_begin(jj, false, 1, &read);
	is_int(KNOT_ENOENT, ret, "journal: cycle removed second changeset (%d should= %d)", ret, KNOT_ENOENT);
	ret = load_j_list(&jj, false, 4294967294, &read, &l);
	is_int(KNOT_EOK, ret, "journal: read after cycle (%s)", knot_strerror(ret));
	ok(3 >= list_size(&l), "journal: cycle caused journal to partly drop");
	ok(changesets_eq(&ch, HEAD(l)), "journal: changeset corrected/not malformed (?) after cycle");
	changesets_free(&l);
	journal_read_end(read);
	changeset_clear(&ch);
	changeset_free(m_ch);

	changeset_init(&e_ch, apex);
	init_random_changeset(&e_ch, 0, 1, 200, apex, true);
	zone_node_t *n = NULL;
	zone_contents_add_rr(e_ch.add, e_ch.soa_to, &n);
	ret = journal_insert_zone(jj, e_ch.add);
	zone_contents_remove_rr(e_ch.add, e_ch.soa_to, &n);
	is_int(KNOT_EOK, ret, "journal: insert zone-in-journal (%s)", knot_strerror(ret));
	changeset_init(&r_ch, apex);
	init_random_changeset(&r_ch, 1, 2, 200, apex, false);
	ret = journal_insert(jj, &r_ch, NULL);
	is_int(KNOT_EOK, ret, "journal: insert after zone-in-journal (%s)", knot_strerror(ret));
	ret = load_j_list(&jj, true, 0, &read, &l);
	is_int(KNOT_EOK, ret, "journal: load zone-in-journal (%s)", knot_strerror(ret));
	is_int(2, list_size(&l), "journal: read two changesets from zone-in-journal");
	ok(changesets_eq(&e_ch, HEAD(l)), "journal: zone-in-journal corrected/not malformed (?)");
	ok(changesets_eq(&r_ch, TAIL(l)), "journal: after zone-in-journal corrected/not malformed (?)");
	changesets_free(&l);
	journal_read_end(read);
	changeset_clear(&e_ch);
	changeset_clear(&r_ch);

	ret = journal_scrape_with_md(jj, true);
	is_int(KNOT_EOK, ret, "journal: scrape with md (%s)", knot_strerror(ret));

	unset_conf();
}

static void test_size_control(const knot_dname_t *zone1, const knot_dname_t *zone2)
{
	set_conf(-1, 100 * 1024, zone1);

	zone_journal_t jj2 = { &jdb, zone2, conf() };
	changeset_t *small_ch2 = changeset_new(zone2);
	init_random_changeset(small_ch2, 1, 2, 100, zone2, false);
	int ret = journal_insert(jj2, small_ch2, NULL);
	is_int(KNOT_EOK, ret, "journal: storing small changeset must be ok");

	changeset_t *big_zij = changeset_new(zone1);
	init_random_changeset(big_zij, 0, 1, 1200, zone1, true);
	zone_node_t *n = NULL;
	zone_contents_add_rr(big_zij->add, big_zij->soa_to, &n);
	ret = journal_insert_zone(jj, big_zij->add);
	is_int(KNOT_EOK, ret, "journal: store big zone-in-journal");

	changeset_t *big_ch2 = changeset_new(zone2);
	init_random_changeset(big_ch2, 2, 3, 750, zone2, false);
	ret = journal_insert(jj2, big_ch2, NULL);
	is_int(KNOT_EOK, ret, "journal: second zone is not affected by storing big zij of other zone");

	journal_read_t *read = NULL;
	list_t l;
	init_list(&l);
	changeset_t *medium_ch1 = changeset_new(zone1);
	init_random_changeset(medium_ch1, 1, 2, 300, zone1, false);
	ret = journal_insert(jj, medium_ch1, NULL);
	is_int(KNOT_EOK, ret, "journal: storing medium changeset must be ok");
	ret = load_j_list(&jj, true, 0, &read, &l);
	is_int(KNOT_EOK, ret, "journal: load zone-in-journal (%s)", knot_strerror(ret));
	is_int(2, list_size(&l), "journal: read two changesets from journal");
	changesets_free(&l);
	journal_read_end(read);

	changeset_t *small_ch1 = changeset_new(zone1);
	init_random_changeset(small_ch1, 2, 3, 100, zone1, false);
	ret = journal_insert(jj, small_ch1, NULL);
	is_int(KNOT_EOK, ret, "journal: storing small changeset must be ok");
	ret = load_j_list(&jj, true, 0, &read, &l);
	is_int(KNOT_EOK, ret, "journal: load zone-in-journal (%s)", knot_strerror(ret));
	is_int(2, list_size(&l), "journal: previous chs merged into zone-in-journal due to size limits");
	changesets_free(&l);
	journal_read_end(read);

	changeset_t *medium_ch1b = changeset_new(zone1);
	init_random_changeset(medium_ch1b, 3, 4, 300, zone1, false);
	ret = journal_insert(jj, medium_ch1b, NULL);
	is_int(KNOT_ESPACE, ret, "journal: not able to free space for changeset by merging");

	changeset_t *too_big_zij = changeset_new(zone1);
	init_random_changeset(too_big_zij, 0, 1, 2200, zone1, true);
	zone_contents_add_rr(too_big_zij->add, too_big_zij->soa_to, &n);
	ret = journal_insert_zone(jj, too_big_zij->add);
	is_int(KNOT_ESPACE, ret, "journal: store too big zone-in-journal");

	changeset_free(big_ch2);
	changeset_free(big_zij);
	changeset_free(too_big_zij);
	changeset_free(small_ch2);
	changeset_free(small_ch1);
	changeset_free(medium_ch1);
	changeset_free(medium_ch1b);

	unset_conf();
}

const uint8_t *rdA = (const uint8_t *) "\x01\x02\x03\x04";
const uint8_t *rdB = (const uint8_t *) "\x01\x02\x03\x05";
const uint8_t *rdC = (const uint8_t *) "\x01\x02\x03\x06";

// frees owner
static knot_rrset_t * tm_rrset(knot_dname_t * owner, const uint8_t * rdata)
{
	knot_rrset_t * rrs = knot_rrset_new(owner, KNOT_RRTYPE_A, KNOT_CLASS_IN, 3600, NULL);
	knot_rrset_add_rdata(rrs, rdata, 4, NULL);
	free(owner);
	return rrs;
}

static knot_dname_t *tm_owner(const char *prefix, const knot_dname_t *apex)
{
	size_t prefix_len = strlen(prefix);
	size_t apex_len = knot_dname_size(apex);

	knot_dname_t *out = malloc(prefix_len + apex_len + 2);
	out[0] = prefix_len;
	memcpy(out + 1, prefix, prefix_len);
	memcpy(out + 1 + prefix_len, apex, apex_len);
	return out;
}

static knot_dname_t *tm_owner_int(int x, const knot_dname_t *apex)
{
	char buf[12] = { 0 };
	(void)snprintf(buf, sizeof(buf), "i%d", x);
	return tm_owner(buf, apex);
}

static knot_rrset_t * tm_rrs(const knot_dname_t * apex, int x)
{
	static knot_rrset_t * rrsA = NULL;
	static knot_rrset_t * rrsB = NULL;
	static knot_rrset_t * rrsC = NULL;

	if (apex == NULL) {
		knot_rrset_free(rrsA, NULL);
		knot_rrset_free(rrsB, NULL);
		knot_rrset_free(rrsC, NULL);
		rrsA = rrsB = rrsC = NULL;
		return NULL;
	}

	if (rrsA == NULL) rrsA = tm_rrset(tm_owner("aaaaaaaaaaaaaaaaa", apex), rdA);
	if (rrsB == NULL) rrsB = tm_rrset(tm_owner("bbbbbbbbbbbbbbbbb", apex), rdB);
	if (rrsC == NULL) rrsC = tm_rrset(tm_owner("ccccccccccccccccc", apex), rdC);
	switch ((x % 3 + 3) % 3) {
	case 0: return rrsA;
	case 1: return rrsB;
	case 2: return rrsC;
	}
	assert(0); return NULL;
}

#define TM_RRS_INT_MAX 1000

static knot_rrset_t *tm_rrs_int(const knot_dname_t *apex, int x)
{
	assert(x < TM_RRS_INT_MAX);
	static knot_rrset_t *stat_rrs[TM_RRS_INT_MAX] = { 0 };

	if (apex == NULL) {
		for (int i = 0; i < TM_RRS_INT_MAX; i++) {
			knot_rrset_free(stat_rrs[i], NULL);
			stat_rrs[i] = NULL;
		}
		return NULL;
	}

	if (stat_rrs[x] == NULL) {
		stat_rrs[x] = tm_rrset(tm_owner_int(x, apex), rdA);
	}
	return stat_rrs[x];
}

int tm_rrcnt(const changeset_t * ch, int flg)
{
	changeset_iter_t it;
	int i = 0;
	if (flg >= 0) changeset_iter_add(&it, ch);
	else changeset_iter_rem(&it, ch);

	knot_rrset_t rri;
	while (rri = changeset_iter_next(&it), !knot_rrset_empty(&rri)) i++;

	changeset_iter_clear(&it);
	return i;
}

static changeset_t * tm_chs(const knot_dname_t * apex, int x)
{
	static changeset_t * chsI = NULL, * chsX = NULL, * chsY = NULL;
	static uint32_t serial = 0;
	if (x < 0) {
		serial = 0;
		return NULL;
	}

	if (apex == NULL) {
		changeset_free(chsI);
		changeset_free(chsX);
		changeset_free(chsY);
		chsI = chsX = chsY = NULL;
		return NULL;
	}

	if (chsI == NULL) {
		chsI = changeset_new(apex);
		assert(chsI != NULL);
		changeset_add_addition(chsI, tm_rrs(apex, 0), 0);
		changeset_add_addition(chsI, tm_rrs(apex, 1), 0);
	}
	if (chsX == NULL) {
		chsX = changeset_new(apex);
		assert(chsX != NULL);
		changeset_add_removal(chsX, tm_rrs(apex, 1), 0);
		changeset_add_addition(chsX, tm_rrs(apex, 2), 0);
	}
	if (chsY == NULL) {
		chsY = changeset_new(apex);
		assert(chsY != NULL);
		changeset_add_removal(chsY, tm_rrs(apex, 2), 0);
		changeset_add_addition(chsY, tm_rrs(apex, 1), 0);
	}
	assert(x >= 0);
	changeset_t * ret;
	if (x == 0) ret = chsI;
	else if (x % 2 == 1) ret = chsX;
	else ret = chsY;

	changeset_set_soa_serials(ret, serial, serial + 1, apex);
	serial++;

	return ret;
}

static void tm2_add_all(zone_contents_t *toadd)
{
	assert(toadd != NULL);
	for (int i = 1; i < TM_RRS_INT_MAX; i++) {
		zone_node_t *unused = NULL;
		_unused_ int ret = zone_contents_add_rr(toadd, tm_rrs_int(toadd->apex->owner, i), &unused);
		assert(ret == KNOT_EOK);
	}
}

static zone_contents_t *tm2_zone(const knot_dname_t *apex)
{
	zone_contents_t *z = zone_contents_new(apex, false);
	if (z != NULL) {
		knot_rrset_t soa;
		zone_node_t *unused = NULL;
		init_soa(&soa, 1, apex);
		_unused_ int ret = zone_contents_add_rr(z, &soa, &unused);
		knot_rrset_clear(&soa, NULL);
		assert(ret == KNOT_EOK);
		tm2_add_all(z);
	}
	return z;
}

static changeset_t *tm2_chs_unzone(const knot_dname_t *apex)
{
	changeset_t *ch = changeset_new(apex);
	if (ch != NULL) {
		changeset_set_soa_serials(ch, 1, 2, apex);
		tm2_add_all(ch->remove);
		_unused_ int ret = changeset_add_addition(ch, tm_rrs_int(apex, 0), 0);
		assert(ret == KNOT_EOK);
	}
	return ch;
}

static int merged_present(void)
{
	bool exists, has_merged;
	return journal_info(jj, &exists, NULL, NULL, NULL, &has_merged, NULL, NULL, NULL) == KNOT_EOK && exists && has_merged;
}

static void test_merge(const knot_dname_t *apex)
{
	int i, ret;
	list_t l;

	// allow merge
	set_conf(-1, 400 * 1024, apex);
	ok(!journal_allow_flush(jj), "journal: merge allowed");

	ret = journal_scrape_with_md(jj, false);
	is_int(KNOT_EOK, ret, "journal: journal_drop_changesets must be ok");

	// insert stuff and check the merge
	for (i = 0; !merged_present() && i < 40000; i++) {
		ret = journal_insert(jj, tm_chs(apex, i), NULL);
		assert(ret == KNOT_EOK);
	}
	ret = journal_sem_check(jj);
	is_int(KNOT_EOK, ret, "journal: sem check (%s)", knot_strerror(ret));
	journal_read_t *read = NULL;
	ret = load_j_list(&jj, false, 0, &read, &l);
	is_int(KNOT_EOK, ret, "journal: journal_load_changesets must be ok");
	assert(ret == KNOT_EOK);
	ok(list_size(&l) == 2, "journal: read the merged and one following");
	changeset_t * mch = (changeset_t *)HEAD(l);
	ok(list_size(&l) >= 1 && tm_rrcnt(mch, 1) == 2, "journal: merged additions # = 2");
	ok(list_size(&l) >= 1 && tm_rrcnt(mch, -1) == 0, "journal: merged removals # = 0");
	changesets_free(&l);
	journal_read_end(read);

	// insert one more and check the #s of results
	ret = journal_insert(jj, tm_chs(apex, i), NULL);
	is_int(KNOT_EOK, ret, "journal: insert one more (%s)", knot_strerror(ret));
	ret = load_j_list(&jj, false, 0, &read, &l);
	is_int(KNOT_EOK, ret, "journal: journal_load_changesets2 must be ok");
	ok(list_size(&l) == 3, "journal: read merged together with new changeset");
	changesets_free(&l);
	journal_read_end(read);
	ret = load_j_list(&jj, false, i - 3, &read, &l);
	is_int(KNOT_EOK, ret, "journal: journal_load_changesets3 must be ok");
	ok(list_size(&l) == 4, "journal: read short history of merged/unmerged changesets");
	changesets_free(&l);
	journal_read_end(read);

	// insert large zone-in-journal taking more than one chunk
	zone_contents_t *bigz = tm2_zone(apex);
	ret = journal_insert_zone(jj, bigz);
	zone_contents_deep_free(bigz);
	is_int(KNOT_EOK, ret, "journal: insert large zone-in-journal");

	// insert changeset that will cancel it mostly out
	changeset_t *bigz_cancelout = tm2_chs_unzone(apex);
	ret = journal_insert(jj, bigz_cancelout, NULL);
	changeset_free(bigz_cancelout);
	is_int(KNOT_EOK, ret, "journal: insert cancel-out changeset");

	// now fill up with dumy changesets to enforce merge
	tm_chs(apex, -1);
	while (changeset_to(tm_chs(apex, 0)) != 2) {  }
	for (i = 0; i < 1600; i++) {
		ret = journal_insert(jj, tm_chs(apex, i), NULL);
		assert(ret == KNOT_EOK);
	}

	// finally: the test case. Reading the journal now must be no EMALF and
	// the zone-in-journal must be little
	ret = load_j_list(&jj, true, 0, &read, &l);
	is_int(KNOT_EOK, ret, "journal: read chunks-shrinked zone-in-journal");
	is_int(4, trie_weight(((changeset_t *)HEAD(l))->add->nodes->trie), "journal: small merged zone-in-journal");
	changesets_free(&l);
	journal_read_end(read);

	ret = journal_scrape_with_md(jj, false);
	assert(ret == KNOT_EOK);

	// disallow merge
	unset_conf();
	set_conf(1000, 512 * 1024, apex);
	ok(journal_allow_flush(jj), "journal: merge disallowed");

	tm_rrs(NULL, 0);
	tm_chs(NULL, 0);
	tm_rrs_int(NULL, 0);
	unset_conf();
}

static void test_stress_base(const knot_dname_t *apex,
                             size_t update_size, size_t file_size)
{
	uint32_t serial = 0;

	int ret = knot_lmdb_reconfigure(&jdb, test_dir_name, file_size, journal_env_flags(JOURNAL_MODE_ASYNC, false));
	is_int(KNOT_EOK, ret, "journal: reconfigure to mapsize %zu (%s)", file_size, knot_strerror(ret));

	set_conf(1000, file_size / 2, apex);

	changeset_t ch;
	ret = changeset_init(&ch, apex);
	ok(ret == KNOT_EOK, "journal: changeset init (%d)", ret);
	init_random_changeset(&ch, serial, serial + 1, update_size, apex, false);

	for (int i = 1; i <= 6; ++i) {
		serial = 0;
		while (true) {
			changeset_set_soa_serials(&ch, serial, serial + 1, apex);
			ret = journal_insert(jj, &ch, NULL);
			if (ret == KNOT_EOK) {
				serial++;
			} else {
				break;
			}
		}

		ret = journal_set_flushed(jj);
		if (ret == KNOT_EOK) {
			ret = journal_sem_check(jj);
		}
		ok(serial > 0 && ret == KNOT_EOK, "journal: pass #%d fillup run (%d inserts) (%s)", i, serial, knot_strerror(ret));
	}

	changeset_clear(&ch);

	unset_conf();
}

/*! \brief Test behavior when writing to the journal and flushing it. */
static void test_stress(const knot_dname_t *apex)
{
	diag("stress test: small data");
	test_stress_base(apex, 40, (1024 + 512) * 1024);

	diag("stress test: medium data");
	test_stress_base(apex, 400, 3 * 1024 * 1024);

	diag("stress test: large data");
	test_stress_base(apex, 4000, 10 * 1024 * 1024);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	const knot_dname_t *apex = (const uint8_t *)"\4test";
	const knot_dname_t *apex2 = (const uint8_t *)"\4ufoo";

	test_dir_name = test_mkdtemp();

	test_journal_db();

	test_store_load(apex);

	if (lmdb_page_size(&jdb) == 4096) {
		test_size_control(apex, apex2);
	} // else it is not manually optimized enough to test correctly

	test_merge(apex);

	test_stress(apex);

	knot_lmdb_deinit(&jdb);

	test_rm_rf(test_dir_name);
	free(test_dir_name);

	return 0;
}
