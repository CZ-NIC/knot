/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <unistd.h>
#include <sys/stat.h>
#include <tap/basic.h>
#include <tap/files.h>

#include "libknot/libknot.h"
#include "knot/journal/journal.c"
#include "knot/zone/zone.h"
#include "knot/zone/zone-diff.h"
#include "libknot/rrtype/soa.h"
#include "test_conf.h"

#define RAND_RR_LABEL 16
#define RAND_RR_PAYLOAD 64
#define MIN_SOA_SIZE 22

char *test_dir_name;
journal_db_t *db;
journal_t *j;
const knot_dname_t *apex = (const uint8_t *)"\4test";

static void set_conf(int zonefile_sync, size_t journal_usage)
{
	char conf_str[512];
	snprintf(conf_str, sizeof(conf_str),
	         "zone:\n"
	         " - domain: %s\n"
	         "   zonefile-sync: %d\n"
	         "   max-journal-usage: %zu\n"
	         "   max-journal-depth: 1000\n",
	         (const char *)(apex + 1), zonefile_sync, journal_usage);
	int ret = test_conf(conf_str, NULL);
	(void)ret;
	assert(ret == KNOT_EOK);
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
	int ret = knot_rrset_add_rdata(rr, soa_data, sizeof(soa_data), NULL);
	knot_soa_serial_set(rr->rrs.rdata, serial);
	(void)ret;
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

	int ret = knot_rrset_add_rdata(rr, txt, RAND_RR_PAYLOAD, NULL);
	(void)ret;
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
		int ret = changeset_add_addition(ch, &rr, 0);
		(void)ret;
		assert(ret == KNOT_EOK);
		knot_rrset_clear(&rr, NULL);
	}

	// Add RRs to remove section
	for (size_t i = 0; i < size / 2 && !is_bootstrap; ++i) {
		knot_rrset_t rr;
		init_random_rr(&rr, apex);
		int ret = changeset_add_removal(ch, &rr, 0);
		(void)ret;
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
	if (changeset_size(ch1) != changeset_size(ch2)) {
		return false;
	}

	changeset_iter_t it1;
	changeset_iter_all(&it1, ch1);
	changeset_iter_t it2;
	changeset_iter_all(&it2, ch2);

	knot_rrset_t rr1 = changeset_iter_next(&it1);
	knot_rrset_t rr2 = changeset_iter_next(&it2);
	bool ret = true;
	while (!knot_rrset_empty(&rr1)) {
		if (!knot_rrset_equal(&rr1, &rr2, KNOT_RRSET_COMPARE_WHOLE)) {
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
	int ret, ret2 = KNOT_EOK;

	ret = journal_db_init(&db, test_dir_name, 2 * 1024 * 1024, JOURNAL_MODE_ASYNC);
	is_int(KNOT_EOK, ret, "journal: init db (%d)", ret);

	ret = journal_open_db(&db);
	is_int(KNOT_EOK, ret, "journal: open db (%d)", ret);

	journal_db_close(&db);
	ok(db == NULL, "journal: close and destroy db");

	ret = journal_db_init(&db, test_dir_name, 4 * 1024 * 1024, JOURNAL_MODE_ASYNC);
	if (ret == KNOT_EOK) ret2 = journal_open_db(&db);
	ok(ret == KNOT_EOK && ret2 == KNOT_EOK, "journal: open with bigger mapsize (%d, %d)", ret, ret2);
	journal_db_close(&db);

	ret = journal_db_init(&db, test_dir_name, 1024 * 1024, JOURNAL_MODE_ASYNC);
	if (ret == KNOT_EOK) ret2 = journal_open_db(&db);
	ok(ret == KNOT_EOK && ret2 == KNOT_EOK, "journal: open with smaller mapsize (%d, %d)", ret, ret2);
	journal_db_close(&db);
}

/*! \brief Test behavior with real changesets. */
static void test_store_load(void)
{
	int ret, ret2 = KNOT_EOK;

	set_conf(1000, 512 * 1024);

	j = journal_new();
	ok(j != NULL, "journal: new");

	ret = journal_db_init(&db, test_dir_name, (512 + 1024) * 1024, JOURNAL_MODE_ASYNC);
	if (ret == KNOT_EOK) ret2 = journal_open(j, &db, apex);
	is_int(KNOT_EOK, ret, "journal: open (%d, %d)", ret, ret2);

	/* Save and load changeset. */
	changeset_t *m_ch = changeset_new(apex);
	init_random_changeset(m_ch, 0, 1, 128, apex, false);
	ret = journal_store_changeset(j, m_ch);
	is_int(KNOT_EOK, ret, "journal: store changeset (%d)", ret);
	ret = journal_check(j, JOURNAL_CHECK_INFO);
	is_int(KNOT_EOK, ret, "journal check (%d)", ret);
	list_t l, k;
	init_list(&l);
	init_list(&k);
	ret = journal_load_changesets(j, &l, 0);
	add_tail(&k, &m_ch->n);
	ok(ret == KNOT_EOK && changesets_list_eq(&l, &k), "journal: load changeset (%d)", ret);
	ret = journal_check(j, JOURNAL_CHECK_STDERR);
	is_int(KNOT_EOK, ret, "journal check (%d)", ret);

	/* Load ctx's. */
	chgset_ctx_list_t cl = { { 0 }, 0 };
	ret = journal_load_chgset_ctx(j, &cl, 0);
	ok(ret == KNOT_EOK, "journal: chgset_ctx: load (%s)", knot_strerror(ret));
	chgset_ctx_list_close(&cl);

	changesets_free(&l);
	changesets_free(&k);

	/* Flush the journal. */
	ret = journal_flush(j);
	is_int(KNOT_EOK, ret, "journal: first and simple flush (%d)", ret);
	ret = journal_check(j, JOURNAL_CHECK_STDERR);
	is_int(KNOT_EOK, ret, "journal check (%d)", ret);
	init_list(&l);
	init_list(&k);

	/* Fill the journal. */
	ret = KNOT_EOK;
	uint32_t serial = 1;
	for (; ret == KNOT_EOK && serial < 40000; ++serial) {
		changeset_t *m_ch2 = changeset_new(apex);
		init_random_changeset(m_ch2, serial, serial + 1, 128, apex, false);
		ret = journal_store_changeset(j, m_ch2);
		if (ret != KNOT_EOK) {
			changeset_free(m_ch2);
			break;
		}
		add_tail(&k, &m_ch2->n);
	}
	is_int(KNOT_EBUSY, ret, "journal: overfill with changesets (%d inserted) (%d should= %d)",
	   serial, ret, KNOT_EBUSY);
	ret = journal_check(j, JOURNAL_CHECK_STDERR);
	is_int(KNOT_EOK, ret, "journal check (%d)", ret);

	/* Load all changesets stored until now. */
	ret = journal_load_changesets(j, &l, 1);
	ok(ret == KNOT_EOK && changesets_list_eq(&l, &k), "journal: load changesets (%d)", ret);

	changesets_free(&l);
	init_list(&l);
	ret = journal_load_changesets(j, &l, 1);
	ok(ret == KNOT_EOK && changesets_list_eq(&l, &k), "journal: re-load changesets (%d)", ret);

	ret = journal_load_chgset_ctx(j, &cl, 1);
	ok(ret == KNOT_EOK, "journal: chgset_ctx: load 2 (%s)", knot_strerror(ret));
	ok(list_size(&cl.l) == list_size(&l), "journal: chgset_ctx: load size %zu ?== %zu", list_size(&cl.l), list_size(&l));
	chgset_ctx_list_close(&cl);

	changesets_free(&l);
	init_list(&l);

	/* Flush the journal. */
	ret = journal_flush(j);
	is_int(KNOT_EOK, ret, "journal: second flush (%d)", ret);
	ret = journal_check(j, JOURNAL_CHECK_STDERR);
	is_int(KNOT_EOK, ret, "journal check (%d)", ret);

	/* Test whether the journal kept changesets after flush. */
	ret = journal_load_changesets(j, &l, 1);
	ok(ret == KNOT_EOK && changesets_list_eq(&l, &k), "journal: load right after flush (%d)", ret);

	changesets_free(&k);
	changesets_free(&l);
	init_list(&k);
	init_list(&l);

	/* Store next changeset. */
	changeset_t ch;
	ret = changeset_init(&ch, apex);
	ok(ret == KNOT_EOK, "journal: changeset init (%d)", ret);
	init_random_changeset(&ch, serial, serial + 1, 128, apex, false);
	ret = journal_store_changeset(j, &ch);
	changeset_clear(&ch);
	is_int(KNOT_EOK, ret, "journal: store after flush (%d)", ret);
	ret = journal_check(j, JOURNAL_CHECK_STDERR);
	is_int(KNOT_EOK, ret, "journal check (%d)", ret);

	/* Load last changesets. */
	init_list(&l);
	ret = journal_load_changesets(j, &l, serial);
	changesets_free(&l);
	is_int(KNOT_EOK, ret, "journal: load changesets after flush (%d)", ret);

	/* Flush the journal again. */
	ret = journal_flush(j);
	is_int(KNOT_EOK, ret, "journal: flush again (%d)", ret);
	ret = journal_check(j, JOURNAL_CHECK_STDERR);
	is_int(KNOT_EOK, ret, "journal check (%d)", ret);

	/* Fill the journal using a list. */
	uint32_t m_serial = 1;
	for (; m_serial < serial / 2; ++m_serial) {
		changeset_t *m_ch7 = changeset_new(apex);
		init_random_changeset(m_ch7, m_serial, m_serial + 1, 128, apex, false);
		add_tail(&l, &m_ch7->n);
	}
	ret = journal_store_changesets(j, &l);
	is_int(KNOT_EOK, ret, "journal: fill with changesets using a list (%d inserted)", m_serial);
	ret = journal_check(j, JOURNAL_CHECK_STDERR);
	is_int(KNOT_EOK, ret, "journal check (%d)", ret);

	/* Cleanup. */
	changesets_free(&l);
	init_list(&l);

	/* Load all previous changesets. */
	ret = journal_load_changesets(j, &l, 1);
	ok(ret == KNOT_EOK && knot_soa_serial(((changeset_t *)TAIL(l))->soa_to->rrs.rdata) == m_serial,
	   "journal: load all changesets");

	/* Check for changeset ordering. */
	ok(test_continuity(&l) == KNOT_EOK, "journal: changesets are in order");

	/* Cleanup. */
	changesets_free(&l);
	init_list(&l);
	ret = journal_flush(j);
	is_int(KNOT_EOK, ret, "journal: allways ok journal_flush 0");
	ret = drop_journal(j, NULL); /* Clear the journal for the collision test */
	is_int(KNOT_EOK, ret, "journal: allways ok drop_journal");

	/* Test for serial number collision handling. We insert changesets
	 * with valid serial sequence that overflows and then collides with itself.
	 * The sequence is 0 -> 1 -> 2 -> 2147483647 -> 4294967294 -> 1 which should
	 * remove changesets 0->1 and 1->2. */
	ok(EMPTY_LIST(k), "journal: empty list k");
	ok(EMPTY_LIST(l), "journal: empty list l");
	changeset_t *m_ch3 = changeset_new(apex);
	init_random_changeset(m_ch3, 0, 1, 128, apex, false);
	ret = journal_store_changeset(j, m_ch3);
	is_int(KNOT_EOK, ret, "journal: allways ok journal_store_changeset 1");
	changeset_set_soa_serials(m_ch3, 1, 2, apex);
	ret = journal_store_changeset(j, m_ch3);
	is_int(KNOT_EOK, ret, "journal: allways ok journal_store_changeset 2");
	changeset_set_soa_serials(m_ch3, 2, 2147483647, apex);
	add_tail(&k, &m_ch3->n);
	ret = journal_store_changeset(j, m_ch3);
	is_int(KNOT_EOK, ret, "journal: allways ok journal_store_changeset 3");
	changeset_t *m_ch4 = changeset_new(apex);
	init_random_changeset(m_ch4, 2147483647, 4294967294, 128, apex, false);
	add_tail(&k, &m_ch4->n);
	ret = journal_store_changeset(j, m_ch4);
	is_int(KNOT_EOK, ret, "journal: allways ok journal_store_changeset 4");
	changeset_t *m_ch5 = changeset_new(apex);
	init_random_changeset(m_ch5, 4294967294, 1, 128, apex, false);
	add_tail(&k, &m_ch5->n);
	ret = journal_store_changeset(j, m_ch5);
	is_int(KNOT_EBUSY, ret, "journal: allways ok journal_store_changeset 5");
	ret = journal_flush(j);
	is_int(KNOT_EOK, ret, "journal: allways ok journal_flush 1");
	ret = journal_store_changeset(j, m_ch5);
	is_int(KNOT_EOK, ret, "journal: allways ok journal_store_changeset 6");
	ret = journal_flush(j);
	is_int(KNOT_EOK, ret, "journal: allways ok journal_flush 2");
	ret = journal_load_changesets(j, &l, 0);
	ret2 = journal_load_changesets(j, &l, 1);
	int ret3 = journal_load_changesets(j, &l, 2);
	fprintf(stderr, "ret=%d ret2=%d ret3=%d\n", ret, ret2, ret3);
	ok(ret == KNOT_ENOENT && ret2 == KNOT_ENOENT && ret3 == KNOT_EOK &&
	   changesets_list_eq(&l, &k), "journal: serial collision");
	ret = journal_check(j, JOURNAL_CHECK_STDERR);
	is_int(KNOT_EOK, ret, "journal check (%d)", ret);

	/* Cleanup. */
	changesets_free(&l);
	changesets_free(&k);

	init_list(&l);
	init_list(&k);

	/* Check bootstrap changeset */
	ret = drop_journal(j, NULL);
	ok(ret == KNOT_EOK, "journal: drop_journal must be ok");

	changeset_t *m_ch6 = changeset_new(apex);
	init_random_changeset(m_ch6, 0, 1, 128, apex, true);
	ret = journal_store_changeset(j, m_ch6);
	ok(ret == KNOT_EOK, "journal: store bootstrap (%d)", ret);
	ret = journal_check(j, JOURNAL_CHECK_STDERR);
	ok(ret == KNOT_EOK, "journal check (%d)", ret);
	changeset_t *m_ch7 = changeset_new(apex);
	init_random_changeset(m_ch7, 1, 2, 128, apex, false);
	ret = journal_store_changeset(j, m_ch7);
	ok(ret == KNOT_EOK, "journal: store after bootstrap (%d)", ret);
	add_tail(&k, &m_ch6->n);
	add_tail(&k, &m_ch7->n);
	ret = journal_load_bootstrap(j, &l);
	ok(ret == KNOT_EOK && changesets_list_eq(&l, &k), "journal: load boostrap (%d)", ret);
	ret = journal_check(j, JOURNAL_CHECK_STDERR);
	ok(ret == KNOT_EOK, "journal check (%d)", ret);

	changesets_free(&l);
	changesets_free(&k);

	init_list(&l);
	init_list(&k);

	ret = journal_scrape(j);
	ok(ret == KNOT_EOK, "journal: scrape must be ok");

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

static knot_dname_t * tm_owner(const char * prefix, const knot_dname_t *apex)
{
	knot_dname_t * ret = malloc(strlen(prefix) + knot_dname_size(apex) + 2);
	ret[0] = strlen(prefix);
	strcpy((char *) (ret + 1), prefix);
	memcpy(ret + ret[0] + 1, apex, knot_dname_size(apex));
	return ret;
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

static int merged_present(void)
{
	local_txn_t(txn, j);
	txn_begin(txn, 0);
	int res = md_flag(txn, MERGED_SERIAL_VALID);
	txn_abort(txn);
	return res;
}

static void test_merge(void)
{
	int i, ret;
	list_t l;

	// allow merge
	set_conf(-1, 512 * 1024);
	ok(journal_merge_allowed(j), "journal: merge allowed");

	ret = drop_journal(j, NULL);
	is_int(KNOT_EOK, ret, "journal: drop_journal must be ok");

	// insert stuff and check the merge
	for (i = 0; !merged_present() && i < 40000; i++) {
		ret = journal_store_changeset(j, tm_chs(apex, i));
		is_int(KNOT_EOK, ret, "journal: journal_store_changeset must be ok");
	}
	init_list(&l);
	ret = journal_load_changesets(j, &l, 0);
	is_int(KNOT_EOK, ret, "journal: journal_load_changesets must be ok");
	ok(list_size(&l) == 2, "journal: read the merged and one following");
	changeset_t * mch = (changeset_t *)HEAD(l);
	ok(list_size(&l) >= 1 && tm_rrcnt(mch, 1) == 2, "journal: merged additions # = 2");
	ok(list_size(&l) >= 1 && tm_rrcnt(mch, -1) == 1, "journal: merged removals # = 1");
	changesets_free(&l);

	// insert one more and check the #s of results
	journal_store_changeset(j, tm_chs(apex, i));
	init_list(&l);
	ret = journal_load_changesets(j, &l, 0);
	is_int(KNOT_EOK, ret, "journal: journal_load_changesets2 must be ok");
	ok(list_size(&l) == 3, "journal: read merged together with new changeset");
	changesets_free(&l);
	init_list(&l);
	ret = journal_load_changesets(j, &l, (uint32_t) (i - 3));
	is_int(KNOT_EOK, ret, "journal: journal_load_changesets3 must be ok");
	ok(list_size(&l) == 4, "journal: read short history of merged/unmerged changesets");
	changesets_free(&l);

	ret = drop_journal(j, NULL);
	assert(ret == KNOT_EOK);

	// disallow merge
	unset_conf();
	set_conf(1000, 512 * 1024);
	ok(!journal_merge_allowed(j), "journal: merge disallowed");

	tm_rrs(NULL, 0);
	tm_chs(NULL, 0);
	unset_conf();
}

static void test_stress_base(journal_t *j, size_t update_size, size_t file_size)
{
	int ret;
	uint32_t serial = 0;

	journal_close(j);
	journal_db_close(&db);
	db = NULL;
	ret = journal_db_init(&db, test_dir_name, file_size, JOURNAL_MODE_ASYNC);
	assert(ret == KNOT_EOK);
	ret = journal_open_db(&db);
	assert(ret == KNOT_EOK);
	ret = journal_open(j, &db, apex);
	assert(ret == KNOT_EOK);

	set_conf(1000, file_size / 2);

	changeset_t ch;
	ret = changeset_init(&ch, apex);
	ok(ret == KNOT_EOK, "journal: changeset init (%d)", ret);
	init_random_changeset(&ch, serial, serial + 1, update_size, apex, false);

	for (int i = 1; i <= 6; ++i) {
		serial = 0;
		while (true) {
			changeset_set_soa_serials(&ch, serial, serial + 1, apex);
			ret = journal_store_changeset(j, &ch);
			if (ret == KNOT_EOK) {
				serial++;
			} else {
				break;
			}
		}

		int ret = journal_flush(j);
		ok(serial > 0 && ret == KNOT_EOK, "journal: pass #%d fillup run (%d inserts)", i, serial);
	}

	changeset_clear(&ch);

	unset_conf();
}

/*! \brief Test behavior when writing to jurnal and flushing it. */
static void test_stress(journal_t *j)
{
	diag("stress test: small data");
	test_stress_base(j, 40, (1024 + 512) * 1024);

	diag("stress test: medium data");
	test_stress_base(j, 400, 3 * 1024 * 1024);

	diag("stress test: large data");
	test_stress_base(j, 4000, 10 * 1024 * 1024);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	test_dir_name = test_mkdtemp();

	test_journal_db();

	test_store_load();

	test_merge();

	test_stress(j);

	journal_close(j);
	journal_free(&j);
	journal_db_close(&db);

	test_rm_rf(test_dir_name);
	free(test_dir_name);

	return 0;
}
