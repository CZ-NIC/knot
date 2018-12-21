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

#include "libknot/libknot.h"
#include "knot/zone/zone.h"
#include "knot/zone/zone-diff.h"
#include "libknot/rrtype/soa.h"
#include "test_conf.h"

#define RAND_RR_LABEL 16
#define RAND_RR_PAYLOAD 64
#define MIN_SOA_SIZE 22

char *test_dir_name;

knot_lmdb_db_t jdb;
zone_journal_t jj;

unsigned env_flag;

static void set_conf(int zonefile_sync, size_t journal_usage, const knot_dname_t *apex)
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
	env_flag = journal_env_flags(JOURNAL_MODE_ASYNC);
	knot_lmdb_init(&jdb, test_dir_name, 2048 * 1024, env_flag);

	int ret = knot_lmdb_open(&jdb);
	is_int(KNOT_EOK, ret, "journal: open db (%s)", knot_strerror(ret));

	ret = knot_lmdb_reconfigure(&jdb, test_dir_name, 4096 * 1024, env_flag);
	is_int(KNOT_EOK, ret, "journal: re-open with bigger mapsize (%s)", knot_strerror(ret));

	ret = knot_lmdb_reconfigure(&jdb, test_dir_name, 1024 * 1024, env_flag);
	is_int(KNOT_EOK, ret, "journal: re-open with smaller mapsize (%s)", knot_strerror(ret));

	knot_lmdb_deinit(&jdb);
}

static int load_j_one(zone_journal_t *zj, journal_changeset_id_t id, journal_read_t **read, changeset_t *ch)
{
	int ret = journal_read_begin(zj, id, read);
	if (ret == KNOT_EOK) {
		if (journal_read_changeset(*read, ch)) {
			ret = journal_read_get_error(*read, KNOT_EOK);
		} else {
			ret = KNOT_ENOENT;
		}
	}
	return ret;
}

static int load_j_list(zone_journal_t *zj, journal_changeset_id_t id, journal_read_t **read, list_t *list)
{
	changeset_t *ch;
	init_list(list);
	int ret = journal_read_begin(zj, id, read);
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

	knot_lmdb_init(&jdb, test_dir_name, 1536 * 1024, env_flag);
	assert(knot_lmdb_open(&jdb) == KNOT_EOK);

	jj.db = &jdb;
	jj.zone = apex;

	changeset_t *m_ch = changeset_new(apex), r_ch, e_ch;
	init_random_changeset(m_ch, 0, 1, 128, apex, false);
	int ret = journal_insert(&jj, m_ch);
	is_int(KNOT_EOK, ret, "journal: store changeset (%s)", knot_strerror(ret));
	ret = journal_sem_check(&jj);
	is_int(KNOT_EOK, ret, "journal: check after store changeset (%s)", knot_strerror(ret));
	journal_changeset_id_t id = { false, changeset_from(m_ch) };
	journal_read_t *read = NULL;
	ret = load_j_one(&jj, id, &read, &r_ch);
	is_int(KNOT_EOK, ret, "journal: read single changeset (%s)", knot_strerror(ret));
	bool readch = journal_read_changeset(read, &e_ch);
	ok(!readch, "journal: no-read nonexisting changeset");
	ret = journal_read_get_error(read, KNOT_EOK);
	is_int(KNOT_EOK, ret, "journal: read ctx status after unsuccessful read (%s)", knot_strerror(ret));
	ok(changesets_eq(m_ch, &r_ch), "journal: changeset equal after read");
	journal_read_clear_changeset(&r_ch);
	journal_read_end(read);
	ret = journal_set_flushed(&jj);
	is_int(KNOT_EOK, ret, "journal: first simple flush (%s)", knot_strerror(ret));

	list_t l, k;
	init_list(&k);
	uint32_t serial = 1;
	id.serial = 1;
	for (; ret == KNOT_EOK && serial < 40000; ++serial) {
		changeset_t *m_ch2 = changeset_new(apex);
		init_random_changeset(m_ch2, serial, serial + 1, 128, apex, false);
		ret = journal_insert(&jj, m_ch2);
		if (ret != KNOT_EOK) {
			changeset_free(m_ch2);
			break;
		}
		add_tail(&k, &m_ch2->n);
	}
	is_int(KNOT_EBUSY, ret, "journal: overfill with changesets (%d inserted) (%d should= %d)",
	       serial, ret, KNOT_EBUSY);
	ret = journal_sem_check(&jj);
	is_int(KNOT_EOK, ret, "journal check (%s)", knot_strerror(ret));

	ret = load_j_list(&jj, id, &read, &l);
	is_int(KNOT_EOK, ret, "journal: load list (%s)", knot_strerror(ret));
	ok(changesets_list_eq(&l, &k), "journal: changeset lists equal after read");
	ok(test_continuity(&l) == KNOT_EOK, "journal: changesets are in order");
	changesets_free(&l);
	journal_read_end(read);

	ret = load_j_list(&jj, id, &read, &l);
	is_int(KNOT_EOK, ret, "journal: load list 2nd (%s)", knot_strerror(ret));
	ok(changesets_list_eq(&l, &k), "journal: changeset lists equal after 2nd read");
	changesets_free(&l);
	journal_read_end(read);

	ret = journal_set_flushed(&jj);
	is_int(KNOT_EOK, ret, "journal: flush after overfill (%s)", knot_strerror(ret));
	ret = journal_sem_check(&jj);
	is_int(KNOT_EOK, ret, "journal check (%s)", knot_strerror(ret));

	ret = load_j_list(&jj, id, &read, &l);
	is_int(KNOT_EOK, ret, "journal: load list (%s)", knot_strerror(ret));
	ok(changesets_list_eq(&l, &k), "journal: changeset lists equal after flush");
	changesets_free(&l);
	journal_read_end(read);

	changesets_free(&k);

	changeset_t ch;
	ret = changeset_init(&ch, apex);
	ok(ret == KNOT_EOK, "journal: changeset init (%d)", ret);
	init_random_changeset(&ch, serial, serial + 1, 555, apex, false);
	ret = journal_insert(&jj, &ch);
	is_int(KNOT_EOK, ret, "journal: store after flush (%d)", ret);
	ret = journal_sem_check(&jj);
	is_int(KNOT_EOK, ret, "journal check (%s)", knot_strerror(ret));
	id.serial = serial;
	ret = load_j_list(&jj, id, &read, &l);
	is_int(KNOT_EOK, ret, "journal: load after store after flush after overfill (%s)", knot_strerror(ret));
	is_int(1, list_size(&l), "journal: single changeset in list");
	ok(changesets_eq(&ch, HEAD(l)), "journal: changeset unmalformed after overfill");
	changesets_free(&l);
	journal_read_end(read);

	changeset_clear(&ch);

	id.serial = 2;
	changeset_init(&ch, apex);
	init_random_changeset(&ch, id.serial, 3, 100, apex, false);
	ret = journal_insert(&jj, &ch);
	is_int(KNOT_EOK, ret, "journal: insert discontinuous changeset (%s)", knot_strerror(ret));
	ret = journal_sem_check(&jj);
	is_int(KNOT_EOK, ret, "journal check (%s)", knot_strerror(ret));
	ret = load_j_list(&jj, id, &read, &l);
	is_int(KNOT_EOK, ret, "journal: read after discontinuity (%s)", knot_strerror(ret));
	is_int(1, list_size(&l), "journal: dicontinuity caused journal to drop");
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
		ret = journal_insert(&jj, &ch);
		is_int(i == 4 ? KNOT_EBUSY : KNOT_EOK, ret, "journal: inserting cycle (%s)", knot_strerror(ret));
		ret = journal_sem_check(&jj);
		is_int(KNOT_EOK, ret, "journal check (%s)", knot_strerror(ret));
	}
	ret = journal_set_flushed(&jj);
	is_int(KNOT_EOK, ret, "journal: flush in cycle (%s)", knot_strerror(ret));
	ret = journal_insert(&jj, &ch);
	is_int(KNOT_EOK, ret, "journal: inserted cycle (%s)", knot_strerror(ret));
	ret = journal_sem_check(&jj);
	is_int(KNOT_EOK, ret, "journal check (%s)", knot_strerror(ret));
	id.serial = 0;
	ret = journal_read_begin(&jj, id, &read);
	is_int(KNOT_ENOENT, ret, "journal: cycle removed first changeset (%d should= %d)", ret, KNOT_ENOENT);
	id.serial = 1;
	ret = journal_read_begin(&jj, id, &read);
	is_int(KNOT_ENOENT, ret, "journal: cycle removed second changeset (%d should= %d)", ret, KNOT_ENOENT);
	id.serial = 4294967294;
	ret = load_j_list(&jj, id, &read, &l);
	is_int(KNOT_EOK, ret, "journal: read after cycle (%s)", knot_strerror(ret));
	ok(3 >= list_size(&l), "journal: cycle caused journal to partly drop");
	ok(changesets_eq(&ch, HEAD(l)), "journal: changeset unmalformed after cycle");
	changesets_free(&l);
	journal_read_end(read);
	changeset_clear(&ch);
	changeset_free(m_ch);

	changeset_init(&e_ch, apex);
	init_random_changeset(&e_ch, 0, 1, 200, apex, true);
	ret = journal_insert_zone(&jj, &e_ch);
	is_int(KNOT_EOK, ret, "journal: insert zone-in-journal (%s)", knot_strerror(ret));
	changeset_init(&r_ch, apex);
	init_random_changeset(&r_ch, 1, 2, 200, apex, false);
	ret = journal_insert(&jj, &r_ch);
	is_int(KNOT_EOK, ret, "journal: insert after zone-in-journal (%s)", knot_strerror(ret));
	id.zone_in_journal = true;
	ret = load_j_list(&jj, id, &read, &l);
	is_int(KNOT_EOK, ret, "journal: load zone-in-journal (%s)", knot_strerror(ret));
	is_int(2, list_size(&l), "journal: read two changesets from zone-in-journal");
	ok(changesets_eq(&e_ch, HEAD(l)), "journal: zone-in-journal unmalformed");
	ok(changesets_eq(&r_ch, TAIL(l)), "journal: after zone-in-journal unmalformed");
	changesets_free(&l);
	journal_read_end(read);
	changeset_clear(&e_ch);
	changeset_clear(&r_ch);

	ret = journal_scrape_with_md(&jj);
	is_int(KNOT_EOK, ret, "journal: scrape with md (%s)", knot_strerror(ret));

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
	bool exists, has_merged;
	return journal_info(&jj, &exists, NULL, NULL, &has_merged, NULL) == KNOT_EOK && exists && has_merged;
}

static void test_merge(const knot_dname_t *apex)
{
	int i, ret;
	list_t l;

	// allow merge
	set_conf(-1, 100 * 1024, apex);
	ok(!journal_allow_flush(&jj), "journal: merge allowed");

	ret = journal_scrape_with_md(&jj);
	is_int(KNOT_EOK, ret, "journal: journal_drop_changesets must be ok");

	// insert stuff and check the merge
	for (i = 0; !merged_present() && i < 40000; i++) {
		ret = journal_insert(&jj, tm_chs(apex, i));
		is_int(KNOT_EOK, ret, "journal: journal_store_changeset must be ok");
	}
	ret = journal_sem_check(&jj);
	is_int(KNOT_EOK, ret, "journal: sem check (%s)", knot_strerror(ret));
	journal_changeset_id_t id = { false, 0 };
	journal_read_t *read = NULL;
	ret = load_j_list(&jj, id, &read, &l);
	is_int(KNOT_EOK, ret, "journal: journal_load_changesets must be ok");
	assert(ret == KNOT_EOK);
	ok(list_size(&l) == 2, "journal: read the merged and one following");
	changeset_t * mch = (changeset_t *)HEAD(l);
	ok(list_size(&l) >= 1 && tm_rrcnt(mch, 1) == 2, "journal: merged additions # = 2");
	ok(list_size(&l) >= 1 && tm_rrcnt(mch, -1) == 1, "journal: merged removals # = 1");
	changesets_free(&l);
	journal_read_end(read);

	// insert one more and check the #s of results
	ret = journal_insert(&jj, tm_chs(apex, i));
	is_int(KNOT_EOK, ret, "journal: insert one more (%s)", knot_strerror(ret));
	ret = load_j_list(&jj, id, &read, &l);
	is_int(KNOT_EOK, ret, "journal: journal_load_changesets2 must be ok");
	ok(list_size(&l) == 3, "journal: read merged together with new changeset");
	changesets_free(&l);
	journal_read_end(read);
	id.serial = i - 3;
	ret = load_j_list(&jj, id, &read, &l);
	is_int(KNOT_EOK, ret, "journal: journal_load_changesets3 must be ok");
	ok(list_size(&l) == 4, "journal: read short history of merged/unmerged changesets");
	changesets_free(&l);
	journal_read_end(read);


	ret = journal_scrape_with_md(&jj);
	assert(ret == KNOT_EOK);

	// disallow merge
	unset_conf();
	set_conf(1000, 512 * 1024, apex);
	ok(journal_allow_flush(&jj), "journal: merge disallowed");

	tm_rrs(NULL, 0);
	tm_chs(NULL, 0);
	unset_conf();
}

static void test_stress_base(const knot_dname_t *apex,
                             size_t update_size, size_t file_size)
{
	int ret;
	uint32_t serial = 0;


	ret = knot_lmdb_reconfigure(&jdb, test_dir_name, file_size, journal_env_flags(JOURNAL_MODE_ASYNC));
	is_int(KNOT_EOK, ret, "journal: recofigure to mapsize %zu (%s)", file_size, knot_strerror(ret));

	set_conf(1000, file_size / 2, apex);

	changeset_t ch;
	ret = changeset_init(&ch, apex);
	ok(ret == KNOT_EOK, "journal: changeset init (%d)", ret);
	init_random_changeset(&ch, serial, serial + 1, update_size, apex, false);

	for (int i = 1; i <= 6; ++i) {
		serial = 0;
		while (true) {
			changeset_set_soa_serials(&ch, serial, serial + 1, apex);
			ret = journal_insert(&jj, &ch);
			if (ret == KNOT_EOK) {
				serial++;
			} else {
				break;
			}
		}

		ret = journal_set_flushed(&jj);
		if (ret == KNOT_EOK) {
			ret = journal_sem_check(&jj);
		}
		ok(serial > 0 && ret == KNOT_EOK, "journal: pass #%d fillup run (%d inserts) (%s)", i, serial, knot_strerror(ret));
	}

	changeset_clear(&ch);

	unset_conf();
}

/*! \brief Test behavior when writing to jurnal and flushing it. */
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

	test_dir_name = test_mkdtemp();

	test_journal_db();

	test_store_load(apex);

	test_merge(apex);

	test_stress(apex);

	knot_lmdb_deinit(&jdb);

	test_rm_rf(test_dir_name);
	free(test_dir_name);

	return 0;
}
