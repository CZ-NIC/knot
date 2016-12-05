/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/libknot.h"
#include "knot/server/journal.h"
#include "knot/zone/zone.h"

#define RAND_RR_LABEL 16
#define RAND_RR_PAYLOAD 64
#define MIN_SOA_SIZE 22

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
	knot_rrset_init(rr, knot_dname_copy(apex, NULL), KNOT_RRTYPE_SOA, KNOT_CLASS_IN);

	assert(serial < 256);
	uint8_t soa_data[MIN_SOA_SIZE] = { 0, 0, 0, 0, 0, serial };
	int ret = knot_rrset_add_rdata(rr, soa_data, sizeof(soa_data), 3600, NULL);
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
	knot_rrset_init(rr, knot_dname_copy((knot_dname_t *)owner, NULL), KNOT_RRTYPE_TXT, KNOT_CLASS_IN);

	/* Create random RDATA. */
	uint8_t txt[RAND_RR_PAYLOAD + 1];
	txt[0] = RAND_RR_PAYLOAD - 1;
	randstr((char *)(txt + 1), RAND_RR_PAYLOAD);

	int ret = knot_rrset_add_rdata(rr, txt, RAND_RR_PAYLOAD, 3600, NULL);
	(void)ret;
	assert(ret == KNOT_EOK);
}

/*! \brief Init changeset with random changes. */
static void init_random_changeset(changeset_t *ch, const uint32_t from, const uint32_t to, const size_t size, const knot_dname_t *apex)
{
	int ret = changeset_init(ch, apex);
	(void)ret;
	assert(ret == KNOT_EOK);

	// Add SOAs
	knot_rrset_t soa;
	init_soa(&soa, from, apex);

	ch->soa_from = knot_rrset_copy(&soa, NULL);
	assert(ch->soa_from);
	knot_rrset_clear(&soa, NULL);

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
	for (size_t i = 0; i < size / 2; ++i) {
		knot_rrset_t rr;
		init_random_rr(&rr, apex);
		int ret = changeset_add_removal(ch, &rr, 0);
		(void)ret;
		assert(ret == KNOT_EOK);
		knot_rrset_clear(&rr, NULL);
	}
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

/*! \brief Journal fillup test with size check. */
static void test_fillup(journal_t *journal, size_t fsize, unsigned iter, size_t chunk_size)
{
	int ret = KNOT_EOK;
	char *mptr = NULL;
	char *large_entry = malloc(chunk_size);
	randstr(large_entry, chunk_size);
	assert(large_entry);

	unsigned i = 0;
	bool read_passed = true;
	for (; i < 2 * JOURNAL_NCOUNT; ++i) {
		uint64_t chk_key = 0xBEBE + i;
		size_t entry_len = chunk_size/2 + rand() % (chunk_size/2);

		/* Write */
		ret = journal_map(journal, chk_key, &mptr, entry_len, false);
		if (ret != KNOT_EOK) {
			break;
		}
		memcpy(mptr, large_entry, entry_len);
		ret = journal_unmap(journal, chk_key, mptr, 1);
		if (ret != KNOT_EOK) {
			diag("journal_unmap = %s", knot_strerror(ret));
			read_passed = true;
			break;
		}

		/* Read */
		ret = journal_map(journal, chk_key, &mptr, entry_len, true);
		if (ret == KNOT_EOK) {
			ret = memcmp(large_entry, mptr, entry_len);
			if (ret != 0) {
				diag("integrity check failed");
				read_passed = false;
			} else {
				ret = journal_unmap(journal, chk_key, mptr, 0);
				if (ret != KNOT_EOK) {
					diag("journal_unmap(rdonly) = %s", knot_strerror(ret));
					read_passed = false;
				}
			}
		} else {
			diag("journal_map(rdonly) = %s", knot_strerror(ret));
			read_passed = false;
		}

		if (!read_passed) {
			break;
		}
	}
	ok(read_passed, "journal: fillup #%u, reading written entries", iter);
	ok(ret != KNOT_EOK, "journal: fillup #%u (%d entries)", iter, i);
	free(large_entry);

	/* Check file size. */
	struct stat st;
	fstat(journal->fd, &st);
	ok(st.st_size < fsize + chunk_size, "journal: fillup / size check #%u", iter);
	if (st.st_size > fsize + chunk_size) {
		diag("journal: fillup / size check #%u fsize(%zu) > max(%zu)",
		     iter, (size_t)st.st_size, fsize + chunk_size);
	}
}

/*! \brief Test behavior with real changesets. */
static void test_store_load(const char *jfilename)
{
	const size_t filesize = 100 * 1024;
	uint8_t *apex = (uint8_t *)"\4test";

	/* Create fake zone. */
	zone_t z = { .name = apex };

	/* Save and load changeset. */
	changeset_t ch;
	init_random_changeset(&ch, 0, 1, 128, apex);
	int ret = journal_store_changeset(&ch, jfilename, filesize);
	(void)ret;
	ok(ret == KNOT_EOK, "journal: store changeset");
	list_t l;
	init_list(&l);
	ret = journal_load_changesets(jfilename, z.name, &l, 0, 1);
	ok(ret == KNOT_EOK && changesets_eq(TAIL(l), &ch), "journal: load changeset");
	changeset_clear(&ch);
	changesets_free(&l);
	init_list(&l);

	/* Fill the journal. */
	ret = KNOT_EOK;
	uint32_t serial = 1;
	for (; ret == KNOT_EOK; ++serial) {
		init_random_changeset(&ch, serial, serial + 1, 128, apex);
		ret = journal_store_changeset(&ch, jfilename, filesize);
		changeset_clear(&ch);
	}
	ok(ret == KNOT_EBUSY, "journal: overfill with changesets");

	/* Load all changesets stored until now. */
	serial--;
	ret = journal_load_changesets(jfilename, z.name, &l, 0, serial);
	changesets_free(&l);
	ok(ret == KNOT_EOK, "journal: load changesets");

	/* Flush the journal. */
	ret = journal_mark_synced(jfilename);
	ok(ret == KNOT_EOK, "journal: flush");

	/* Store next changeset. */
	init_random_changeset(&ch, serial, serial + 1, 128, apex);
	ret = journal_store_changeset(&ch, jfilename, filesize);
		changeset_clear(&ch);
	ok(ret == KNOT_EOK, "journal: store after flush");

	/* Load all changesets, except the first one that got evicted. */
	init_list(&l);
	ret = journal_load_changesets(jfilename, z.name, &l, 1, serial + 1);
	changesets_free(&l);
	ok(ret == KNOT_EOK, "journal: load changesets after flush");
}

/*! \brief Test behavior when writing to jurnal and flushing it. */
static void test_stress(const char *jfilename)
{
	uint8_t *apex = (uint8_t *)"\4test";
	const size_t filesize = 100 * 1024;
	int ret = KNOT_EOK;
	uint32_t serial = 0;
	size_t update_size = 3;
	for (; ret == KNOT_EOK && serial < 32; ++serial) {
		changeset_t ch;
		init_random_changeset(&ch, serial, serial + 1, update_size, apex);
		update_size *= 1.5;
		ret = journal_store_changeset(&ch, jfilename, filesize);
		changeset_clear(&ch);
		journal_mark_synced(jfilename);
	}
	ok(ret == KNOT_ESPACE, "journal: does not overfill under load");
}

int main(int argc, char *argv[])
{
	plan_lazy();

	/* Create tmpdir */
	size_t fsize = 10 * 1024 * 1024;
	char *tmpdir = test_tmpdir();
	char jfilename[256];
	snprintf(jfilename, sizeof(jfilename), "%s/%s", tmpdir, "journal.XXXXXX");

	/* Create tmpfile. */
	int tmp_fd = mkstemp(jfilename);
	ok(tmp_fd >= 0, "journal: create temporary file");
	if (tmp_fd < 0) {
		goto skip_all;
	}
	close(tmp_fd);
	remove(jfilename);

	/* Try to open journal with too small fsize. */
	journal_t *journal = NULL;
	int ret = journal_open(&journal, jfilename, 1024);
	ok(ret != KNOT_EOK, "journal: open too small");

	/* Open/create new journal. */
	ret = journal_open(&journal, jfilename, fsize);
	ok(ret == KNOT_EOK, "journal: open journal '%s'", jfilename);
	if (ret != KNOT_EOK) {
		goto skip_all;
	}

	/* Write entry and check integrity. */
	char *mptr = NULL;
	uint64_t chk_key = 0;
	char chk_buf[64] = {'\0'};
	randstr(chk_buf, sizeof(chk_buf));
	ret = journal_map(journal, chk_key, &mptr, sizeof(chk_buf), false);
	is_int(KNOT_EOK, ret, "journal: write data (map)");
	if (ret == KNOT_EOK) {
		memcpy(mptr, chk_buf, sizeof(chk_buf));
		ret = journal_unmap(journal, chk_key, mptr, 1);
		is_int(KNOT_EOK, ret, "journal: write data (unmap)");
	}

	ret = journal_map(journal, chk_key, &mptr, sizeof(chk_buf), true);
	is_int(KNOT_EOK, ret, "journal: data integrity check (map)");
	if (ret == KNOT_EOK) {
		ret = memcmp(chk_buf, mptr, sizeof(chk_buf));
		is_int(0, ret, "journal: data integrity check (cmp)");
		ret = journal_unmap(journal, chk_key, mptr, 0);
		is_int(KNOT_EOK, ret, "journal: data integrity check (unmap)");
	}

	/* Reopen log and re-read value. */
	journal_close(journal);
	ret = journal_open(&journal, jfilename, fsize);
	ok(ret == KNOT_EOK, "journal: open journal '%s'", jfilename);

	ret = journal_map(journal, chk_key, &mptr, sizeof(chk_buf), true);
	if (ret == KNOT_EOK) {
		ret = memcmp(chk_buf, mptr, sizeof(chk_buf));
		journal_unmap(journal, chk_key, mptr, 0);
	}
	is_int(KNOT_EOK, ret, "journal: data integrity check after close/open");

	/*  Write random data. */
	ret = KNOT_EOK;
	for (int i = 0; i < 512; ++i) {
		chk_key = 0xDEAD0000 + i;
		ret = journal_map(journal, chk_key, &mptr, sizeof(chk_buf), false);
		if (ret != KNOT_EOK) {
			diag("journal_map failed: %s", knot_strerror(ret));
			break;
		}
		randstr(mptr, sizeof(chk_buf));
		if ((ret = journal_unmap(journal, chk_key, mptr, 1)) != KNOT_EOK) {
			diag("journal_unmap failed: %s", knot_strerror(ret));
			break;
		}
	}
	is_int(KNOT_EOK, ret, "journal: sustained mmap r/w");

	/* Overfill (yields ESPACE/EBUSY) */
	ret = journal_map(journal, chk_key, &mptr, fsize, false);
	ok(ret != KNOT_EOK, "journal: overfill");

	/* Fillup */
	size_t sizes[] = {16, 64, 1024, 4096, 512 * 1024, 1024 * 1024 };
	const int num_sizes = sizeof(sizes)/sizeof(size_t);
	for (unsigned i = 0; i < 2 * num_sizes; ++i) {
		/* Journal flush. */
		journal_close(journal);
		ret = journal_mark_synced(jfilename);
		is_int(KNOT_EOK, ret, "journal: flush after fillup #%u", i);
		ret = journal_open(&journal, jfilename, fsize);
		ok(ret == KNOT_EOK, "journal: reopen after flush #%u", i);
		/* Journal fillup. */
		if (journal) {
			test_fillup(journal, fsize, i, sizes[i % num_sizes]);
		}
	}

	/* Close journal. */
	journal_close(journal);

	/* Delete journal. */
	remove(jfilename);

	test_store_load(jfilename);
	remove(jfilename);

	test_stress(jfilename);
	remove(jfilename);

	free(tmpdir);

skip_all:
	return 0;
}
