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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <tap/basic.h>

#include "knot/server/journal.h"

/*! \brief Generate random string with given length. */
static int randstr(char* dst, size_t len)
{
	for (int i = 0; i < len - 1; ++i) {
		dst[i] = '0' + (int) (('Z'-'0') * (rand() / (RAND_MAX + 1.0)));
	}
	dst[len - 1] = '\0';

	return 0;
}

/*! \brief Journal fillup test with size check. */
static void test_fillup(journal_t *journal, int fsize, const char *note)
{
	const int chunk = 512 + rand() % 512;
	int ret = KNOT_EOK;
	char *mptr = NULL;
	size_t large_entry_len = chunk * 1024;
	char *large_entry = malloc(chunk * 1024);
	assert(large_entry);
	randstr(large_entry, large_entry_len);
	for (int i = 0; i < chunk; ++i) {
		uint64_t chk_key = (uint64_t)journal + i;
		ret = journal_map(journal, chk_key, &mptr, large_entry_len, false);
		if (ret != KNOT_EOK) {
			break;
		}

		memcpy(mptr, large_entry, large_entry_len);
		journal_unmap(journal, chk_key, mptr, 1);
	}
	is_int(KNOT_EBUSY, ret, "journal: %s fillup", note);
	free(large_entry);

	/* Check file size. */
	struct stat st;
	fstat(journal->fd, &st);
	ok(st.st_size < fsize + large_entry_len, "journal: %s fillup file size check", note);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	/* Create tmpdir */
	int fsize = 10 * 1024 * 1024;
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

	/* Open/create new journal. */
	journal_t *journal = journal_open(jfilename, fsize);
	ok(journal != NULL, "journal: open journal '%s'", jfilename);
	if (journal == NULL) {
		goto skip_all;
	}

	/* Write entry and check integrity. */
	char *mptr = NULL;
	uint64_t chk_key = 0;
	char chk_buf[64] = {'\0'};
	randstr(chk_buf, sizeof(chk_buf));
	int ret = journal_map(journal, chk_key, &mptr, sizeof(chk_buf), false);
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
	journal = journal_open(jfilename, fsize);
	ok(journal != NULL, "journal: open journal '%s'", jfilename);

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

	/* Overfill */
	ret = journal_map(journal, chk_key, &mptr, fsize, false);
	is_int(KNOT_ESPACE, ret, "journal: overfill");

	/* Fillup */
	test_fillup(journal, fsize, "iter#1");
	
	/* Journal flush + refill. */
	journal_close(journal);
	ret = journal_mark_synced(jfilename);
	is_int(KNOT_EOK, ret, "journal: flush after fillup");
	journal = journal_open(jfilename, fsize);
	ok(journal != NULL, "journal: reopen after flush");
	
	/* Fillup */
	test_fillup(journal, fsize, "iter#2");

	/* Close journal. */
	journal_close(journal);

	/* Delete journal. */
	remove(jfilename);
	free(tmpdir);

skip_all:
	return 0;
}
