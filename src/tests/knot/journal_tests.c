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

#include "tests/knot/journal_tests.h"
#include "knot/server/journal.h"
#include "knot/other/error.h"

static int journal_tests_count(int argc, char *argv[]);
static int journal_tests_run(int argc, char *argv[]);

/*
 * Unit API.
 */
unit_api journal_tests_api = {
	"Journal",
	&journal_tests_count,
	&journal_tests_run
};

/*
 *  Unit implementation.
 */
static const int JOURNAL_TEST_COUNT = 11;

/*! \brief Generate random string with given length. */
static int randstr(char* dst, size_t len)
{
	for (int i = 0; i < len - 1; ++i) {
		dst[i] = '0' + (int) (('Z'-'0') * (rand() / (RAND_MAX + 1.0)));
	}
	dst[len - 1] = '\0';

	return 0;
}

/*! \brief Walk journal of chars into buffer. */
static int  _wbi = 0;
static char _walkbuf[7];
static int walkchars_cmp(uint64_t k1, uint64_t k2) {
	return k1 - k2;
}

static int walkchars(journal_t *j, journal_node_t *n) {
	journal_read(j, n->id, walkchars_cmp, _walkbuf + _wbi);
	++_wbi;
	return 0;
} 

/*! API: return number of tests. */
static int journal_tests_count(int argc, char *argv[])
{
	return JOURNAL_TEST_COUNT;
}

/*! API: run tests. */
static int journal_tests_run(int argc, char *argv[])
{
	/* Test 1: Create tmpfile. */
	int fsize = 8092;
	int jsize = 6;
	char jfn_buf[] = "/tmp/journal.XXXXXX";
	int tmp_fd = mkstemp(jfn_buf);
	ok(tmp_fd >= 0, "journal: create temporary file");
	skip(tmp_fd < 0, JOURNAL_TEST_COUNT - 1);

	/* Test 2: Create journal. */
	const char *jfilename = jfn_buf;
	int ret = journal_create(jfilename, jsize);
	ok(ret == KNOTD_EOK, "journal: create journal '%s'", jfilename);

	/* Test 3: Open journal. */
	journal_t *j = journal_open(jfilename, fsize, 0);
	ok(j != 0, "journal: open");

	/* Test 4: Write entry to log. */
	const char *sample = "deadbeef";
	ret = journal_write(j, 0x0a, sample, strlen(sample));
	ok(ret == KNOTD_EOK, "journal: write");

	/* Test 5: Read entry from log. */
	char tmpbuf[64] = {'\0'};
	ret = journal_read(j, 0x0a, 0, tmpbuf);
	ok(ret == KNOTD_EOK, "journal: read entry");

	/* Test 6: Compare read data. */
	ret = strncmp(sample, tmpbuf, strlen(sample));
	ok(ret == 0, "journal: read data integrity check");
	
	/* Append several characters. */
	journal_write(j, 0, "X", 1); /* Dummy */
	char word[7] =  { 'w', 'o', 'r', 'd', '0', '\0', '\0' };
	for (int i = 0; i < strlen(word); ++i) {
		journal_write(j, i, word+i, 1);
	}

	/* Test 7: Compare journal_walk() result. */
	_wbi = 0;
	journal_walk(j, walkchars);
	_walkbuf[_wbi] = '\0';
	ret = strcmp(word, _walkbuf);
	ok(ret == 0, "journal: read data integrity check 2 '%s'", _walkbuf);
	_wbi = 0;
	
	/* Test 8: Change single letter and compare. */
	word[5] = 'X';
	journal_write(j, 5, word+5, 1); /* append 'X', shifts out 'w' */
	journal_walk(j, walkchars);
	_walkbuf[_wbi] = '\0';
	ret = strcmp(word + 1, _walkbuf);
	ok(ret == 0, "journal: read data integrity check 3 '%s'", _walkbuf);
	_wbi = 0;
	
	/* Close journal. */
	journal_close(j);
	
	/* Recreate journal. */
	remove(jfilename);
	fsize = 8092;
	jsize = 512;
	ret = journal_create(jfilename, jsize);
	j = journal_open(jfilename, fsize, 0);
	
	/* Test 9: Write random data. */
	int chk_key = 0;
	char chk_buf[64] = {'\0'};
	ret = 0;
	const int itcount = 1;//jsize * 5 + 5;
	for (int i = 0; i < itcount; ++i) {
		int key = rand() % 65535;
		randstr(tmpbuf, sizeof(tmpbuf));
		if (journal_write(j, key, tmpbuf, sizeof(tmpbuf)) != KNOTD_EOK) {
			ret = -1;
			break;
		}

		/* Store some key on the end. */
		if (i == itcount - 2) {
			chk_key = key;
			memcpy(chk_buf, tmpbuf, sizeof(chk_buf));
		}
	}
	ok(ret == 0, "journal: sustained looped writes");

	/* Test 10: Check data integrity. */
	memset(tmpbuf, 0, sizeof(tmpbuf));
	journal_read(j, chk_key, 0, tmpbuf);
	ret = strncmp(chk_buf, tmpbuf, sizeof(chk_buf));
	ok(ret == 0, "journal: read data integrity check");

	/* Test 11: Reopen log and re-read value. */
	memset(tmpbuf, 0, sizeof(tmpbuf));
	journal_close(j);
	j = journal_open(jfilename, fsize, 0);
	journal_read(j, chk_key, 0, tmpbuf);
	ret = strncmp(chk_buf, tmpbuf, sizeof(chk_buf));
	ok(ret == 0, "journal: read data integrity check after close/open");

	/* Close journal. */
	journal_close(j);

	/* Close temporary file fd. */
	close(tmp_fd);

	/* Delete journal. */
	remove(jfilename);

	endskip;

	return 0;
}
