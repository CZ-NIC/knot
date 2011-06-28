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
static const int JOURNAL_TEST_COUNT = 8;

/*! \brief Generate random string with given length. */
static int randstr(char* dst, size_t len)
{
	for (int i = 0; i < len - 1; ++i) {
		dst[i] = '0' + (int) (('Z'-'0') * (rand() / (RAND_MAX + 1.0)));
	}
	dst[len - 1] = '\0';

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
	/* Test 1: Create journal. */
	const int jsize = 256;
	char jfn_buf[] = "/tmp/journal.XXXXXX";
	mkstemp(jfn_buf);
	const char *jfilename = jfn_buf;
	int ret = journal_create(jfilename, jsize);
	ok(ret == KNOT_EOK, "journal: create journal '%s'", jfilename);

	/* Test 2: Open journal. */
	journal_t *j = journal_open(jfilename);
	ok(j != 0, "journal: open");

	/* Test 3: Write entry to log. */
	const char *sample = "deadbeef";
	ret = journal_write(j, 0x0a, sample, strlen(sample));
	ok(ret == KNOT_EOK, "journal: write");

	/* Test 4: Read entry from log. */
	char tmpbuf[64] = {'\0'};
	ret = journal_read(j, 0x0a, tmpbuf);
	ok(ret == KNOT_EOK, "journal: read entry");

	/* Test 5: Compare read data. */
	ret = strncmp(sample, tmpbuf, strlen(sample));
	ok(ret == 0, "journal: read data integrity check");

	/* Test 6: Write random data. */
	int chk_key = 0;
	char chk_buf[64] = {'\0'};
	ret = 0;
	const int itcount = jsize * 3;
	for (int i = 0; i < itcount; ++i) {
		int key = rand() % 65535;
		randstr(tmpbuf, sizeof(tmpbuf));
		if (journal_write(j, key, tmpbuf, sizeof(tmpbuf)) != KNOT_EOK) {
			ret = -1;
			break;
		}

		/* Store some key on the end. */
		if (i == itcount - jsize/5) {
			chk_key = key;
			memcpy(chk_buf, tmpbuf, sizeof(chk_buf));
		}
	}
	ok(ret == 0, "journal: sustained looped writes");

	/* Test 7: Check data integrity. */
	memset(tmpbuf, 0, sizeof(tmpbuf));
	journal_read(j, chk_key, tmpbuf);
	ret = strncmp(chk_buf, tmpbuf, sizeof(chk_buf));
	ok(ret == 0, "journal: read data integrity check");

	/* Test 8: Reopen log and re-read value. */
	memset(tmpbuf, 0, sizeof(tmpbuf));
	journal_close(j);
	j = journal_open(jfilename);
	journal_read(j, chk_key, tmpbuf);
	ret = strncmp(chk_buf, tmpbuf, sizeof(chk_buf));
	ok(ret == 0, "journal: read data integrity check after close/open");

	/* Close journal. */
	journal_close(j);

	/* Delete journal. */
	unlink(jfilename);

	return 0;
}
