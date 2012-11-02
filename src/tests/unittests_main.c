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

#include <config.h>
#include "knot/common.h"
#include "common/libtap/tap_unit.h"

// Units to test
#include "tests/common/slab_tests.h"
#include "tests/common/skiplist_tests.h"
#include "tests/common/events_tests.h"
#include "tests/common/acl_tests.h"
#include "tests/common/fdset_tests.h"
#include "tests/common/base64_tests.h"
#include "tests/common/base32hex_tests.h"
#include "tests/knot/dthreads_tests.h"
#include "tests/knot/journal_tests.h"
#include "tests/knot/server_tests.h"
#include "tests/knot/conf_tests.h"

// Run all loaded units
int main(int argc, char *argv[])
{
	// Open log
	log_init();
	log_levels_set(LOGT_SYSLOG, LOG_ANY, 0);
	log_levels_set(LOGT_STDERR, LOG_ANY, 0);
	log_levels_set(LOGT_STDOUT, LOG_ANY, LOG_MASK(LOG_DEBUG));

	// Build test set
	unit_api *tests[] = {
		/* Core data structures. */
		&journal_tests_api,	//! Journal unit
		&slab_tests_api,	//! SLAB allocator unit
		&skiplist_tests_api,	//! Skip list unit
		&dthreads_tests_api,	//! DThreads testing unit
		&events_tests_api,	//! Events testing unit
		&acl_tests_api,		//! ACLs
		&fdset_tests_api,	//! FDSET polling wrapper
		&base64_tests_api,	//! Base64 encoding
		&base32hex_tests_api,	//! Base32hex encoding

		/* Server parts. */
		&conf_tests_api,	//! Configuration parser tests
		&server_tests_api,	//! Server unit
		NULL
	};

	// Plan number of tests
	int id = 0;
	int test_count = 0;
	note("Units:");
	while (tests[id] != NULL) {
		note("- %s : %d tests", tests[id]->name,
		     tests[id]->count(argc, argv));
		test_count += tests[id]->count(argc, argv);
		++id;
	}

	plan(test_count);

	// Run tests
	id = 0;
	while (tests[id] != NULL) {
		diag("Testing unit: %s", tests[id]->name);
		tests[id]->run(argc, argv);
		++id;
	}

	log_close();

	// Evaluate
	return exit_status();
}

