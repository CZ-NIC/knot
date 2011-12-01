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

#include "tests/libknot/libknot/rrset_tests.h"
#include "libknot/common.h"
#include "libknot/util/descriptor.h"
#include "libknot/rrset.h"
#include "libknot/dname.h"
#include "libknot/rdata.h"
#include "libknot/util/utils.h"
#include "libknot/zone/node.h"
#include "libknot/util/debug.h"


#include "tsig_tests.h"

static int knot_tsig_tests_count(int argc, char *argv[]);
static int knot_tsig_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api tsig_tests_api = {
	"DNS library - tsig",        //! Unit name
	&knot_tsig_tests_count,  //! Count scheduled tests
	&knot_tsig_tests_run     //! Run scheduled tests
};

static const int KNOT_TSIG_TEST_COUNT = 1;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int knot_tsig_tests_count(int argc, char *argv[])
{
	return KNOT_TSIG_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int knot_tsig_tests_run(int argc, char *argv[])
{
}
