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

#include "tests/libknot/libknot/zonedb_tests.h"


static int zonedb_tests_count(int argc, char *argv[]);
static int zonedb_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api zonedb_tests_api = {
	"Zone database",      //! Unit name
	&zonedb_tests_count,  //! Count scheduled tests
	&zonedb_tests_run     //! Run scheduled tests
};

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int zonedb_tests_count(int argc, char *argv[])
{
	return 0;
}

/*! Run all scheduled tests for given parameters.
 */
static int zonedb_tests_run(int argc, char *argv[])
{
	return 0;
}
