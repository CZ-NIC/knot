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
/*!
 * \file tap_unit.h
 * \author Marek Vavrusa <marek.vavusa@nic.cz>
 *
 * \brief libtap test unit.
 *
 * Contains description of a single test unit API.
 *
 * Export unit_api in each module header file,
 * and set function pointer to according test routines.
 *
 * <b>Example code for myunit.h</b>
 * \code
 * #ifndef MYUNIT_TEST_H
 * #define MYUNIT_TEST_H
 *
 * // Export unittest symbol
 * unit_api mymodule;
 *
 * #endif // MYUNIT_TEST_H
 * \endcode
 *
 * <b>Example code for myunit.c</b>
 * \code
 * #include "myunit.h"
 *
 * // Function to return unit test count
 * int myunit_count(int argc, char *argv[]) {
 *     return 1; // Number of tests in this unit
 * }
 *
 * // Function to perform tests
 * int myunit_run(int argc, char *argv[]) {
 *     // 1. test
 *     ok(1 == 1, "test OK");
 *     return 0;
 * }
 *
 * // Declare module API
 * unit_api mymodule = {
 *     "My module",
 *     &myunit_count,
 *     &myunit_run
 * };
 * \endcode
 *
 * To incorporate test, add it to unit tests main().
 *
 * See https://github.com/zorgnax/libtap for libtap API reference.
 *
 * \addtogroup tests
 * @{
 */

#ifndef _TAP_UNIT_H_
#define _TAP_UNIT_H_

#include "common/libtap/tap.h"

/*! \brief Pointer to function for unit_api. */
typedef int(unitapi_f)(int, char*[]);


/*!
 * \brief Basic Unit APIs.
 *
 * Each unit should have one global variable with
 * an initialized instance of unit_api.
 */
typedef struct {
	const char *name;  /*!< Test unit name. */
	unitapi_f  *count; /*!< Function to calculate number of tests. */
	unitapi_f  *run;   /*!< Function to run unit tests. */
} unit_api;

#endif // _TAP_UNIT_H_

/*! @} */
