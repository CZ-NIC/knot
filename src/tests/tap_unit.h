/*!
 * \file tap_unit.h
 * \author Marek Vavrusa <marek.vavusa@nic.cz>
 *
 * \brief libtap test unit.
 *
 * Contains description of a single test unit API.
 *
 * \addtogroup tests
 * @{
 */

#ifndef _CUTEDNS_TAP_UNIT_H_
#define _CUTEDNS_TAP_UNIT_H_

#include "libtap/tap.h"

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

#endif // _CUTEDNS_TAP_UNIT_H_

/*! @} */

