#ifndef TAP_UNIT_H
#define TAP_UNIT_H

#include "libtap/tap.h"

/*! Pointer to function for unit_api.
 */
typedef int(unitapi_f)(int,char*[]);


/*! Basic Unit APIs.
 *
 *  Each unit should have one global variable with
 *  initialized instance of unit_api.
 *
 *  Unit API should contain:
 *  - name (const char*)
 *  - count (function to calculate number of tests)
 *  - run (function to run unit tests)
 */
typedef struct {
   const char* name;
   unitapi_f* count;
   unitapi_f* run;
} unit_api;

#endif
