#ifndef COMMON
#define COMMON

/* Common types and constants.
 */

typedef unsigned int uint;

#define PROJECT_NAME "CuteDNS" // Project name
#define PROJECT_VER  0x000001  // 0xMMIIRR (MAJOR,MINOR,REVISION)

/* Common includes.
 */

#include "print.h"
#include "log.h"

/* Common macros.
 */
#define ERR_ALLOC_FAILED log_error("Allocation failed at %s:%d (%s ver.%x)\n", __FILE__, __LINE__, PROJECT_NAME, PROJECT_VER)

#endif // COMMON
