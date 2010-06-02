#ifndef COMMON
#define COMMON

/* Common types and macros.
 */

typedef unsigned int uint;

#define PROJECT_NAME "CuteDNS" // Project name
#define PROJECT_VER  0x000001  // 0xMMIIRR (MAJOR,MINOR,REVISION)
#define ERR_ALLOC_FAILED fprintf(stderr, "Allocation failed.\n")

/* Common includes.
 */

#include "print.h"
#include "log.h"

#endif // COMMON
