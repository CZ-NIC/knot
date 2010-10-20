#ifndef COMMON
#define COMMON
#include <signal.h>

/* Common types and constants.
 */

typedef unsigned int uint;

#define PROJECT_NAME "CuteDNS" // Project name
#define PROJECT_VER  0x000001  // 0xMMIIRR (MAJOR,MINOR,REVISION)

/* Server. */
#define SERVER_MGR_COUNT  2    // TCP + UDP
#define DEFAULT_THR_COUNT 2    // Default thread count for socket manager
#define DEFAULT_PORT 53531     // Default port

/* Common includes.
 */

#include "print.h"
#include "log.h"
#include "debug.h"

/* Common macros.
 */
#define ERR_ALLOC_FAILED log_error("Allocation failed at %s:%d (%s ver.%x)\n", __FILE__, __LINE__, PROJECT_NAME, PROJECT_VER)

/* Eliminate compiler warning with unused parameters. */
#define UNUSED(param) (param) = (param)

/* Signal definitions. */
#define SIGCLOSE SIGALRM
#define SIGREADY SIGUSR1

#endif // COMMON
