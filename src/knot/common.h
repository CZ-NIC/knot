/*!
 * \file common.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Common macros, includes and utilities.
 *
 * \addtogroup utils
 * @{
 */

#ifndef _KNOT_COMMON_H_
#define _KNOT_COMMON_H_

#include <signal.h>
#include <stdint.h>
#include "config.h"

/* Common types and constants.
 */

#define PROJECT_NAME PACKAGE // Project name
#define PROJECT_VER  0x000100  // 0xMMIIRR (MAJOR,MINOR,REVISION)
#define PROJECT_EXEC "knotd" // Project executable
#define ZONEPARSER_EXEC "knot-zcompile" // Zoneparser executable
#define PID_FILE "knot.pid"

/* Server. */
#define CPU_ESTIMATE_MAGIC 2   // Extra threads above the number of processors
#define DEFAULT_THR_COUNT 2    // Default thread count for socket manager
#define DEFAULT_PORT 53531     // Default port

/* Sockets. */
#define TCP_BACKLOG_SIZE 5     // TCP listen backlog size

/* Memory allocator. */
//#define MEM_SLAB_CAP 3   // Cap slab_cache empty slab count (undefined = inf)
#define MEM_COLORING       // Slab cache coloring

#define USE_HASH_TABLE
//#define COMPRESSION_PEDANTIC
//#define TEST_WITH_LDNS

/* Common includes.
 */

#include "common/latency.h"
#include "common/print.h"
#include "knot/other/log.h"
#include "knot/other/debug.h"
#include "dnslib/dnslib-common.h"


/* Eliminate compiler warning with unused parameters. */
#ifndef UNUSED
#define UNUSED(param) (void)(param)
#endif

/* Type-safe minimum and maximum macros. */
#ifndef MIN
#define MIN(a, b) \
	({ typeof (a) _a = (a); typeof (b) _b = (b); _a < _b ? _a : _b; })
#endif

#ifndef MAX
#define MAX(a, b) \
	({ typeof (a) _a = (a); typeof (b) _b = (b); _a > _b ? _a : _b; })
#endif

/* Optimisation macros. */
#ifndef likely
#define likely(x)       __builtin_expect((x),1)
#endif
#ifndef unlikely
#define unlikely(x)     __builtin_expect((x),0)
#endif

//#define STAT_COMPILE
#ifdef HAVE_LIBLDNS
#define TEST_WITH_LDNS
#endif

#endif /* _KNOT_COMMON_H_ */

/*! @} */
