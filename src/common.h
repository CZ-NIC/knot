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

#ifndef _CUTEDNS_COMMON_H_
#define _CUTEDNS_COMMON_H_

#include <signal.h>
#include <stdint.h>

/* Common types and constants.
 */

typedef unsigned int uint;

#define PROJECT_NAME "CuteDNS" // Project name
#define PROJECT_VER  0x000001  // 0xMMIIRR (MAJOR,MINOR,REVISION)

/* Server. */
#define DEFAULT_THR_COUNT 2    // Default thread count for socket manager
#define DEFAULT_PORT 53531     // Default port

/* Sockets. */
#define TCP_BACKLOG_SIZE 5     // TCP listen backlog size

/* Common includes.
 */

#include "print.h"
#include "log.h"
#include "debug.h"

/* Common macros.
 */

#define ERR_ALLOC_FAILED log_error("Allocation failed at %s:%d (%s ver.%x)\n", \
                                  __FILE__, __LINE__, PROJECT_NAME, PROJECT_VER)

#define CHECK_ALLOC_LOG(var, ret) \
	do { \
		if ((var) == NULL) { \
			ERR_ALLOC_FAILED; \
			return (ret); \
		} \
	} while (0)

#define CHECK_ALLOC(var, ret) \
	do { \
		if ((var) == NULL) { \
			return (ret); \
		} \
	} while (0)

/* Eliminate compiler warning with unused parameters. */
#define UNUSED(param) (param) = (param)

/* Minimum and maximum macros. */
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#define MAX(x,y) ((x) > (y) ? (x) : (y))

//#define STAT_COMPILE

#endif /* _CUTEDNS_COMMON_H_ */

/*! @} */
