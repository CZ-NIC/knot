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

/*
 * Common types and constants.
 */

typedef unsigned int uint; /*!< \brief Unsigned. */

#define PROJECT_NAME PACKAGE /*!< \brief Project name. */
#define PROJECT_VER  0x000100  /*!< \brief  0xMMIIRR (MAJOR,MINOR,REVISION). */
#define PROJECT_EXEC "knotd" /*!< \brief  Project executable. */
#define ZONEPARSER_EXEC "knot-zcompile" /*!< \brief  Zoneparser executable. */
#define PID_FILE "knot.pid" /*!< \brief Server PID file name. */

/*
 * Server.
 */

#define CPU_ESTIMATE_MAGIC 2 /*!< \brief Extra threads to the number of cores.*/
#define DEFAULT_THR_COUNT 2  /*!< \brief Default thread count. */
#define DEFAULT_PORT 53531   /*!< \brief Default interface port. */
#define TCP_BACKLOG_SIZE 5   /*!< \brief TCP listen backlog size. */
#define XFR_THREADS_COUNT 3  /*!< \brief Number of threads for XFR handler. */

///*! \brief If defined, zone structures will use hash table for lookup. */
//#define COMPRESSION_PEDANTIC

///*!
// * \brief If defined, tests will use ldns library to parse sample data.
// *
// * If not defined, some tests will be disabled.
// */
//#define TEST_WITH_LDNS

///*! \brief If defined, the statistics module will be enabled. */
//#define STAT_COMPILE


#ifdef HAVE_LIBLDNS
#define TEST_WITH_LDNS
#endif

/*
 * Common includes.
 */

#include "common/latency.h"
#include "common/print.h"
#include "knot/other/log.h"
#include "knot/other/debug.h"

/*! \brief Eliminate compiler warning with unused parameters. */
#define UNUSED(param) (void)(param)

/*! \brief Type-safe minimum macro. */
#define MIN(a, b) \
	({ typeof (a) _a = (a); typeof (b) _b = (b); _a < _b ? _a : _b; })

/*! \brief Type-safe maximum macro. */
#define MAX(a, b) \
	({ typeof (a) _a = (a); typeof (b) _b = (b); _a > _b ? _a : _b; })

/* Optimisation macros. */
#ifndef likely
/*! \brief Optimize for x to be true value. */
#define likely(x)       __builtin_expect((x),1)
#endif
#ifndef unlikely
/*! \brief Optimize for x to be false value. */
#define unlikely(x)     __builtin_expect((x),0)
#endif

/*! \todo Refactor theese. We should have an allocator function handling this.*/
#ifndef ERR_ALLOC_FAILED
#define ERR_ALLOC_FAILED fprintf(stderr, "Allocation failed at %s:%d (%s ver.%x)\n", \
				 __FILE__, __LINE__, PROJECT_NAME, PROJECT_VER)
#endif

#ifndef CHECK_ALLOC_LOG
#define CHECK_ALLOC_LOG(var, ret) \
	do { \
		if ((var) == NULL) { \
			ERR_ALLOC_FAILED; \
			return (ret); \
		} \
	} while (0)
#endif

#ifndef CHECK_ALLOC
#define CHECK_ALLOC(var, ret) \
	do { \
		if ((var) == NULL) { \
			return (ret); \
		} \
	} while (0)
#endif

#endif /* _KNOT_COMMON_H_ */

/*! @} */
