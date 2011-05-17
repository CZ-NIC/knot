/*!
 * \file dnslib-common.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Common macros, includes and utilities.
 *
 * \addtogroup dnslib
 * @{
 */
#include <config.h>

#ifdef HAVE_LIBLDNS
#define TEST_WITH_LDNS
#endif

#ifndef _KNOT_DNSLIB_COMMON_H_
#define _KNOT_DNSLIB_COMMON_H_

#define DNSLIB_NAME "dnslib" // Project name
#define DNSLIB_VER  0x000100  // 0xMMIIRR (MAJOR,MINOR,REVISION)
#include "dnslib/fmalloc.h"

typedef unsigned int uint;

/*! \brief If defined, zone structures will use hash table for lookup. */
#define USE_HASH_TABLE

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

/* Optimisation macros. */
#ifndef likely
/*! \brief Optimize for x to be true value. */
#define likely(x)       __builtin_expect((x),1)
#endif
#ifndef unlikely
/*! \brief Optimize for x to be false value. */
#define unlikely(x)     __builtin_expect((x),0)
#endif

#define malloc(x) malloc_with_count(x)
/*! \todo Refactor theese. We should have an allocator function handling this.*/
#ifndef ERR_ALLOC_FAILED
#define ERR_ALLOC_FAILED fprintf(stderr, "Allocation failed at %s:%d (%s ver.%x)\n", \
				 __FILE__, __LINE__, DNSLIB_NAME, DNSLIB_VER)
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

#endif /* _KNOT_DNSLIB_COMMON_H_ */

/*! @} */
