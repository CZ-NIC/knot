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
#ifndef _KNOT_DNSLIB_COMMON_H_
#define _KNOT_DNSLIB_COMMON_H_

#define PROJECT_NAME "dnslib" // Project name
#define PROJECT_VER  0x000100  // 0xMMIIRR (MAJOR,MINOR,REVISION)

typedef unsigned int uint;

/* Common macros.
 */

#define ERR_ALLOC_FAILED fprintf(stderr, "Allocation failed at %s:%d (%s ver.%x)\n", \
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

/* Optimisation macros. */
#ifndef likely
#define likely(x)       __builtin_expect((x),1)
#endif
#ifndef unlikely
#define unlikely(x)     __builtin_expect((x),0)
#endif

#endif /* _KNOT_DNSLIB_COMMON_H_ */

/*! @} */
