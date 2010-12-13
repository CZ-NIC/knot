#ifndef __CUTEDNS_MALLOC_H__
#define __CUTEDNS_MALLOC_H__

#include <stdlib.h>

#include "debug.h"

/* Redirect malloc only if debugging.
 */
#ifdef MEM_DEBUG

/*! \brief Redirected malloc() call.
 *
 *  This function logs malloc() call with the associated metadata.
 *
 * \param caller - Name of the caller function.
 * \param line   - Number of the line in current caller function.
 * \param size   - Requested block size.
 * \return Result of malloc(size).
 */
void *log_malloc(const char *caller, int line, size_t size);

/* Rewrite original malloc. */
#define malloc(x) log_malloc(__func__, __LINE__, (x))
#endif

#endif
