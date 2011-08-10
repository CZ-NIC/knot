/*!
 * \file malloc.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Memory allocation related functions.
 *
 * \addtogroup alloc
 * @{
 */

#ifndef _KNOTD_COMMON_MALLOC_H_
#define _KNOTD_COMMON_MALLOC_H_

#include <stdlib.h>

/*! \brief Print usage statistics.
 *
 *  \note This function has destructor attribute set if MEM_DEBUG is enabled.
 *
 *  \warning Not all printed statistics are available on every OS,
 *           consult manual page for getrusage(2).
 */
void usage_dump();

#endif // _KNOTD_COMMON_MALLOC_H_

/*! @} */
