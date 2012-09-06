/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/*!
 * \file mempattern.h
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

/*!
 * \brief Reserve new or trim excessive memory.
 *
 * \param p Double-pointer to memory region.
 * \param tlen Memory unit (f.e. sizeof(int) for int* array)
 * \param min Minimum number of items required.
 * \param allow Maximum extra items to keep (for trimming).
 * \param reserved Pointer to number of already reserved items.
 *
 * \note Example usage:
 * char *buf = NULL; size_t len = 0;
 * if (mreserve(&buf, sizeof(char), 6, 0, &len) == 0) {
 *   memcpy(buf, "hello", strlen("hello");
 *   if (mreserve(&buf, sizeof(char), 20, 0, &len) == 0) {
 *     strncat(buf, "!", 1);
 *     mreserve(&buf, sizeof(char), strlen("hello!")+1, 0, &len);
 *   }
 * }
 * free(buf);
 *
 * \retval 0 on success.
 * \retval -1 on error.
 *
 * \note Memory region will be left untouched if function fails.
 */
int mreserve(char **p, size_t tlen, size_t min, size_t allow, size_t *reserved);

/*!
 * \brief Format string and take care of allocating memory.
 *
 * \note sprintf(3) manual page reference implementation.
 *
 * \param fmt Message format.
 * \return formatted message or NULL.
 */
char* sprintf_alloc(const char *fmt, ...);

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
