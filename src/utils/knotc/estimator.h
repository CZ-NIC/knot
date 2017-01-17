/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \file
 *
 * \brief Memory estimation for zone files.
 *
 * \addtogroup knot_utils
 * @{
 */

#pragma once

#include "contrib/qp-trie/trie.h"
#include "zscanner/scanner.h"

/*!
 * \brief Memory estimation context.
 */
typedef struct {
	trie_t *node_table;  /*!< Same trie is in actual zone. */
	size_t rdata_size;   /*!< Estimated RDATA size. */
	size_t dname_size;   /*!< Estimated DNAME size. */
	size_t node_size;    /*!< Estimated node size. */
	size_t record_count; /*!< Total record count for zone. */
} zone_estim_t;

/*!
 * \brief Size counting malloc wrapper.
 *
 * \param ctx Data for malloc wrapper.
 * \param len Size to allocate.
 *
 * \retval Alloc'd data on succes.
 * \retval NULL on error.
 */
void *estimator_malloc(void *ctx, size_t len);

/*!
 * \brief Size counting free wrapper.
 *
 * \param p Data to free.
 */
void estimator_free(void *p);

/*!
 * \brief For use with scanner - counts memsize of RRSets.
 *
 * \param scanner Scanner context.
 */
void estimator_rrset_memsize_wrap(zs_scanner_t *scanner);

/*!
 * \brief Cleanup function for use with trie.
 *
 * \param p Data to free.
 */
int estimator_free_trie_node(trie_val_t *val, void *data);

/*! @} */
