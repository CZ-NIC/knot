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
 * \file journal.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Journal for storing transactions on permanent storage.
 *
 * Journal stores entries on a permanent storage.
 * Each written entry is guaranteed to persist until
 * the maximum file size or node count is reached.
 * Entries are removed from the least recent.
 *
 * Journal file structure
 * <pre>
 *  uint16_t node_count
 *  uint16_t node_queue_head
 *  uint16_t node_queue_tail
 *  journal_entry_t free_segment
 *  node_count *journal_entry_t
 *  ...data...
 * </pre>
 * \addtogroup utils
 * @{
 */

#ifndef _KNOTD_JOURNAL_H_
#define _KNOTD_JOURNAL_H_

#include <stdint.h>
#include <fcntl.h>

/*!
 * \brief Journal entry flags.
 */
typedef enum journal_flag_t {
	JOURNAL_NULL  = 0 << 0, /*!< Invalid journal entry. */
	JOURNAL_FREE  = 1 << 0, /*!< Free journal entry. */
	JOURNAL_VALID = 1 << 1, /*!< Valid journal entry. */
	JOURNAL_DIRTY = 1 << 2  /*!< Journal entry cannot be evicted. */
} journal_flag_t;

/*!
 * \brief Journal node structure.
 *
 * Each node represents journal entry and points
 * to position of the data in the permanent storage.
 */
typedef struct journal_node_t
{
	uint64_t id;    /*!< Node ID. */
	uint16_t flags; /*!< Node flags. */
	uint32_t pos;   /*!< Position in journal file. */
	uint32_t len;   /*!< Entry data length. */
} journal_node_t;

/*!
 * \brief Journal structure.
 *
 * Journal organizes entries as nodes.
 * Nodes are stored in-memory for fast lookup and also
 * backed by a permanent storage.
 * Each journal has a fixed number of nodes.
 *
 * \todo Organize nodes in an advanced structure, like
 *       btree or hash table to improve lookup time (issue #964).
 */
typedef struct journal_t
{
	int fd;
	struct flock fl;        /*!< File lock. */
	uint16_t max_nodes;     /*!< Number of nodes. */
	uint16_t qhead;         /*!< Node queue head. */
	uint16_t qtail;         /*!< Node queue tail. */
	uint16_t bflags;        /*!< Initial flags for each written node. */
	size_t fsize;           /*!< Journal file size. */
	size_t fslimit;         /*!< File size limit. */
	journal_node_t free;    /*!< Free segment. */
	journal_node_t nodes[]; /*!< Array of nodes. */
} journal_t;

/*!
 * \brief Entry identifier compare function.
 *
 * \retval -n if k1 < k2
 * \retval +n if k1 > k2
 * \retval  0 if k1 == k2
 */
typedef int (*journal_cmp_t)(uint64_t k1, uint64_t k2);

/*!
 * \brief Function prototype for journal_walk() function.
 *
 * \param j Associated journal.
 * \param n Pointer to target node.
 */
typedef int (*journal_apply_t)(journal_t *j, journal_node_t *n);

/*
 * Journal defaults and constants.
 */
#define JOURNAL_NCOUNT 1024 /*!< Default node count. */
#define JOURNAL_HSIZE (sizeof(uint16_t) * 3) /*!< max_entries, qhead, qtail */

/*!
 * \brief Create new journal.
 *
 * \param fn Journal file name, will be created if not exist.
 * \param max_nodes Maximum number of nodes in journal.
 *
 * \retval KNOTD_EOK if successful.
 * \retval KNOTD_EINVAL if the file with given name cannot be created.
 * \retval KNOTD_ERROR on I/O error.
 */
int journal_create(const char *fn, uint16_t max_nodes);

/*!
 * \brief Open journal file for read/write.
 *
 * \param fn Journal file name.
 * \param fslimit File size limit (0 for no limit).
 * \param bflags Initial flags for each written node.
 *
 * \retval new journal instance if successful.
 * \retval NULL on error.
 */
journal_t* journal_open(const char *fn, size_t fslimit, uint16_t bflags);

/*!
 * \brief Fetch entry node for given identifier.
 *
 * \param journal Associated journal.
 * \param id Entry identifier.
 * \param cf Compare function (NULL for equality).
 * \param dst Destination for journal entry.
 *
 * \retval KNOTD_EOK if successful.
 * \retval KNOTD_ENOENT if not found.
 */
int journal_fetch(journal_t *journal, uint64_t id,
		  journal_cmp_t cf, journal_node_t** dst);

/*!
 * \brief Read journal entry data.
 *
 * \param journal Associated journal.
 * \param id Entry identifier.
 * \param cf Compare function (NULL for equality).
 * \param dst Pointer to destination memory.
 *
 * \retval KNOTD_EOK if successful.
 * \retval KNOTD_ENOENT if the entry cannot be found.
 * \retval KNOTD_EINVAL if the entry is invalid.
 * \retval KNOTD_ERROR on I/O error.
 */
int journal_read(journal_t *journal, uint64_t id, journal_cmp_t cf, char *dst);

/*!
 * \brief Write journal entry data.
 *
 * \param journal Associated journal.
 * \param id Entry identifier.
 * \param src Pointer to source data.
 *
 * \retval KNOTD_EOK if successful.
 * \retval KNOTD_EAGAIN if no free node is available, need to remove dirty nodes.
 * \retval KNOTD_ERROR on I/O error.
 */
int journal_write(journal_t *journal, uint64_t id, const char *src, size_t size);

/*!
 * \brief Return least recent node (journal head).
 *
 * \param journal Associated journal.
 *
 * \retval node if successful.
 * \retval NULL if empty.
 */
static inline journal_node_t *journal_head(journal_t *journal) {
	return journal->nodes + journal->qhead;
}

/*!
 * \brief Return node after most recent node (journal tail).
 *
 * \param journal Associated journal.
 *
 * \retval node if successful.
 * \retval NULL if empty.
 */
static inline journal_node_t *journal_end(journal_t *journal) {
	return journal->nodes +  journal->qtail;
}

/*!
 * \brief Apply function to each node.
 *
 * \param journal Associated journal.
 * \param apply Function to apply to each node.
 *
 * \retval KNOTD_EOK if successful.
 * \retval KNOTD_EINVAL on invalid parameters.
 */
int journal_walk(journal_t *journal, journal_apply_t apply);

/*!
 * \brief Sync node state to permanent storage.
 *
 * \note May be used for journal_walk().
 *
 * \param journal Associated journal.
 * \param n Pointer to node (must belong to associated journal).
 *
 * \retval KNOTD_EOK on success.
 * \retval KNOTD_EINVAL on invalid parameters.
 */
int journal_update(journal_t *journal, journal_node_t *n);

/*!
 * \brief Close journal file.
 *
 * \param journal Associated journal.
 *
 * \retval KNOTD_EOK on success.
 * \retval KNOTD_EINVAL on invalid parameter.
 */
int journal_close(journal_t *journal);

#endif /* _KNOTD_JOURNAL_H_ */
