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
	JOURNAL_DIRTY = 1 << 2, /*!< Journal entry cannot be evicted. */
	JOURNAL_TRANS = 1 << 3  /*!< Entry is in transaction (uncommited). */
} journal_flag_t;

/*!
 * \brief Journal mode.
 */
typedef enum journal_mode_t {
	JOURNAL_PERSISTENT = 0 << 0, /*!< Persistent mode (open keeps fd). */
	JOURNAL_LAZY       = 1 << 0  /*!< Lazy mode (open doesn't keep fd). */
} journal_mode_t;

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
	uint16_t next;  /*!< Next node ptr. */
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
	char *path;             /*!< Path to journal file. */
	int refs;               /*!< Number of references. */
	uint16_t tmark;         /*!< Transaction start mark. */
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
#define JOURNAL_MAGIC {'k', 'n', 'o', 't', '1', '4', '0'}
#define MAGIC_LENGTH 7
/* HEADER = magic, crc, max_entries, qhead, qtail */
#define JOURNAL_HSIZE (MAGIC_LENGTH + sizeof(crc_t) + sizeof(uint16_t) * 3)


/*!
 * \brief Create new journal.
 *
 * \param fn Journal file name, will be created if not exist.
 * \param max_nodes Maximum number of nodes in journal.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_EINVAL if the file with given name cannot be created.
 * \retval KNOT_ERROR on I/O error.
 */
int journal_create(const char *fn, uint16_t max_nodes);

/*!
 * \brief Open journal file for read/write.
 *
 * \param fn Journal file name.
 * \param fslimit File size limit (0 for no limit).
 * \param mode Open mode (0 for normal).
 * \param bflags Initial flags for each written node.
 *
 * \retval new journal instance if successful.
 * \retval NULL on error.
 */
journal_t* journal_open(const char *fn, size_t fslimit, int mode, uint16_t bflags);

/*!
 * \brief Fetch entry node for given identifier.
 *
 * \param journal Associated journal.
 * \param id Entry identifier.
 * \param cf Compare function (NULL for equality).
 * \param dst Destination for journal entry.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_ENOENT if not found.
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
 * \retval KNOT_EOK if successful.
 * \retval KNOT_ENOENT if the entry cannot be found.
 * \retval KNOT_EINVAL if the entry is invalid.
 * \retval KNOT_ERROR on I/O error.
 */
int journal_read(journal_t *journal, uint64_t id, journal_cmp_t cf, char *dst);

/*!
 * \brief Read journal entry data.
 *
 * \param journal Associated journal.
 * \param n Entry.
 * \param dst Pointer to destination memory.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_ENOENT if the entry cannot be found.
 * \retval KNOT_EINVAL if the entry is invalid.
 * \retval KNOT_ERROR on I/O error.
 */
int journal_read_node(journal_t *journal, journal_node_t *n, char *dst);


/*!
 * \brief Write journal entry data.
 *
 * \param journal Associated journal.
 * \param id Entry identifier.
 * \param src Pointer to source data.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_EAGAIN if no free node is available, need to remove dirty nodes.
 * \retval KNOT_ERROR on I/O error.
 */
int journal_write(journal_t *journal, uint64_t id, const char *src, size_t size);

/*!
 * \brief Map journal entry for read/write.
 *
 * \warning New nodes shouldn't be created until the entry is unmapped.
 *
 * \param journal Associated journal.
 * \param id Entry identifier.
 * \param dst Will contain mapped memory.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_EAGAIN if no free node is available, need to remove dirty nodes.
 * \retval KNOT_ERROR on I/O error.
 */
int journal_map(journal_t *journal, uint64_t id, char **dst, size_t size);

/*!
 * \brief Finalize mapped journal entry.
 *
 * \param journal Associated journal.
 * \param id Entry identifier.
 * \param ptr Mapped memory.
 * \param finalize Set to true to finalize node or False to discard it.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_ENOENT if the entry cannot be found.
 * \retval KNOT_EAGAIN if no free node is available, need to remove dirty nodes.
 * \retval KNOT_ERROR on I/O error.
 */
int journal_unmap(journal_t *journal, uint64_t id, void *ptr, int finalize);

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
 * \retval KNOT_EOK if successful.
 * \retval KNOT_EINVAL on invalid parameters.
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
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 */
int journal_update(journal_t *journal, journal_node_t *n);

/*!
 * \brief Begin transaction of multiple entries.
 *
 * \note Only one transaction at a time is supported.
 *
 * \param journal Associated journal.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_EBUSY if transaction is already pending.
 */
int journal_trans_begin(journal_t *journal);

/*!
 * \brief Commit pending transaction.
 *
 * \note Only one transaction at a time is supported.
 *
 * \param journal Associated journal.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ENOENT if no transaction is pending.
 */
int journal_trans_commit(journal_t *journal);

/*!
 * \brief Rollback pending transaction.
 *
 * \note Only one transaction at a time is supported.
 *
 * \param journal Associated journal.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ENOENT if no transaction is pending.
 */
int journal_trans_rollback(journal_t *journal);

/*!
 * \brief Close journal file.
 *
 * \param journal Associated journal.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameter.
 */
int journal_close(journal_t *journal);

/*!
 * \brief Retain journal for use.
 *
 * Allows to track usage of lazily-opened journals.
 *
 * \param journal Journal.
 *
 * \return Retained journal.
 */
journal_t *journal_retain(journal_t *journal);

/*!
 * \brief Release retained journal.
 *
 * \param journal Retained journal.
 */
void journal_release(journal_t *journal);

/*!
 * \brief Recompute journal CRC.
 *
 * \warning Use only if you altered the journal file somehow
 * and need it to pass CRC checks. CRC check normally
 * checks file integrity, so you should not touch it unless
 * you know what you're doing.
 *
 * \param fd Open journal file.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL if not valid fd.
 */
int journal_update_crc(int fd);

#endif /* _KNOTD_JOURNAL_H_ */

/*! @} */
