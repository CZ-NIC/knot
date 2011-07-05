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

#ifndef _KNOT_JOURNAL_H_
#define _KNOT_JOURNAL_H_

#include <stdint.h>

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
	uint16_t id;    /*!< Node ID. */
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
 *       btree or hash table to improve lookup time.
 */
typedef struct journal_t
{
	FILE *fp;
	uint16_t max_nodes;     /*!< Number of nodes. */
	uint16_t qhead;         /*!< Node queue head. */
	uint16_t qtail;         /*!< Node queue tail. */
	journal_node_t free;    /*!< Free segment. */
	journal_node_t nodes[]; /*!< Array of nodes. */
} journal_t;

/*
 * Journal defaults and constants.
 */
#define JOURNAL_NCOUNT 512 /*!< Default node count. */
#define JOURNAL_HSIZE (sizeof(uint16_t) * 3) /*!< max_entries, qhead, qtail */

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
 *
 * \retval new journal instance if successful.
 * \retval NULL on error.
 */
journal_t* journal_open(const char *fn);

/*!
 * \brief Fetch entry node for given identifier.
 *
 * \param journal Associated journal.
 * \param id Entry identifier.
 * \param dst Destination for journal entry.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_ENOENT if not found.
 */
int journal_fetch(journal_t *journal, int id, const journal_node_t** dst);

/*!
 * \brief Read journal entry data.
 *
 * \param journal Associated journal.
 * \param id Entry identifier.
 * \param dst Pointer to destination memory.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_ENOENT if the entry cannot be found.
 * \retval KNOT_EINVAL if the entry is invalid.
 * \retval KNOT_ERROR on I/O error.
 */
int journal_read(journal_t *journal, int id, char *dst);

/*!
 * \brief Write journal entry data.
 *
 * \param journal Associated journal.
 * \param id Entry identifier.
 * \param src Pointer to source data.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_ERROR on I/O error.
 */
int journal_write(journal_t *journal, int id, const char *src, size_t size);

/*!
 * \brief Close journal file.
 *
 * \param journal Associated journal.
 *
 * \retval KNOT_EOK
 */
int journal_close(journal_t *journal);

#endif /* _KNOT_JOURNAL_H_ */
