/*!
 * \file journal.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Journal for storing transactions on permanent storage.
 *
 * \addtogroup utils
 * @{
 */

#ifndef _KNOT_JOURNAL_H_
#define _KNOT_JOURNAL_H_

#include <stdint.h>

/* File structure
 * uint16_t max_entries
 * <max_entries + 1> * journal_entry_t
 * <data>
 */

typedef enum journal_flag_t {
	JOURNAL_NULL  = 0 << 0, /*!< Invalid journal entry. */
	JOURNAL_VALID = 1 << 0  /*!< Valid journal entry. */
} journal_flag_t;

/*! 12 bytes. */
typedef struct journal_node_t
{
	uint16_t id;    /*!< Node ID. */
	uint16_t flags; /*!< Node flags. */
	uint32_t pos;   /*!< Position in journal file. */
	uint32_t len;   /*!< Entry data length. */
} journal_node_t;

/*! \todo Review nodes data storage type. */

typedef struct journal_t
{
	FILE *fp;
	uint16_t max_nodes; /*!< Number of nodes. */
	uint16_t n_next; /*! \todo Temporary index to next free node. */
	journal_node_t free; /*!< Free segment. */
	journal_node_t nodes[]; /*!< Array of nodes. */
	/* Implement nodes as queue? */
} journal_t;

#define JOURNAL_NCOUNT 512 /*!< Default node count. */

/*!  max_entries */
#define JOURNAL_HSIZE (sizeof(uint16_t))

/*! \todo Document functions. */

int journal_create(const char *fn, uint16_t max_nodes);
journal_t* journal_open(const char *fn);
int journal_fetch(journal_t *journal, int id, const journal_node_t** dst);
int journal_read(journal_t *journal, int id, char *dst);
int journal_write(journal_t *journal, int id, const char *src, size_t size);
int journal_close(journal_t *journal);



#endif /* _KNOT_JOURNAL_H_ */
