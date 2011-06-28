#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "knot/other/error.h"
#include "knot/other/debug.h"
#include "journal.h"

static inline int sfread(void *dst, size_t len, FILE *fp)
{
	return fread(dst, len, 1, fp) == 1;
}

static inline int sfwrite(const void *src, size_t len, FILE *fp)
{
	return fwrite(src, len, 1, fp) == 1;
}

int journal_create(const char *fn, uint16_t max_nodes)
{
	/* Create journal file. */
	FILE *fp = fopen(fn, "w");
	if (!fp) {
		debug_journal("journal: failed to create file '%s'\n", fn);
		return KNOT_EINVAL;
	}

	/* Disable buffering. */
	setvbuf(fp, (char *)0, _IONBF, 0);

	/* Create journal header. */
	debug_journal("journal: creating header\n");
	if (!sfwrite(&max_nodes, sizeof(uint16_t), fp)) {
		fclose(fp);
		unlink(fn);
		return KNOT_ERROR;
	}

	/* Create empty queue head + tail. */
	uint16_t zval = 0;
	if (!sfwrite(&zval, sizeof(uint16_t), fp)) {
		fclose(fp);
		unlink(fn);
		return KNOT_ERROR;
	}
	if (!sfwrite(&zval, sizeof(uint16_t), fp)) {
		fclose(fp);
		unlink(fn);
		return KNOT_ERROR;
	}

	debug_journal("journal: creating free segment descriptor\n");

	/* Create free segment descriptor. */
	journal_node_t jn;
	jn.id = 0;
	jn.flags = JOURNAL_VALID;
	jn.pos = JOURNAL_HSIZE + (max_nodes + 1) * sizeof(journal_node_t);
	jn.len = 0;
	if (!sfwrite(&jn, sizeof(journal_node_t), fp)) {
		fclose(fp);
		unlink(fn);
		return KNOT_ERROR;
	}

	/* Create nodes. */
	debug_journal("journal: creating node table, size=%u\n", max_nodes);
	memset(&jn, 0, sizeof(journal_node_t));
	for(uint16_t i = 0; i < max_nodes; ++i) {
		if (!sfwrite(&jn, sizeof(journal_node_t), fp)) {
			fclose(fp);
			unlink(fn);
			return KNOT_ERROR;
		}
	}

	/* Journal file created. */
	debug_journal("journal: file '%s' initialized\n", fn);
	return KNOT_EOK;
}

journal_t* journal_open(const char *fn)
{
	/*! \todo Memory mapping may be faster than stdio? */

	/*! \todo Lock file. */

	/* Open journal file for r/w. */
	FILE *fp = fopen(fn, "r+");
	if (!fp) {
		debug_journal("journal: failed to open file '%s'\n", fn);
		return 0;
	}

	/* Disable buffering. */
	setvbuf(fp, (char *)0, _IONBF, 0);

	/* Read maximum number of entries. */
	uint16_t max_nodes = 512;
	if (!sfread(&max_nodes, sizeof(uint16_t), fp)) {
		fclose(fp);
		return 0;
	}

	/* Allocate journal structure. */
	const size_t node_len = sizeof(journal_node_t);
	journal_t *j = malloc(sizeof(journal_t) + max_nodes * node_len);
	if (!j) {
		fclose(fp);
		return 0;
	}
	j->qhead = j->qtail = 0;
	j->fp = fp;
	j->max_nodes = max_nodes;

	/* Load node queue state. */
	if (!sfread(&j->qhead, sizeof(uint16_t), fp)) {
		fclose(fp);
		free(j);
		return 0;
	}

	/* Load queue tail. */
	if (!sfread(&j->qtail, sizeof(uint16_t), fp)) {
		fclose(fp);
		free(j);
		return 0;
	}

	/* Load empty segment descriptor. */
	if (!sfread(&j->free, node_len, fp)) {
		fclose(fp);
		free(j);
		return 0;
	}

	/* Read journal descriptors table. */
	if (fread(&j->nodes, node_len, max_nodes, fp) != max_nodes) {
		fclose(fp);
		free(j);
		return 0;
	}

	/*! \todo Some file checksum, check node integrity. */
	debug_journal("journal: opened journal size=%u, queue=<%u, %u>, fd=%d\n",
		      max_nodes, j->qhead, j->qtail, fileno(j->fp));

	return j;
}

int journal_fetch(journal_t *journal, int id, const journal_node_t** dst)
{
	/*! \todo Organize journal descriptors in btree? */
	/*! \todo Or store pointer to last fetch for sequential lookup? */
	for(uint16_t i = 0; i != journal->max_nodes; ++i) {

		if (journal->nodes[i].id == id) {
			*dst = journal->nodes + i;
			return KNOT_EOK;
		}
	}

	return KNOT_ENOENT;
}

int journal_read(journal_t *journal, int id, char *dst)
{
	const journal_node_t *n = 0;
	if(journal_fetch(journal, id, &n) != 0) {
		debug_journal("journal: failed to fetch node with id=%d\n",
			      id);
		return KNOT_ENOENT;
	}

	/* Check valid flag. */
	if (n->flags != JOURNAL_VALID) {
		debug_journal("journal: node with id=%d is invalid\n", id);
		return KNOT_EINVAL;
	}

	debug_journal("journal: reading node with id=%d, data=<%u, %u>\n",
		      id, n->pos, n->pos + n->len);

	/* Seek journal node. */
	fseek(journal->fp, n->pos, SEEK_SET);

	/* Read journal node content. */
	int ret = fread(dst, n->len, 1, journal->fp);
	if (ret != 1) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int journal_write(journal_t *journal, int id, const char *src, size_t size)
{
	/*! \todo Find key with already existing identifier? */

	const size_t node_len = sizeof(journal_node_t);

	/* Find next free node. */
	uint16_t jnext = (journal->qtail + 1) % journal->max_nodes;

	debug_journal("journal: writing id=%d, node=%u, next=%u\n",
		      id, journal->qtail, jnext);

	/* Increase free segment if on the end of file. */
	journal_node_t *n = journal->nodes + journal->qtail;
	if (journal->free.len < size) {

		/* Increase on the end of node queue / uninitialized. */
		if (journal->qtail > jnext || n->flags == JOURNAL_NULL) {
			debug_journal("journal: growing by +%zu, pos=%u\n",
				      size - journal->free.len, journal->free.pos);
			journal->free.len = size;
		}
	}

	/* Evict occupied nodes if necessary. */
	while (journal->free.len < size) {

		/* Evict least recent node if not empty. */
		journal_node_t *head = journal->nodes + journal->qhead;
		head->flags = JOURNAL_FREE;

		/* Write back evicted node. */
		fseek(journal->fp, JOURNAL_HSIZE + (journal->qhead + 1) * node_len, SEEK_SET);
		if (!sfwrite(head, node_len, journal->fp)) {
			return KNOT_ERROR;
		}

		debug_journal("journal: evicted node=%u, growing by +%u\n",
			      journal->qhead, head->len);

		/* Write back query state. */
		journal->qhead = (journal->qhead + 1) % journal->max_nodes;
		uint16_t qstate[2] = {journal->qhead, journal->qtail};
		fseek(journal->fp, JOURNAL_HSIZE - 2 * sizeof(uint16_t), SEEK_SET);
		if (!sfwrite(qstate, 2 * sizeof(uint16_t), journal->fp)) {
			return KNOT_ERROR;
		}

		/* Increase free segment. */
		journal->free.len += head->len;
	}

	/* Calculate node position in permanent storage. */
	long jn_fpos = JOURNAL_HSIZE + (journal->qtail + 1) * node_len;

	/* Invalidate node and write back. */
	n->id = id;
	n->pos = journal->free.pos;
	n->len = size;
	n->flags = JOURNAL_FREE;
	if (!sfwrite(n, node_len, journal->fp)) {
		debug_journal("journal: failed to writeback node=%d to %u\n",
			      n->id, jn_fpos);
		return KNOT_ERROR;
	}

	/* Write data to permanent storage. */
	fseek(journal->fp, n->pos, SEEK_SET);
	if (!sfwrite(src, size, journal->fp)) {
		return KNOT_ERROR;
	}

	/* Mark node as valid and write back. */
	n->flags = JOURNAL_VALID;
	fseek(journal->fp, jn_fpos, SEEK_SET);
	if (!sfwrite(n, node_len, journal->fp)) {
		return KNOT_ERROR;
	}

	debug_journal("journal: written node=%u, data=<%u, %u>\n",
		      journal->qtail, n->pos, n->pos + n->len);

	/* Trim free space on the last node. */
	if (journal->qtail > jnext) {
		debug_journal("journal: trimming free space, next=%u\n",
			      jnext);
		journal_node_t *next = journal->nodes + jnext;
		journal->free.pos = next->pos;
		journal->free.len = 0;
	} else {
		/* Mark used space. */
		journal->free.pos += size;
		journal->free.len -= size;
		debug_journal("journal: free segment <%u, %u>\n",
			journal->free.pos, journal->free.pos + journal->free.len);
	}

	/* Node write successful. */
	journal->qtail = jnext;

	/* Write back free segment state. */
	fseek(journal->fp, JOURNAL_HSIZE, SEEK_SET);
	if (!sfwrite(&journal->free, node_len, journal->fp)) {
		/*! \todo Node is marked valid and failed to shrink free space,
			  node will be overwritten on the next open - this may be
			  a problem, how to solve it properly? */
		return KNOT_ERROR;
	}

	/* Write back query state, not essential as it may be recovered.
	 * qhead - lowest valid node identifier (least recent)
	 * qtail - highest valid node identifier (most recently used)
	 */
	uint16_t qstate[2] = {journal->qhead, journal->qtail};
	fseek(journal->fp, JOURNAL_HSIZE - 2 * sizeof(uint16_t), SEEK_SET);
	if (!sfwrite(qstate, 2 * sizeof(uint16_t), journal->fp)) {
		return KNOT_ERROR;
	}

	/*! \todo Delayed write-back? */

	debug_journal("journal: write finished, nqueue=<%u, %u>\n",
		      journal->qhead, journal->qtail);

	return KNOT_EOK;
}

int journal_close(journal_t *journal)
{
	/* Close file. */
	fclose(journal->fp);

	debug_journal("journal: closed journal %p\n", journal);

	/* Free allocated resources. */
	free(journal);

	return KNOT_EOK;
}
