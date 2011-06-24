#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "journal.h"

static inline int sfread(void *dst, size_t len, FILE *fp)
{
	return fread(dst, len, 1, fp) == len;
}

static inline int sfwrite(const void *src, size_t len, FILE *fp)
{
	return fwrite(src, len, 1, fp) == len;
}

int journal_create(const char *fn, uint16_t max_nodes)
{
	/* Create journal file. */
	FILE *fp = fopen(fn, "w");
	if (!fp) {
		return -1;
	}

	/* Disable buffering. */
	setvbuf(fp, (char *)0, _IONBF, 0);

	/*! \todo Unlink created file on error? */

	/* Create journal header. */
	if (!sfwrite(&max_nodes, sizeof(uint16_t), fp)) {
		fclose(fp);
		return -1;
	}

	/* Create free segment descriptor. */
	journal_node_t jn;
	jn.id = 0;
	jn.flags = JOURNAL_VALID;
	jn.pos = 0;
	jn.len = 0;
	if (!sfwrite(&jn, sizeof(journal_node_t), fp)) {
		fclose(fp);
		return -1;
	}

	/* Create nodes. */
	memset(&jn, 0, sizeof(journal_node_t));
	for(uint16_t i = 0; i < max_nodes; ++i) {
		if (!sfwrite(&jn, sizeof(journal_node_t), fp)) {
			fclose(fp);
			return -1;
		}
	}

	/* Journal file created. */
	return 0;
}

journal_t* journal_open(const char *fn)
{
	/*! \todo Memory mapping may be faster than stdio? */

	/*! \todo Lock file. */

	/* Open journal file for r/w. */
	FILE *fp = fopen(fn, "rw");
	if (!fp) {
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

	/* Read journal header. */
	j->n_next = 0;
	j->fp = fp;
	j->max_nodes = max_nodes;
	if (!sfread(&j->free, node_len, fp)) {
		fclose(fp);
		free(j);
		return 0;
	}

	/*! \todo Load node queue state. */

	/* Read journal descriptors table. */
	if (fread(&j->nodes, node_len, max_nodes, fp) != node_len * max_nodes) {
		fclose(fp);
		free(j);
		return 0;
	}

	/*! \todo Some file checksum, check node integrity. */
	return j;
}

int journal_fetch(journal_t *journal, int id, const journal_node_t** dst)
{
	/*! \todo Organize journal descriptors in btree? */
	/*! \todo Or store pointer to last fetch for sequential lookup? */
	for(uint16_t i = 0; i < journal->max_nodes; ++i) {
		if (journal->nodes[i].id == id) {
			*dst = journal->nodes + i;
			return 0;
		}
	}

	return -1;
}

int journal_read(journal_t *journal, int id, char *dst)
{
	const journal_node_t *n = 0;
	if(journal_fetch(journal, id, &n) != 0) {
		return -1;
	}

	/* Check valid flag. */
	if (n->flags == JOURNAL_NULL) {
		return -1;
	}

	/* Seek journal node. */
	fseek(journal->fp, n->pos, SEEK_SET);

	/* Read journal node content. */
	return fread(dst, n->len, 1, journal->fp);
}

int journal_write(journal_t *journal, int id, const char *src, size_t size)
{
	/*! \todo Free nodes if necessary. */
	if (journal->free.len < size) {
		return -1;
	}

	/*! \todo Find first unused node, need to treat nodes as queue. */
	uint16_t jn = (journal->n_next) % journal->max_nodes;
	long jn_fpos = JOURNAL_HSIZE + (jn + 1) * sizeof(journal_node_t);
	journal_node_t *n = journal->nodes + jn;

	/* Invalidate node and write back. */
	n->pos = journal->free.pos;
	n->len = size;
	n->flags = JOURNAL_NULL;
	fseek(journal->fp, jn_fpos, SEEK_SET);
	if (fwrite(n, sizeof(journal_node_t), 1, journal->fp) != sizeof(journal_node_t)) {
		return -1;
	}

	/* Write data to permanent storage. */
	fseek(journal->fp, n->pos, SEEK_SET);
	if (fwrite(src, size, 1, journal->fp) != size) {
		return -1;
	}

	/* Mark node as valid and write back. */
	n->flags = JOURNAL_VALID;
	fseek(journal->fp, jn_fpos, SEEK_SET);
	if (fwrite(n, sizeof(journal_node_t), 1, journal->fp) != sizeof(journal_node_t)) {
		return -1;
	}

	/* Node write successful. */
	++journal->n_next;
	journal->free.pos += size;
	journal->free.len -= size;

	/* Write back free segment state. */
	fseek(journal->fp, JOURNAL_HSIZE, SEEK_SET);
	if (fwrite(&journal->free, sizeof(journal_node_t), 1, journal->fp) != sizeof(journal_node_t)) {
		/*! \todo Node is marked valid and failed to shrink free space,
			  node will be overwritten on the next open - this may be
			  a problem, how to solve it properly? */
		return -1;
	}

	/*! \todo Delayed write-back? */

	return 0;

}

int journal_close(journal_t *journal)
{
	/*! \todo Store node queue state. */

	/* Close file. */
	fclose(journal->fp);

	/* Free allocated resources. */
	free(journal);
	return 0;
}
