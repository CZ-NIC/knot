#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "knot/other/error.h"
#include "knot/other/debug.h"
#include "journal.h"

/*! \brief Infinite file size limit. */
#define FSLIMIT_INF (~((size_t)0))

static inline int sfread(void *dst, size_t len, FILE *fp)
{
	return fread(dst, len, 1, fp) == 1;
}

static inline int sfwrite(const void *src, size_t len, FILE *fp)
{
	return fwrite(src, len, 1, fp) == 1;
}

/*! \brief Equality compare function. */
static inline int journal_cmp_eq(uint64_t k1, uint64_t k2)
{
	return k1 - k2;
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
		remove(fn);
		return KNOT_ERROR;
	}

	/* Create empty queue head + tail. */
	uint16_t zval = 0;
	if (!sfwrite(&zval, sizeof(uint16_t), fp)) {
		fclose(fp);
		remove(fn);
		return KNOT_ERROR;
	}
	if (!sfwrite(&zval, sizeof(uint16_t), fp)) {
		fclose(fp);
		remove(fn);
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

journal_t* journal_open(const char *fn, int fslimit, uint16_t bflags)
{
	/*! \todo Memory mapping may be faster than stdio? */

	/*! \todo Lock file. */

	/* Check file. */
	struct stat st;
	if (stat(fn, &st) < 0) {
		return 0;
	}

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
	j->bflags = bflags;

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

	/* Set file size. */
	j->fsize = st.st_size;
	if (fslimit < 0) {
		j->fslimit = FSLIMIT_INF;
	} else {
		j->fslimit = (size_t)fslimit;
	}

	/*! \todo Some file checksum, check node integrity. */
	debug_journal("journal: opened journal size=%u, queue=<%u, %u>, fd=%d\n",
		      max_nodes, j->qhead, j->qtail, fileno(j->fp));

	return j;
}

int journal_fetch(journal_t *journal, uint64_t id,
		  journal_cmp_t cf, journal_node_t** dst)
{
	/* Check compare function. */
	if (!cf) {
		cf = journal_cmp_eq;
	}

	/*! \todo Organize journal descriptors in btree? */
	/*! \todo Or store pointer to last fetch for sequential lookup? */
	for(uint16_t i = 0; i != journal->max_nodes; ++i) {

		if (cf(journal->nodes[i].id, id) == 0) {
			*dst = journal->nodes + i;
			return KNOT_EOK;
		}
	}

	return KNOT_ENOENT;
}

int journal_read(journal_t *journal, uint64_t id, journal_cmp_t cf, char *dst)
{
	journal_node_t *n = 0;
	if(journal_fetch(journal, id, cf, &n) != 0) {
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

int journal_write(journal_t *journal, uint64_t id, const char *src, size_t size)
{
	/*! \todo Find key with already existing identifier? */

	const size_t node_len = sizeof(journal_node_t);

	/* Find next free node. */
	uint16_t jnext = (journal->qtail + 1) % journal->max_nodes;

	debug_journal("journal: will write id=%zu, node=%u, size=%zu, fsize=%zu\n",
		      id, journal->qtail, size, journal->fsize);

	/* Calculate remaining bytes to reach file size limit. */
	size_t fs_remaining = journal->fslimit - journal->fsize;

	/* Increase free segment if on the end of file. */
	journal_node_t *n = journal->nodes + journal->qtail;
	if (journal->free.pos + journal->free.len == journal->fsize) {

		debug_journal("journal: * is last node\n");

		/* Grow journal file until the size limit. */
		if(journal->free.len < size && size <= fs_remaining) {
			size_t diff = size - journal->free.len;
			debug_journal("journal: * growing by +%zu, pos=%u, new fsize=%zu\n",
				      diff, journal->free.pos,
				      journal->fsize + diff);
			journal->fsize += diff; /* Appending increases file size. */
			journal->free.len += diff;

		}

		/*  Rewind if resize is needed, but the limit is reached. */
		if(journal->free.len < size && size > fs_remaining) {
			journal_node_t *head = journal->nodes + journal->qhead;
			journal->fsize = journal->free.pos;
			journal->free.pos = head->pos;
			journal->free.len = 0;
			debug_journal("journal: * fslimit reached, rewinding to %u\n",
				      head->pos);
			debug_journal("journal: * file size trimmed to %zu\n",
				      journal->fsize);
		}
	}

	/* Evict occupied nodes if necessary. */
	while (journal->free.len < size) {

		/* Evict least recent node if not empty. */
		journal_node_t *head = journal->nodes + journal->qhead;

		/* Check if it has been synced to disk. */
		if (head->flags & JOURNAL_DIRTY) {
			return KNOT_EAGAIN;
		}

		/* Write back evicted node. */
		head->flags = JOURNAL_FREE;
		fseek(journal->fp, JOURNAL_HSIZE + (journal->qhead + 1) * node_len, SEEK_SET);
		if (!sfwrite(head, node_len, journal->fp)) {
			return KNOT_ERROR;
		}

		debug_journal("journal: * evicted node=%u, growing by +%u\n",
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

	/* Invalidate node and write back. */
	n->id = id;
	n->pos = journal->free.pos;
	n->len = size;
	n->flags = JOURNAL_FREE;
	journal_update(journal, n);

	/* Write data to permanent storage. */
	fseek(journal->fp, n->pos, SEEK_SET);
	if (!sfwrite(src, size, journal->fp)) {
		return KNOT_ERROR;
	}

	/* Mark node as valid and write back. */
	n->flags = JOURNAL_VALID | journal->bflags;
	journal_update(journal, n);

	/* Handle free segment on node rotation. */
	if (journal->qtail > jnext && journal->fslimit == FSLIMIT_INF) {
		/* Trim free space. */
		journal->fsize -= journal->free.len;
		debug_journal("journal: * trimmed filesize to %zu\n",
			      journal->fsize);

		/* Rewind free segment. */
		journal_node_t *n = journal->nodes + jnext;
		journal->free.pos = n->pos;
		journal->free.len = 0;

	} else {
		/* Mark used space. */
		journal->free.pos += size;
		journal->free.len -= size;
	}
	debug_journal("journal: finished node=%u, data=<%u, %u> free=<%u, %u>\n",
		      journal->qtail, n->pos, n->pos + n->len,
		      journal->free.pos, journal->free.pos + journal->free.len);

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

int journal_walk(journal_t *journal, journal_apply_t apply)
{
	int ret = KNOT_EOK;
	size_t i = journal->qhead;
	for(; i != journal->qtail; i = (i + 1) % journal->max_nodes) {
		/* Apply function. */
		ret = apply(journal, journal->nodes + i);
	}

	return KNOT_EOK;
}

int journal_update(journal_t *journal, journal_node_t *n)
{
	if (!journal || !n) {
		return KNOT_EINVAL;
	}

	/* Calculate node offset. */
	const size_t node_len = sizeof(journal_node_t);
	size_t i = n - journal->nodes;
	if (i > journal->max_nodes) {
		return KNOT_EINVAL;
	}

	/* Calculate node position in permanent storage. */
	long jn_fpos = JOURNAL_HSIZE + (i + 1) * node_len;

	debug_journal("journal: syncing journal node=%zu at %ld\n",
		      i, jn_fpos);

	/* Write back. */
	fseek(journal->fp, jn_fpos, SEEK_SET);
	if (!sfwrite(n, node_len, journal->fp)) {
		debug_journal("journal: failed to writeback node=%d to %ld\n",
			      n->id, jn_fpos);
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int journal_close(journal_t *journal)
{
	/* Check journal. */
	if (!journal) {
		return KNOT_EINVAL;
	}

	/* Close file. */
	fclose(journal->fp);

	debug_journal("journal: closed journal %p\n", journal);

	/* Free allocated resources. */
	free(journal);

	return KNOT_EOK;
}
