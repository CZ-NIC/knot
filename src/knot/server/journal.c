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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <assert.h>

#include "common/crc.h"
#include "libknot/common.h"
#include "knot/other/debug.h"
#include "knot/server/journal.h"
#include "knot/server/serialization.h"
#include "libknot/rrtype/soa.h"

/*! \brief Infinite file size limit. */
#define FSLIMIT_INF (~((size_t)0))

/*! \brief Node classification macros. */
#define jnode_flags(j, i) ((j)->nodes[(i)].flags)

/*! \brief Next node. */
#define jnode_next(j, i) (((i) + 1) % (j)->max_nodes)

/*! \brief Previous node. */
#define jnode_prev(j, i) (((i) == 0) ? (j)->max_nodes - 1 : (i) - 1)

static inline int sfread(void *dst, size_t len, int fd)
{
	return read(fd, dst, len) == len;
}

static inline int sfwrite(const void *src, size_t len, int fd)
{
	return write(fd, src, len) == len;
}

static inline journal_node_t *journal_end(journal_t *journal) {
	return journal->nodes +  journal->qtail;
}

/*! \brief Equality compare function. */
static inline int journal_cmp_eq(uint64_t k1, uint64_t k2)
{
	if (k1 > k2) return 1;
	if (k1 < k2) return -1;
	return 0;
}

/*! \brief Return 'serial_from' part of the key. */
static inline uint32_t journal_key_from(uint64_t k)
{
	/*      64    32       0
	 * key = [TO   |   FROM]
	 * Need: Least significant 32 bits.
	 */
	return (uint32_t)(k & ((uint64_t)0x00000000ffffffff));
}

/*----------------------------------------------------------------------------*/

/*! \brief Compare function to match entries with starting serial. */
static inline int journal_key_from_cmp(uint64_t k, uint64_t from)
{
	/*      64    32       0
	 * key = [TO   |   FROM]
	 * Need: Least significant 32 bits.
	 */
	return ((uint64_t)journal_key_from(k)) - from;
}

/*! \brief Make key for journal from serials. */
static inline uint64_t ixfrdb_key_make(uint32_t from, uint32_t to)
{
	/*      64    32       0
	 * key = [TO   |   FROM]
	 */
	return (((uint64_t)to) << ((uint64_t)32)) | ((uint64_t)from);
}

/*! \brief Recover metadata from journal. */
static int journal_recover(journal_t *j)
{
	if (j == NULL) {
		return KNOT_EINVAL;
	}

	/* Attempt to recover queue. */
	int qstate[2] = { -1, -1 };
	unsigned c = 0, p = j->max_nodes - 1;
	while (1) {

		/* Fetch previous and current node. */
		journal_node_t *np = j->nodes + p;
		journal_node_t *nc = j->nodes + c;

		/* Check flags
		 * p c (0 = free, 1 = non-free)
		 * 0 0 - in free segment
		 * 0 1 - c-node is qhead
		 * 1 0 - c-node is qtail
		 * 1 1 - in full segment
		 */
		unsigned c_set = (nc->flags > JOURNAL_FREE);
		unsigned p_set = (np->flags > JOURNAL_FREE);
		if (!p_set && c_set && qstate[0] < 0) {
			qstate[0] = c; /* Recovered qhead. */
			dbg_journal_verb("journal: recovered qhead=%u\n",
			                 qstate[0]);
		}
		if (p_set && !c_set && qstate[1] < 0) {\
			qstate[1] = c; /* Recovered qtail. */
			dbg_journal_verb("journal: recovered qtail=%u\n",
			                 qstate[1]);
		}

		/* Both qstates set. */
		if (qstate[0] > -1 && qstate[1] > -1) {
			break;
		}

		/* Set prev and next. */
		p = c;
		c = (c + 1) % j->max_nodes;

		/* All nodes probed. */
		if (c == 0) {
			dbg_journal("journal: failed to recover node queue\n");
			break;
		}
	}

	/* Evaluate */
	if (qstate[0] < 0 || qstate[1] < 0) {
		return KNOT_ERANGE;
	}

	/* Write back. */
	int seek_ret = lseek(j->fd, JOURNAL_HSIZE - 2 * sizeof(uint16_t), SEEK_SET);
	if (seek_ret < 0 || !sfwrite(qstate, 2 * sizeof(uint16_t), j->fd)) {
		dbg_journal("journal: failed to write back queue state\n");
		return KNOT_ERROR;
	}

	/* Reset queue state. */
	j->qhead = qstate[0];
	j->qtail = qstate[1];
	dbg_journal("journal: node queue=<%u,%u> recovered\n",
	            qstate[0], qstate[1]);


	return KNOT_EOK;
}

/* Recalculate CRC. */
static int journal_update_crc(int fd)
{
	if (fcntl(fd, F_GETFL) < 0) {
		return KNOT_EINVAL;
	}

	char buf[4096];
	ssize_t rb = 0;
	crc_t crc = crc_init();
	if (lseek(fd, MAGIC_LENGTH + sizeof(crc_t), SEEK_SET) < 0) {
		return KNOT_ERROR;
	}
	while((rb = read(fd, buf, sizeof(buf))) > 0) {
		crc = crc_update(crc, (const unsigned char *)buf, rb);
	}
	if (lseek(fd, MAGIC_LENGTH, SEEK_SET) < 0) {
		return KNOT_ERROR;
	}
	if (!sfwrite(&crc, sizeof(crc_t), fd)) {
		dbg_journal("journal: couldn't write CRC to fd=%d\n", fd);
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}


/*! \brief Create new journal. */
static int journal_create_file(const char *fn, uint16_t max_nodes)
{
	if (fn == NULL) {
		return KNOT_EINVAL;
	}

	/* File lock. */
	struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET,
	                    .l_start = 0, .l_len = 0, .l_pid = getpid() };

	/* Create journal file. */
	int fd = open(fn, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
	if (fd < 0) {
		dbg_journal("journal: failed to create file '%s'\n", fn);
		return knot_map_errno(errno);
	}

	/* Lock. */
	if (fcntl(fd, F_SETLKW, &fl) == -1) {
		close(fd);
		remove(fn);
		return KNOT_ERROR;
	}

	/* Create journal header. */
	dbg_journal("journal: creating header\n");
	const char magic[MAGIC_LENGTH] = JOURNAL_MAGIC;
	if (!sfwrite(magic, MAGIC_LENGTH, fd)) {
		close(fd);
		remove(fn);
		return KNOT_ERROR;
	}
	crc_t crc = crc_init();
	if (!sfwrite(&crc, sizeof(crc_t), fd)) {
		close(fd);
		remove(fn);
		return KNOT_ERROR;
	}
	if (!sfwrite(&max_nodes, sizeof(uint16_t), fd)) {
		close(fd);
		remove(fn);
		return KNOT_ERROR;
	}

	/* Create node queue head + tail.
	 * qhead points to least recent node
	 * qtail points to next free node
	 * qhead == qtail means empty queue
	 */
	uint16_t zval = 0;
	if (!sfwrite(&zval, sizeof(uint16_t), fd)) {
		close(fd);
		remove(fn);
		return KNOT_ERROR;
	}

	if (!sfwrite(&zval, sizeof(uint16_t), fd)) {
		close(fd);
		remove(fn);
		return KNOT_ERROR;
	}

	dbg_journal_verb("journal: creating free segment descriptor\n");

	/* Create free segment descriptor. */
	journal_node_t jn;
	memset(&jn, 0, sizeof(journal_node_t));
	jn.id = 0;
	jn.flags = JOURNAL_VALID;
	jn.pos = JOURNAL_HSIZE + (max_nodes + 1) * sizeof(journal_node_t);
	jn.len = 0;
	if (!sfwrite(&jn, sizeof(journal_node_t), fd)) {
		close(fd);
		remove(fn);
		return KNOT_ERROR;
	}

	/* Create nodes. */
	dbg_journal("journal: creating node table, size=%u\n", max_nodes);
	memset(&jn, 0, sizeof(journal_node_t));
	for(uint16_t i = 0; i < max_nodes; ++i) {
		if (!sfwrite(&jn, sizeof(journal_node_t), fd)) {
			close(fd);
			if (remove(fn) < 0) {
				dbg_journal("journal: failed to remove journal file after error\n");
			}
			return KNOT_ERROR;
		}
	}

	/* Recalculate CRC. */
	if (journal_update_crc(fd) != KNOT_EOK) {
		close(fd);
		if(remove(fn) < 0) {
			dbg_journal("journal: failed to remove journal file after error\n");
		}
		return KNOT_ERROR;
	}

	/* Unlock and close. */
	close(fd);

	/* Journal file created. */
	dbg_journal("journal: file '%s' initialized\n", fn);
	return KNOT_EOK;
}

/*! \brief Open journal file for r/w (returns error if not exists). */
static int journal_open_file(journal_t *j)
{
	assert(j != NULL);

	int ret = KNOT_EOK;
	j->fd = open(j->path, O_RDWR);
	dbg_journal_verb("journal: open_file '%s'\n", j->path);
	if (j->fd < 0) {
		if (errno != ENOENT) {
			return knot_map_errno(errno);
		}

		/* Create new journal file and open if not exists. */
		ret = journal_create_file(j->path, JOURNAL_NCOUNT);
		if(ret == KNOT_EOK) {
			return journal_open_file(j);
		}
		return ret;
	}

	/* File lock. */
	struct flock lock = { .l_type = F_WRLCK, .l_whence = SEEK_SET,
	                      .l_start  = 0, .l_len = 0, .l_pid = 0 };
	/* Attempt to lock. */
	dbg_journal_verb("journal: locking journal %s\n", j->path);
	ret = fcntl(j->fd, F_SETLKW, &lock);
	if (ret < 0) {
		return knot_map_errno(errno);
	}

	/* Read magic bytes. */
	dbg_journal("journal: reading magic bytes\n");
	const char magic_req[MAGIC_LENGTH] = JOURNAL_MAGIC;
	char magic[MAGIC_LENGTH];
	if (!sfread(magic, MAGIC_LENGTH, j->fd)) {
		dbg_journal_verb("journal: cannot read magic bytes\n");
		goto open_file_error;
	}
	if (memcmp(magic, magic_req, MAGIC_LENGTH) != 0) {
		log_server_warning("Journal file '%s' version is too old, "
		                   "it will be purged.\n", j->path);
		close(j->fd);
		j->fd = -1;
		ret = journal_create_file(j->path, JOURNAL_NCOUNT);
		if(ret == KNOT_EOK) {
			return journal_open_file(j);
		}
		return ret;
	}
	crc_t crc = 0;
	if (!sfread(&crc, sizeof(crc_t), j->fd)) {
		dbg_journal_verb("journal: cannot read CRC\n");
		goto open_file_error;
	}

	/* Recalculate CRC. */
	char buf[4096];
	ssize_t rb = 0;
	crc_t crc_calc = crc_init();
	while((rb = read(j->fd, buf, sizeof(buf))) > 0) {
		crc_calc = crc_update(crc_calc, (const unsigned char *)buf, rb);
	}

	/* Compare */
	if (crc == crc_calc) {
		/* Rewind. */
		if (lseek(j->fd, MAGIC_LENGTH + sizeof(crc_t), SEEK_SET) < 0) {
			goto open_file_error;
		}
	} else {
		log_server_warning("Journal file '%s' CRC error, "
		                   "it will be purged.\n", j->path);
		close(j->fd);
		j->fd = -1;
		ret = journal_create_file(j->path, JOURNAL_NCOUNT);
		if(ret == KNOT_EOK) {
			return journal_open_file(j);
		}
		return ret;
	}

	/* Get journal file size. */
	struct stat st;
	if (stat(j->path, &st) < 0) {
		dbg_journal_verb("journal: cannot get journal fsize\n");
		goto open_file_error;
	}

	/* Set file size. */
	j->fsize = st.st_size;

	/* Read maximum number of entries. */
	if (!sfread(&j->max_nodes, sizeof(uint16_t), j->fd)) {
		dbg_journal_verb("journal: cannot read max_nodes\n");
		goto open_file_error;
	}

	/* Check max_nodes, but this is riddiculous. */
	if (j->max_nodes == 0) {
		dbg_journal_verb("journal: invalid max_nodes\n");
		goto open_file_error;
	}

	/* Allocate nodes. */
	const size_t node_len = sizeof(journal_node_t);
	j->nodes = malloc(j->max_nodes * node_len);
	if (j->nodes == NULL) {
		dbg_journal_verb("journal: can't allocate nodes\n");
		goto open_file_error;
	} else {
		memset(j->nodes, 0, j->max_nodes * node_len);
	}

	/* Load node queue state. */
	j->qhead = j->qtail = 0;
	if (!sfread(&j->qhead, sizeof(uint16_t), j->fd)) {
		dbg_journal_verb("journal: cannot read qhead\n");
		goto open_file_error;
	}

	/* Load queue tail. */
	if (!sfread(&j->qtail, sizeof(uint16_t), j->fd)) {
		dbg_journal_verb("journal: cannot read qtail\n");
		goto open_file_error;
	}

	/* Check head + tail */
	if (j->qtail >= j->max_nodes || j->qhead >= j->max_nodes) {
		dbg_journal_verb("journal: queue pointers corrupted\n");
		goto open_file_error;
	}

	/* Load empty segment descriptor. */
	if (!sfread(&j->free, node_len, j->fd)) {
		dbg_journal_verb("journal: cannot read free segment ptr\n");
		goto open_file_error;
	}

	/* Read journal descriptors table. */
	if (!sfread(j->nodes, j->max_nodes * node_len, j->fd)) {
		dbg_journal_verb("journal: cannot read node table\n");
		goto open_file_error;
	}

	dbg_journal("journal: opened journal size=%u, queue=<%u, %u>, fd=%d\n",
	            j->max_nodes, j->qhead, j->qtail, j->fd);

	/* Check node queue. */
	unsigned qtail_free = (jnode_flags(j, j->qtail) <= JOURNAL_FREE);
	unsigned qhead_free = j->max_nodes - 1; /* Left of qhead must be free.*/
	if (j->qhead > 0) {
		qhead_free = (j->qhead - 1);
	}
	qhead_free = (jnode_flags(j, qhead_free) <= JOURNAL_FREE);
	if ((j->qhead != j->qtail) && (!qtail_free || !qhead_free)) {
		log_server_warning("Recovering journal '%s' metadata "
		                   "after crash.\n",
		                   j->path);
		ret = journal_recover(j);
		if (ret != KNOT_EOK) {
			log_server_error("Journal file '%s' is unrecoverable, "
			                 "metadata corrupted - %s\n",
			                 j->path, knot_strerror(ret));
			goto open_file_error;
		}
	}

	/* Save file lock and return. */
	return KNOT_EOK;

	/* Unlock and close file and return error. */
open_file_error:
	free(j->nodes);
	j->nodes = NULL;
	close(j->fd);
	j->fd = -1;
	return KNOT_ERROR;
}

/*! \brief Close journal file. */
static int journal_close_file(journal_t *journal)
{
	/* Check journal. */
	if (journal == NULL) {
		return KNOT_EINVAL;
	}

	/* Recalculate CRC. */
	int ret = journal_update_crc(journal->fd);

	/* Close file. */
	if (journal->fd > 0) {
		close(journal->fd);
		journal->fd = -1;
	}

	/* Free nodes. */
	free(journal->nodes);
	journal->nodes = NULL;

	return ret;
}

/*!  \brief Sync node state to permanent storage. */
static int journal_update(journal_t *journal, journal_node_t *n)
{
	if (journal == NULL || n == NULL) {
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

	dbg_journal("journal: syncing journal node=%zu id=%llu flags=0x%x\n",
		      i, (unsigned long long)n->id, n->flags);

	/* Write back. */
	int seek_ret = lseek(journal->fd, jn_fpos, SEEK_SET);
	if (seek_ret < 0 || !sfwrite(n, node_len, journal->fd)) {
		dbg_journal("journal: failed to writeback node=%llu to %ld\n",
		            (unsigned long long)n->id, jn_fpos);
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int journal_write_in(journal_t *j, journal_node_t **rn, uint64_t id, size_t len)
{
	const size_t node_len = sizeof(journal_node_t);
	*rn = NULL;

	/* Find next free node. */
	uint16_t jnext = (j->qtail + 1) % j->max_nodes;

	dbg_journal("journal: will write id=%llu, node=%u, size=%zu, fsize=%zu\n",
	            (unsigned long long)id, j->qtail, len, j->fsize);

	/* Calculate remaining bytes to reach file size limit. */
	size_t fs_remaining = j->fslimit - j->fsize;
	int seek_ret = 0;

	/* Increase free segment if on the end of file. */
	dbg_journal("journal: free.pos = %u free.len = %u\n",
	            j->free.pos, j->free.len);
	journal_node_t *n = j->nodes + j->qtail;
	if (j->free.pos + j->free.len == j->fsize) {

		dbg_journal_verb("journal: * is last node\n");

		/* Grow journal file until the size limit. */
		if(j->free.len < len && len <= fs_remaining) {
			size_t diff = len - j->free.len;
			dbg_journal("journal: * growing by +%zu, pos=%u, "
			            "new fsize=%zu\n",
			            diff, j->free.pos,
			            j->fsize + diff);
			j->fsize += diff; /* Appending increases file size. */
			j->free.len += diff;

		}

		/*  Rewind if resize is needed, but the limit is reached. */
		if(j->free.len < len && len > fs_remaining) {
			journal_node_t *head = j->nodes + j->qhead;
			j->fsize = j->free.pos;
			j->free.pos = head->pos;
			j->free.len = 0;
			dbg_journal_verb("journal: * fslimit reached, "
			                 "rewinding to %u\n",
			                 head->pos);
			dbg_journal_verb("journal: * file size trimmed to %zu\n",
			                 j->fsize);
		}
	}

	/* Count node visits to prevent looping. */
	uint16_t visit_count = 0;

	/* Evict occupied nodes if necessary. */
	while (j->free.len < len || j->nodes[jnext].flags > JOURNAL_FREE) {

		/* Evict least recent node if not empty. */
		journal_node_t *head = j->nodes + j->qhead;

		/* Check if it has been synced to disk. */
		if ((head->flags & JOURNAL_DIRTY) && (head->flags & JOURNAL_VALID)) {
			return KNOT_EBUSY;
		}

		/* Write back evicted node. */
		head->flags = JOURNAL_FREE;
		seek_ret = lseek(j->fd, JOURNAL_HSIZE + (j->qhead + 1) * node_len, SEEK_SET);
		if (seek_ret < 0 || !sfwrite(head, node_len, j->fd)) {
			return KNOT_ERROR;
		}

		dbg_journal("journal: * evicted node=%u, growing by +%u\n",
			      j->qhead, head->len);

		/* Write back query state. */
		j->qhead = (j->qhead + 1) % j->max_nodes;
		uint16_t qstate[2] = {j->qhead, j->qtail};
		seek_ret = lseek(j->fd, JOURNAL_HSIZE - 2 * sizeof(uint16_t), SEEK_SET);
		if (seek_ret < 0 || !sfwrite(qstate, 2 * sizeof(uint16_t), j->fd)) {
			return KNOT_ERROR;
		}

		/* Increase free segment. */
		j->free.len += head->len;

		/* Update node visit count. */
		visit_count += 1;
		if (visit_count >= j->max_nodes) {
			return KNOT_ESPACE;
		}
	}

	/* Invalidate node and write back. */
	n->id = id;
	n->pos = j->free.pos;
	n->len = len;
	n->flags = JOURNAL_FREE;
	n->next = jnext;
	journal_update(j, n);
	*rn = n;
	return KNOT_EOK;
}

int journal_write_out(journal_t *journal, journal_node_t *n)
{
	/* Mark node as valid and write back. */
	uint16_t jnext = n->next;
	size_t size = n->len;
	const size_t node_len = sizeof(journal_node_t);
	n->flags = JOURNAL_VALID | journal->bflags;
	n->next = 0;
	journal_update(journal, n);

	/* Handle free segment on node rotation. */
	if (journal->qtail > jnext && journal->fslimit == FSLIMIT_INF) {
		/* Trim free space. */
		journal->fsize -= journal->free.len;
		dbg_journal_verb("journal: * trimmed filesize to %zu\n",
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

	dbg_journal("journal: finishing node=%u id=%llu flags=0x%x, "
	            "data=<%u, %u> free=<%u, %u>\n",
	            journal->qtail, (unsigned long long)n->id,
	            n->flags, n->pos, n->pos + n->len,
	            journal->free.pos,
	            journal->free.pos + journal->free.len);

	/* Write back free segment state. */
	int seek_ret = lseek(journal->fd, JOURNAL_HSIZE, SEEK_SET);
	if (seek_ret < 0 || !sfwrite(&journal->free, node_len, journal->fd)) {
		/* Node is marked valid and failed to shrink free space,
		 * node will be overwritten on the next write. Return error.
		 */
		dbg_journal("journal: failed to write back "
		            "free segment descriptor\n");
		return KNOT_ERROR;
	}

	/* Node write successful. */
	journal->qtail = jnext;

	/* Write back queue state, not essential as it may be recovered.
	 * qhead - lowest valid node identifier (least recent)
	 * qtail - highest valid node identifier (most recently used)
	 */
	uint16_t qstate[2] = {journal->qhead, journal->qtail};
	seek_ret = lseek(journal->fd, JOURNAL_HSIZE - 2 * sizeof(uint16_t), SEEK_SET);
	if (seek_ret < 0 || !sfwrite(qstate, 2 * sizeof(uint16_t), journal->fd)) {
		dbg_journal("journal: failed to write back queue state\n");
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}


journal_t* journal_open(const char *path, size_t fslimit)
{
	if (path == NULL) {
		return NULL;
	}

	journal_t *j = malloc(sizeof(journal_t));
	if (j == NULL) {
		return NULL;
	}

	memset(j, 0, sizeof(journal_t));
	j->bflags = JOURNAL_DIRTY;
	j->fd = -1;

	/* Set file size. */
	if (fslimit == 0) {
		j->fslimit = FSLIMIT_INF;
	} else {
		j->fslimit = fslimit;
	}

	/* Copy path. */
	j->path = strdup(path);
	if (j->path == NULL) {
		free(j);
		return NULL;
	}

	/* Open journal file. */
	int ret = journal_open_file(j);
	if (ret != KNOT_EOK) {
		journal_close(j);
		return NULL;
	}

	return j;
}

/*!
 * \brief Entry identifier compare function.
 *
 * \retval -n if k1 < k2
 * \retval +n if k1 > k2
 * \retval  0 if k1 == k2
 */
typedef int (*journal_cmp_t)(uint64_t k1, uint64_t k2);

static int journal_fetch(journal_t *journal, uint64_t id,
		  journal_cmp_t cf, journal_node_t** dst)
{
	if (journal == NULL || dst == NULL) {
		return KNOT_EINVAL;
	}

	/*! \todo Organize journal descriptors in btree? */
	size_t i = jnode_prev(journal, journal->qtail);
	size_t endp = jnode_prev(journal, journal->qhead);
	for(; i != endp; i = jnode_prev(journal, i)) {
		journal_node_t *n = journal->nodes + i;
		if (cf(n->id, id) == 0) {
			*dst = journal->nodes + i;
			return KNOT_EOK;
		}
	}

	return KNOT_ENOENT;
}

static int journal_read_node(journal_t *journal, journal_node_t *n, char *dst)
{
	dbg_journal("journal: reading node with id=%"PRIu64", data=<%u, %u>, flags=0x%hx\n",
	            n->id, n->pos, n->pos + n->len, n->flags);

	/* Check valid flag. */
	if (!(n->flags & JOURNAL_VALID)) {
		dbg_journal("journal: node with id=%llu is invalid "
		            "(flags=0x%hx)\n", (unsigned long long)n->id, n->flags);
		return KNOT_EINVAL;
	}

	/* Seek journal node. */
	int seek_ret = lseek(journal->fd, n->pos, SEEK_SET);

	/* Read journal node content. */
	if (seek_ret < 0 || !sfread(dst, n->len, journal->fd)) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int journal_map(journal_t *journal, uint64_t id, char **dst, size_t size, bool rdonly)
{
	if (journal == NULL || dst == NULL) {
		return KNOT_EINVAL;
	}

	/* Check if entry exists. */
	journal_node_t *n = NULL;
	int ret = journal_fetch(journal, id, journal_cmp_eq, &n);
	if (ret != KNOT_EOK) {
		/* Return error if read only. */
		if (rdonly) {
			return ret;
		}

		/* Prepare journal write. */
		ret = journal_write_in(journal, &n, id, size);
		if (ret != KNOT_EOK) {
			return ret;
		}

		/* Reserve data in permanent storage. */
		/*! \todo This is only needed when inflating journal file. */
		if (lseek(journal->fd, n->pos, SEEK_SET) < 0) {
			return KNOT_ERROR;
		}
		char nbuf[4096] = {0};
		size_t wb = sizeof(nbuf);
		while (size > 0) {
			if (size < sizeof(nbuf)) {
				wb = size;
			}
			if (!sfwrite(nbuf, wb, journal->fd)) {
				return KNOT_ERROR;
			}
			size -= wb;
		}
	} else {
		/* Entry resizing is not really supported now. */
		if (n->len < size) {
			return KNOT_ESPACE;
		}
	}

	/* Align offset to page size (required). */
	const size_t ps = sysconf(_SC_PAGESIZE);
	off_t ps_delta = (n->pos % ps);
	off_t off = n->pos - ps_delta;

	/* Map file region. */
	*dst = mmap(NULL, n->len + ps_delta, PROT_READ | PROT_WRITE, MAP_SHARED,
	            journal->fd, off);
	if (*dst == ((void*)-1)) {
		dbg_journal("journal: couldn't mmap() fd=%d <%u,%u> %d\n",
		            journal->fd, n->pos, n->pos+n->len, errno);
		return KNOT_ERROR;
	}

	/* Advise usage of memory. */
#ifdef HAVE_MADVISE
	madvise(*dst, n->len + ps_delta, MADV_SEQUENTIAL);
#endif
	/* Correct dst pointer to alignment. */
	*dst += ps_delta;

	return KNOT_EOK;
}

int journal_unmap(journal_t *journal, uint64_t id, void *ptr, int finalize)
{
	if (journal == NULL || ptr == NULL) {
		return KNOT_EINVAL;
	}

	/* Mapped node is on tail. */
	/* @todo: This is hack to allow read-only correct unmap. */
	int ret = KNOT_EOK;
	journal_node_t *n = journal->nodes + journal->qtail;
	if (!finalize) {
		ret = journal_fetch(journal, id, journal_cmp_eq, &n);
		if (ret != KNOT_EOK) {
			return KNOT_ENOENT;
		}
	}
	if(n->id != id) {
		dbg_journal("journal: failed to find mmap node with id=%llu\n",
		            (unsigned long long)id);
		return KNOT_ENOENT;
	}

	/* Realign memory. */
	const size_t ps = sysconf(_SC_PAGESIZE);
	off_t ps_delta = (n->pos % ps);
	ptr = ((char*)ptr - ps_delta);

	/* Unmap memory. */
	if (munmap(ptr, n->len + ps_delta) != 0) {
		dbg_journal("journal: couldn't munmap() fd=%d <%u,%u> %d\n",
		            journal->fd, n->pos, n->pos+n->len, errno);
		return KNOT_ERROR;
	}

	/* Finalize. */
	if (finalize) {
		ret = journal_write_out(journal, n);
	}
	return ret;
}

int journal_close(journal_t *journal)
{
	/* Check journal. */
	if (journal == NULL) {
		return KNOT_EINVAL;
	}

	/* Close file. */
	journal_close_file(journal);

	/* Free allocated resources. */
	free(journal->path);
	free(journal);

	return KNOT_EOK;
}

bool journal_exists(const char *path)
{
	if (path == NULL) {
		return false;
	}

	/* Check journal file existence. */
	struct stat st;
	return stat(path, &st) == 0;
}

/*! \brief No doc here. Moved from zones.h (@mvavrusa) */
static int changesets_unpack(changeset_t *chs)
{

	knot_rrset_t *rrset = NULL;

	/* Read changeset flags. */
	if (chs->data == NULL) {
		return KNOT_EMALF;
	}
	size_t remaining = chs->size;

	/* Read initial changeset RRSet - SOA. */
	uint8_t *stream = chs->data + (chs->size - remaining);
	int ret = rrset_deserialize(stream, &remaining, &rrset);
	if (ret != KNOT_EOK) {
		return KNOT_EMALF;
	}

	assert(rrset->type == KNOT_RRTYPE_SOA);
	chs->soa_from = rrset;

	/* Read remaining RRSets */
	bool in_remove_section = true;
	while (remaining > 0) {

		/* Parse next RRSet. */
		rrset = 0;
		stream = chs->data + (chs->size - remaining);
		ret = rrset_deserialize(stream, &remaining, &rrset);
		if (ret != KNOT_EOK) {
			return KNOT_EMALF;
		}

		/* Check for next SOA. */
		if (rrset->type == KNOT_RRTYPE_SOA) {
			/* Move to ADD section if in REMOVE. */
			if (in_remove_section) {
				chs->soa_to = rrset;
				in_remove_section = false;
			} else {
				/* Final SOA. */
				knot_rrset_free(&rrset, NULL);
				break;
			}
		} else {
			/* Remove RRSets. */
			if (in_remove_section) {
				ret = changeset_add_rrset(chs, rrset,
				                          CHANGESET_REMOVE);
			} else {
				/* Add RRSets. */
				ret = changeset_add_rrset(chs, rrset,
				                          CHANGESET_ADD);
			}
		}
	}

	return ret;
}

static int rrset_write_to_mem(const knot_rrset_t *rr, char **entry,
                              size_t *remaining) {
	size_t written = 0;
	int ret = rrset_serialize(rr, *((uint8_t **)entry),
	                          &written);
	if (ret == KNOT_EOK) {
		assert(written <= *remaining);
		*remaining -= written;
		*entry += written;
	}

	return ret;
}

static int serialize_and_store_chgset(const changeset_t *chs,
                                      char *entry, size_t max_size)
{
	/* Serialize SOA 'from'. */
	int ret = rrset_write_to_mem(chs->soa_from, &entry, &max_size);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Serialize RRSets from the 'remove' section. */
	knot_rr_ln_t *rr_node = NULL;
	WALK_LIST(rr_node, chs->remove) {
		knot_rrset_t *rrset = rr_node->rr;
		ret = rrset_write_to_mem(rrset, &entry, &max_size);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* Serialize SOA 'to'. */
	ret = rrset_write_to_mem(chs->soa_to, &entry, &max_size);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Serialize RRSets from the 'add' section. */
	WALK_LIST(rr_node, chs->add) {
		knot_rrset_t *rrset = rr_node->rr;
		ret = rrset_write_to_mem(rrset, &entry, &max_size);
		if (ret != KNOT_EOK) {
			return ret;
		}

	}

	return KNOT_EOK;
}

static int changeset_pack(const changeset_t *chs, journal_t *j)
{
	assert(chs != NULL);
	assert(j != NULL);

	uint64_t k = ixfrdb_key_make(knot_soa_serial(&chs->soa_from->rrs),
	                             knot_soa_serial(&chs->soa_to->rrs));

	/* Count the size of the entire changeset in serialized form. */
	size_t entry_size = 0;

	int ret = changeset_binary_size(chs, &entry_size);
	assert(ret == KNOT_EOK);

	/* Reserve space for the journal entry. */
	char *journal_entry = NULL;
	ret = journal_map(j, k, &journal_entry, entry_size, false);
	if (ret != KNOT_EOK) {
		return ret;
	}

	assert(journal_entry != NULL);

	/* Serialize changeset, saving it bit by bit. */
	ret = serialize_and_store_chgset(chs, journal_entry, entry_size);
	/* Unmap the journal entry.
	 * If successfuly written changeset to journal, validate the entry. */
	int unmap_ret = journal_unmap(j, k, journal_entry, ret == KNOT_EOK);
	if (ret == KNOT_EOK && unmap_ret != KNOT_EOK) {
		ret = unmap_ret; /* Propagate the result. */
	}

	return ret;
}

/*! \brief Helper for iterating journal (this is temporary until #80) */
typedef int (*journal_apply_t)(journal_t *, journal_node_t *, void *);
static int journal_walk(const char *fn, uint32_t from, uint32_t to,
                        journal_apply_t cb, void *data)
{
	/* Open journal for reading. */
	journal_t *journal = journal_open(fn, FSLIMIT_INF);
	if (journal == NULL) {
		return KNOT_ENOMEM;
	}

	/* Read entries from starting serial until finished. */
	uint32_t found_to = from;
	journal_node_t *n = 0;
	int ret = journal_fetch(journal, from, journal_key_from_cmp, &n);
	if (ret != KNOT_EOK) {
		goto finish;
	}

	while (n != 0 && n != journal_end(journal)) {
		/* Check for history end. */
		if (to == found_to) {
			break;
		}

		/* Skip wrong changesets. */
		if (!(n->flags & JOURNAL_VALID)) {
			++n;
			continue;
		}

		/* Callback. */
		ret = cb(journal, n, data);
		if (ret != KNOT_EOK) {
			break;
		}

		++n;
	}

finish:
	/* Close journal. */
	journal_close(journal);
	return ret;
}

static int load_changeset(journal_t *journal, journal_node_t *n, void *data)
{
	changesets_t *chsets = (changesets_t *)data;
	changeset_t *chs = changesets_create_changeset(chsets);
	if (chs == NULL) {
		return KNOT_ERROR;
	}

	/* Initialize changeset. */
	chs->data = malloc(n->len);
	if (!chs->data) {
		return KNOT_ENOMEM;
	}

	/* Read journal entry. */
	int ret = journal_read_node(journal, n, (char*)chs->data);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Update changeset binary size. */
	chs->size = n->len;
	return KNOT_EOK;
}

int journal_load_changesets(const char *path, changesets_t *dst,
                            uint32_t from, uint32_t to)
{
	int ret = journal_walk(path, from, to, &load_changeset, dst);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Unpack binary data. */
	assert(dst != NULL);
	/*
	 * Parses changesets from the binary format stored in chgsets->data
	 * into the changeset_t structures.
	 */
	changeset_t* chs = NULL;
	WALK_LIST(chs, dst->sets) {
		ret = changesets_unpack(chs);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* Check for complete history. */
	changeset_t *last = changesets_get_last(dst);
	if (to != knot_soa_serial(&last->soa_to->rrs)) {
		return KNOT_ERANGE;
	}

	return KNOT_EOK;
}

int journal_store_changesets(changesets_t *src, const char *path, size_t size_limit)
{
	if (src == NULL || path == NULL) {
		return KNOT_EINVAL;
	}

	/* Open journal for reading. */
	int ret = KNOT_EOK;
	journal_t *journal = journal_open(path, size_limit);
	if (journal == NULL) {
		return KNOT_ENOMEM;
	}

	/* Begin writing to journal. */
	changeset_t *chs = NULL;
	WALK_LIST(chs, src->sets) {
		/* Make key from serials. */
		ret = changeset_pack(chs, journal);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	/*! @note If the journal is full, this function returns KNOT_EBUSY. */

	/* Written changesets to journal. */
	return journal_close(journal);
}

static void mark_synced(journal_t *journal, journal_node_t *node)
{
	/* Check for dirty bit (not synced to permanent storage). */
	if (node->flags & JOURNAL_DIRTY) {
		/* Remove dirty bit. */
		node->flags = node->flags & ~JOURNAL_DIRTY;
		journal_update(journal, node);
	}
}

int journal_mark_synced(const char *path)
{
	if (!journal_exists(path)) {
		return KNOT_EOK;
	}

	journal_t *journal = journal_open(path, FSLIMIT_INF);
	if (journal == NULL) {
		return KNOT_ENOMEM;
	}

	size_t i = journal->qhead;
	for(; i != journal->qtail; i = (i + 1) % journal->max_nodes) {
		mark_synced(journal, journal->nodes + i);
	}

	journal_close(journal);

	return KNOT_EOK;
}
