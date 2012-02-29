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
#include <sys/stat.h>
#include <fcntl.h>

#include "knot/other/error.h"
#include "knot/other/debug.h"
#include "journal.h"

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

/*! \brief Equality compare function. */
static inline int journal_cmp_eq(uint64_t k1, uint64_t k2)
{
	if (k1 == k2) {
		return 0;
	}
	
	if (k1 < k2) {
		return -1;
	}
	
	return 1;
}

/*! \brief Recover metadata from journal. */
static int journal_recover(journal_t *j)
{
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
		return KNOTD_ERANGE;
	}
	
	/* Write back. */
	lseek(j->fd, JOURNAL_HSIZE - 2 * sizeof(uint16_t), SEEK_SET);
	if (!sfwrite(qstate, 2 * sizeof(uint16_t), j->fd)) {
		dbg_journal("journal: failed to write back queue state\n");
		return KNOTD_ERROR;
	}
	
	/* Reset queue state. */
	j->qhead = qstate[0];
	j->qtail = qstate[1];
	dbg_journal("journal: node queue=<%u,%u> recovered\n",
	            qstate[0], qstate[1]);
	
	
	return KNOTD_EOK;
}

int journal_create(const char *fn, uint16_t max_nodes)
{
	if (fn == NULL) {
		return KNOTD_EINVAL;
	}
	
	/* File lock. */
	struct flock fl;
	memset(&fl, 0, sizeof(struct flock));
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_pid = getpid();
	
	/* Create journal file. */
	int fd = open(fn, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
	if (fd < 0) {
		dbg_journal("journal: failed to create file '%s'\n", fn);
		return KNOTD_EINVAL;
	}
	
	/* Lock. */
	fcntl(fd, F_SETLKW, &fl);
	fl.l_type  = F_UNLCK;

	/* Create journal header. */
	dbg_journal("journal: creating header\n");
	if (!sfwrite(&max_nodes, sizeof(uint16_t), fd)) {
		fcntl(fd, F_SETLK, &fl);
		close(fd);
		remove(fn);
		return KNOTD_ERROR;
	}

	/* Create node queue head + tail.
	 * qhead points to least recent node
	 * qtail points to next free node
	 * qhead == qtail means empty queue
	 */
	uint16_t zval = 0;
	if (!sfwrite(&zval, sizeof(uint16_t), fd)) {
		fcntl(fd, F_SETLK, &fl);
		close(fd);
		remove(fn);
		return KNOTD_ERROR;
	}
	
	if (!sfwrite(&zval, sizeof(uint16_t), fd)) {
		fcntl(fd, F_SETLK, &fl);
		close(fd);
		remove(fn);
		return KNOTD_ERROR;
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
		fcntl(fd, F_SETLK, &fl);
		close(fd);
		remove(fn);
		return KNOTD_ERROR;
	}

	/* Create nodes. */
	dbg_journal("journal: creating node table, size=%u\n", max_nodes);
	memset(&jn, 0, sizeof(journal_node_t));
	for(uint16_t i = 0; i < max_nodes; ++i) {
		if (!sfwrite(&jn, sizeof(journal_node_t), fd)) {
			fcntl(fd, F_SETLK, &fl);
			close(fd);
			remove(fn);
			return KNOTD_ERROR;
		}
	}
	
	/* Unlock and close. */
	fcntl(fd, F_SETLK, &fl);
	close(fd);

	/* Journal file created. */
	dbg_journal("journal: file '%s' initialized\n", fn);
	return KNOTD_EOK;
}

journal_t* journal_open(const char *fn, size_t fslimit, int mode, uint16_t bflags)
{
	/*! \todo Memory mapping may be faster than stdio? (issue #964) */
	if (fn == NULL) {
		return NULL;
	}

	/* Check for lazy mode. */
	if (mode & JOURNAL_LAZY) {
		dbg_journal("journal: opening journal %s lazily\n", fn);
		journal_t *j = malloc(sizeof(journal_t));
		if (j != NULL) {
			memset(j, 0, sizeof(journal_t));
			j->fd = -1;
			j->path = strdup(fn);
			j->fslimit = fslimit;
			j->bflags = bflags;
			j->refs = 1;
		}
		return j;
	}
	
	/* File lock. */
	struct flock fl;
	memset(&fl, 0, sizeof(struct flock));
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_pid = getpid();

	/* Open journal file for r/w (returns error if not exists). */
	int fd = open(fn, O_RDWR);
	if (fd < 0) {
		dbg_journal("journal: failed to open file '%s'\n", fn);
		return NULL;
	}
	
	/* Attempt to lock. */
	dbg_journal_verb("journal: locking journal %s\n", fn);
	int ret = fcntl(fd, F_SETLK, &fl);
	
	/* Lock. */
	if (ret < 0) {
		struct flock efl;
		memcpy(&efl, &fl, sizeof(struct flock));
		fcntl(fd, F_GETLK, &efl);
		log_server_warning("Journal file '%s' is locked by process "
		                   "PID=%d, waiting for process to "
		                   "release lock.\n",
		                   fn, efl.l_pid);
		ret = fcntl(fd, F_SETLKW, &fl);
	}
	fl.l_type  = F_UNLCK;
	dbg_journal("journal: locked journal %s (returned %d)\n", fn, ret);

	/* Read maximum number of entries. */
	uint16_t max_nodes = 512;
	if (!sfread(&max_nodes, sizeof(uint16_t), fd)) {
		dbg_journal_detail("journal: cannot read max_nodes\n");
		fcntl(fd, F_SETLK, &fl);
		close(fd);
		return NULL;
	}
	
	/* Check max_nodes, but this is riddiculous. */
	if (max_nodes == 0) {
		dbg_journal_detail("journal: max_nodes is invalid\n");
		fcntl(fd, F_SETLK, &fl);
		close(fd);
		return NULL;
	}

	/* Allocate journal structure. */
	const size_t node_len = sizeof(journal_node_t);
	journal_t *j = malloc(sizeof(journal_t) + max_nodes * node_len);
	memset(j, 0, sizeof(journal_t) + max_nodes * node_len);
	if (!j) {
		dbg_journal_detail("journal: cannot allocate journal\n");
		fcntl(fd, F_SETLK, &fl);
		close(fd);
		return NULL;
	}
	j->qhead = j->qtail = 0;
	j->fd = fd;
	j->max_nodes = max_nodes;
	j->bflags = bflags;
	j->refs = 1;

	/* Load node queue state. */
	if (!sfread(&j->qhead, sizeof(uint16_t), fd)) {
		dbg_journal_detail("journal: cannot read qhead\n");
		fcntl(fd, F_SETLK, &fl);
		close(fd);
		free(j);
		return NULL;
	}

	/* Load queue tail. */
	if (!sfread(&j->qtail, sizeof(uint16_t), fd)) {
		dbg_journal_detail("journal: cannot read qtail\n");
		fcntl(fd, F_SETLK, &fl);
		close(fd);
		free(j);
		return NULL;
	}
	
	/* Check head + tail */
	if (j->qtail > max_nodes || j->qhead > max_nodes) {
		dbg_journal_detail("journal: queue pointers corrupted\n");
		fcntl(fd, F_SETLK, &fl);
		close(fd);
		free(j);
		return NULL;
	}

	/* Load empty segment descriptor. */
	if (!sfread(&j->free, node_len, fd)) {
		dbg_journal_detail("journal: cannot read free segment ptr\n");
		fcntl(fd, F_SETLK, &fl);
		close(fd);
		free(j);
		return NULL;
	}

	/* Read journal descriptors table. */
	if (!sfread(&j->nodes, max_nodes * node_len, fd)) {
		dbg_journal_detail("journal: cannot read node table\n");
		fcntl(fd, F_SETLK, &fl);
		close(fd);
		free(j);
		return NULL;
	}
	
	/* Get journal file size. */
	struct stat st;
	if (stat(fn, &st) < 0) {
		dbg_journal_detail("journal: cannot get journal fsize\n");
		fcntl(fd, F_SETLK, &fl);
		close(fd);
		free(j);
		return NULL;
	}

	/* Set file size. */
	j->fsize = st.st_size;
	if (fslimit == 0) {
		j->fslimit = FSLIMIT_INF;
	} else {
		j->fslimit = (size_t)fslimit;
	}
	
	dbg_journal("journal: opened journal size=%u, queue=<%u, %u>, fd=%d\n",
	            max_nodes, j->qhead, j->qtail, j->fd);	
	
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
		                   fn);
		ret = journal_recover(j);
		if (ret != KNOTD_EOK) {
			log_server_error("Journal file '%s' is unrecoverable, "
			                 "metadata corrupted - %s\n",
			                 fn, knotd_strerror(ret));
			fcntl(fd, F_SETLK, &fl);
			close(fd);
			free(j);
			return NULL;
		}
	}

	/* Save file lock. */
	fl.l_type = F_WRLCK;
	memcpy(&j->fl, &fl, sizeof(struct flock));

	return j;
}

int journal_fetch(journal_t *journal, uint64_t id,
		  journal_cmp_t cf, journal_node_t** dst)
{
	if (journal == 0 || dst == 0) {
		return KNOTD_EINVAL;
	}
	
	/* Check compare function. */
	if (!cf) {
		cf = journal_cmp_eq;
	}

	/*! \todo Organize journal descriptors in btree? */
	size_t i = jnode_prev(journal, journal->qtail);
	size_t endp = jnode_prev(journal, journal->qhead);
	for(; i != endp; i = jnode_prev(journal, i)) {
		if (cf(journal->nodes[i].id, id) == 0) {
			*dst = journal->nodes + i;
			return KNOTD_EOK;
		}
	}

	return KNOTD_ENOENT;
}

int journal_read(journal_t *journal, uint64_t id, journal_cmp_t cf, char *dst)
{
	if (journal == 0 || dst == 0) {
		return KNOTD_EINVAL;
	}
	
	journal_node_t *n = 0;
	if(journal_fetch(journal, id, cf, &n) != 0) {
		dbg_journal("journal: failed to fetch node with id=%llu\n",
		            (unsigned long long)id);
		return KNOTD_ENOENT;
	}

	/* Check valid flag. */
	if (!(n->flags & JOURNAL_VALID)) {
		dbg_journal("journal: node with id=%llu is invalid "
		            "(flags=0x%hx)\n", (unsigned long long)id, n->flags);
		return KNOTD_EINVAL;
	}

	dbg_journal("journal: reading node with id=%llu, data=<%u, %u>, flags=0x%hx\n",
	            (unsigned long long)id, n->pos, n->pos + n->len, n->flags);

	/* Seek journal node. */
	lseek(journal->fd, n->pos, SEEK_SET);

	/* Read journal node content. */
	if (!sfread(dst, n->len, journal->fd)) {
		return KNOTD_ERROR;
	}

	return KNOTD_EOK;
}

int journal_write(journal_t *journal, uint64_t id, const char *src, size_t size)
{
	if (journal == 0 || src == 0) {
		return KNOTD_EINVAL;
	}
	
	const size_t node_len = sizeof(journal_node_t);

	/* Find next free node. */
	uint16_t jnext = (journal->qtail + 1) % journal->max_nodes;

	dbg_journal("journal: will write id=%llu, node=%u, size=%zu, fsize=%zu\n",
	            (unsigned long long)id, journal->qtail, size, journal->fsize);

	/* Calculate remaining bytes to reach file size limit. */
	size_t fs_remaining = journal->fslimit - journal->fsize;

	/* Increase free segment if on the end of file. */
	journal_node_t *n = journal->nodes + journal->qtail;
	if (journal->free.pos + journal->free.len == journal->fsize) {

		dbg_journal_verb("journal: * is last node\n");

		/* Grow journal file until the size limit. */
		if(journal->free.len < size && size <= fs_remaining) {
			size_t diff = size - journal->free.len;
			dbg_journal("journal: * growing by +%zu, pos=%u, "
			            "new fsize=%zu\n",
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
			dbg_journal_verb("journal: * fslimit reached, "
			                 "rewinding to %u\n",
			                 head->pos);
			dbg_journal_verb("journal: * file size trimmed to %zu\n",
			                 journal->fsize);
		}
	}
	
	/* Evict occupied nodes if necessary. */
	while (journal->free.len < size ||
	       journal->nodes[jnext].flags > JOURNAL_FREE) {

		/* Evict least recent node if not empty. */
		journal_node_t *head = journal->nodes + journal->qhead;

		/* Check if it has been synced to disk. */
		if (head->flags & JOURNAL_DIRTY) {
			return KNOTD_EAGAIN;
		}

		/* Write back evicted node. */
		head->flags = JOURNAL_FREE;
		lseek(journal->fd, JOURNAL_HSIZE + (journal->qhead + 1) * node_len, SEEK_SET);
		if (!sfwrite(head, node_len, journal->fd)) {
			return KNOTD_ERROR;
		}

		dbg_journal("journal: * evicted node=%u, growing by +%u\n",
			      journal->qhead, head->len);

		/* Write back query state. */
		journal->qhead = (journal->qhead + 1) % journal->max_nodes;
		uint16_t qstate[2] = {journal->qhead, journal->qtail};
		lseek(journal->fd, JOURNAL_HSIZE - 2 * sizeof(uint16_t), SEEK_SET);
		if (!sfwrite(qstate, 2 * sizeof(uint16_t), journal->fd)) {
			return KNOTD_ERROR;
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
	lseek(journal->fd, n->pos, SEEK_SET);
	if (!sfwrite(src, size, journal->fd)) {
		return KNOTD_ERROR;
	}

	/* Mark node as valid and write back. */
	n->flags = JOURNAL_VALID | journal->bflags;
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
	dbg_journal("journal: finished node=%u, data=<%u, %u> free=<%u, %u>\n",
	            journal->qtail, n->pos, n->pos + n->len,
	            journal->free.pos,
	            journal->free.pos + journal->free.len);

	/* Write back free segment state. */
	lseek(journal->fd, JOURNAL_HSIZE, SEEK_SET);
	if (!sfwrite(&journal->free, node_len, journal->fd)) {
		/* Node is marked valid and failed to shrink free space,
		 * node will be overwritten on the next write. Return error.
		 */
		dbg_journal("journal: failed to write back "
		            "free segment descriptor\n");
		return KNOTD_ERROR;
	}
	
	/* Node write successful. */
	journal->qtail = jnext;

	/* Write back queue state, not essential as it may be recovered.
	 * qhead - lowest valid node identifier (least recent)
	 * qtail - highest valid node identifier (most recently used)
	 */
	uint16_t qstate[2] = {journal->qhead, journal->qtail};
	lseek(journal->fd, JOURNAL_HSIZE - 2 * sizeof(uint16_t), SEEK_SET);
	if (!sfwrite(qstate, 2 * sizeof(uint16_t), journal->fd)) {
		dbg_journal("journal: failed to write back queue state\n");
		return KNOTD_ERROR;
	}

	/*! \todo Delayed write-back? (issue #964) */
	dbg_journal_verb("journal: write of finished, nqueue=<%u, %u>\n",
	                 journal->qhead, journal->qtail);

	return KNOTD_EOK;
}

int journal_walk(journal_t *journal, journal_apply_t apply)
{
	int ret = KNOTD_EOK;
	size_t i = journal->qhead;
	for(; i != journal->qtail; i = (i + 1) % journal->max_nodes) {
		/* Apply function. */
		ret = apply(journal, journal->nodes + i);
	}

	return ret;
}

int journal_update(journal_t *journal, journal_node_t *n)
{
	if (!journal || !n) {
		return KNOTD_EINVAL;
	}

	/* Calculate node offset. */
	const size_t node_len = sizeof(journal_node_t);
	size_t i = n - journal->nodes;
	if (i > journal->max_nodes) {
		return KNOTD_EINVAL;
	}

	/* Calculate node position in permanent storage. */
	long jn_fpos = JOURNAL_HSIZE + (i + 1) * node_len;

	dbg_journal("journal: syncing journal node=%zu at %ld\n",
		      i, jn_fpos);

	/* Write back. */
	lseek(journal->fd, jn_fpos, SEEK_SET);
	if (!sfwrite(n, node_len, journal->fd)) {
		dbg_journal("journal: failed to writeback node=%llu to %ld\n",
		            (unsigned long long)n->id, jn_fpos);
		return KNOTD_ERROR;
	}

	return KNOTD_EOK;
}

int journal_close(journal_t *journal)
{
	/* Check journal. */
	if (!journal) {
		return KNOTD_EINVAL;
	}
	
	/* Check if lazy. */
	if (journal->fd < 0) {
		free(journal->path);
	} else {
		/* Unlock journal file. */
		journal->fl.l_type = F_UNLCK;
		fcntl(journal->fd, F_SETLK, &journal->fl);
		dbg_journal("journal: unlocked journal %p\n", journal);

		/* Close file. */
		close(journal->fd);
	}
	
	dbg_journal("journal: closed journal %p\n", journal);

	/* Free allocated resources. */
	
	free(journal);

	return KNOTD_EOK;
}

journal_t *journal_retain(journal_t *journal)
{
	/* Return active journal if opened lazily. */
	if (journal != NULL) {
		if (journal->fd < 0) {
			dbg_journal("journal: retain(), opening for rw\n");
			journal = journal_open(journal->path, journal->fslimit, 
			                       0, journal->bflags);
		} else {
			++journal->refs;
			dbg_journal("journal: retain(), ++refcount\n");
		}
	}
	
	return journal;
}


void journal_release(journal_t *journal) {
	if (journal != NULL) {
		if (journal->refs == 1) {
			dbg_journal("journal: release(), closing last\n");
			journal_close(journal);
		} else {
			--journal->refs;
			dbg_journal_verb("journal: release(), --refcount\n");
		}
	}
}
