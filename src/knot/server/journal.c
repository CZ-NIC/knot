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

#include "knot/common/log.h"
#include "knot/server/journal.h"
#include "knot/server/serialization.h"
#include "knot/zone/zone.h"
#include "libknot/libknot.h"
#include "libknot/rrtype/soa.h"

/*! \brief Infinite file size limit. */
#define FSLIMIT_INF (~((size_t)0))

/*! \brief Next node. */
#define jnode_next(j, i) (((i) + 1) % (j)->max_nodes)

/*! \brief Previous node. */
#define jnode_prev(j, i) (((i) == 0) ? (j)->max_nodes - 1 : (i) - 1)

/*! \bref Starting node data position. */
#define jnode_base_pos(max_nodes) (JOURNAL_HSIZE + (max_nodes + 1) * sizeof(journal_node_t))

static const uint32_t CRC_PLACEHOLDER = 0;

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
	int fd = open(fn, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP);
	if (fd < 0) {
		return knot_map_errno();
	}

	/* Lock. */
	if (fcntl(fd, F_SETLKW, &fl) == -1) {
		close(fd);
		remove(fn);
		return KNOT_ERROR;
	}

	/* Create journal header. */
	const char magic[MAGIC_LENGTH] = JOURNAL_MAGIC;
	if (!sfwrite(magic, MAGIC_LENGTH, fd)) {
		close(fd);
		remove(fn);
		return KNOT_ERROR;
	}

	if (!sfwrite(&CRC_PLACEHOLDER, sizeof(CRC_PLACEHOLDER), fd)) {
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

	/* Create free segment descriptor. */
	journal_node_t jn;
	memset(&jn, 0, sizeof(journal_node_t));
	jn.id = 0;
	jn.flags = JOURNAL_VALID;
	jn.pos = jnode_base_pos(max_nodes);
	jn.len = 0;
	if (!sfwrite(&jn, sizeof(journal_node_t), fd)) {
		close(fd);
		remove(fn);
		return KNOT_ERROR;
	}

	/* Create nodes. */
	memset(&jn, 0, sizeof(journal_node_t));
	for(uint16_t i = 0; i < max_nodes; ++i) {
		if (!sfwrite(&jn, sizeof(journal_node_t), fd)) {
			close(fd);
			(void)remove(fn);
			return KNOT_ERROR;
		}
	}

	/* Unlock and close. */
	close(fd);

	/* Journal file created. */
	return KNOT_EOK;
}

/*! \brief Open journal file for r/w (returns error if not exists). */
static int journal_open_file(journal_t *j)
{
	assert(j != NULL);

	int ret = KNOT_EOK;
	j->fd = open(j->path, O_RDWR);
	if (j->fd < 0) {
		if (errno != ENOENT) {
			return knot_map_errno();
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
	ret = fcntl(j->fd, F_SETLKW, &lock);
	if (ret < 0) {
		return knot_map_errno();
	}

	/* Read magic bytes. */
	const char magic_req[MAGIC_LENGTH] = JOURNAL_MAGIC;
	char magic[MAGIC_LENGTH];
	if (!sfread(magic, MAGIC_LENGTH, j->fd)) {
		goto open_file_error;
	}
	if (memcmp(magic, magic_req, MAGIC_LENGTH) != 0) {
		log_warning("journal '%s', version too old, purging", j->path);
		close(j->fd);
		j->fd = -1;
		ret = journal_create_file(j->path, JOURNAL_NCOUNT);
		if(ret == KNOT_EOK) {
			return journal_open_file(j);
		}
		return ret;
	}

	/* Skip CRC */
	if (lseek(j->fd, MAGIC_LENGTH + sizeof(CRC_PLACEHOLDER), SEEK_SET) < 0) {
		goto open_file_error;
	}

	/* Get journal file size. */
	struct stat st;
	if (fstat(j->fd, &st) < 0) {
		goto open_file_error;
	}

	/* Set file size. */
	j->fsize = st.st_size;

	/* Read maximum number of entries. */
	if (!sfread(&j->max_nodes, sizeof(uint16_t), j->fd)) {
		goto open_file_error;
	}

	/* Check max_nodes, but this is riddiculous. */
	if (j->max_nodes == 0) {
		goto open_file_error;
	}

	/* Check minimum fsize limit. */
	size_t fslimit_min = jnode_base_pos(j->max_nodes) + 1024; /* At least 1K block */
	if (j->fslimit < fslimit_min) {
		log_error("journal '%s', filesize limit smaller than '%zu'", j->path, fslimit_min);
		goto open_file_error;
	}

	/* Allocate nodes. */
	const size_t node_len = sizeof(journal_node_t);
	j->nodes = malloc(j->max_nodes * node_len);
	if (j->nodes == NULL) {
		goto open_file_error;
	} else {
		memset(j->nodes, 0, j->max_nodes * node_len);
	}

	/* Load node queue state. */
	j->qhead = j->qtail = 0;
	if (!sfread(&j->qhead, sizeof(uint16_t), j->fd)) {
		goto open_file_error;
	}

	/* Load queue tail. */
	if (!sfread(&j->qtail, sizeof(uint16_t), j->fd)) {
		goto open_file_error;
	}

	/* Check head + tail */
	if (j->qtail >= j->max_nodes || j->qhead >= j->max_nodes) {
		goto open_file_error;
	}

	/* Load empty segment descriptor. */
	if (!sfread(&j->free, node_len, j->fd)) {
		goto open_file_error;
	}

	/* Read journal descriptors table. */
	if (!sfread(j->nodes, j->max_nodes * node_len, j->fd)) {
		goto open_file_error;
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

	/* Close file. */
	if (journal->fd > 0) {
		close(journal->fd);
		journal->fd = -1;
	}

	/* Free nodes. */
	free(journal->nodes);
	journal->nodes = NULL;

	return KNOT_EOK;
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
	assert(i < journal->max_nodes);

	/* Calculate node position in permanent storage. */
	long jn_fpos = JOURNAL_HSIZE + (i + 1) * node_len;

	/* Write back. */
	int seek_ret = lseek(journal->fd, jn_fpos, SEEK_SET);
	if (seek_ret < 0 || !sfwrite(n, node_len, journal->fd)) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int journal_write_in(journal_t *j, journal_node_t **rn, uint64_t id, size_t len)
{
	const size_t node_len = sizeof(journal_node_t);
	*rn = NULL;

	/* Count rewinds. */
	bool already_rewound = false;

	/* Evict occupied nodes if necessary. */
	while (j->free.len < len || jnode_next(j, j->qtail) == j->qhead) {

		/* Increase free segment if on the end of file. */
		bool is_empty = (j->qtail == j->qhead);
		journal_node_t *head = j->nodes + j->qhead;
		journal_node_t *last = j->nodes + jnode_prev(j, j->qtail);
		if (is_empty || (head->pos <= last->pos && j->free.pos > last->pos)) {

			/* Grow journal file until the size limit. */
			if(j->free.pos + len < j->fslimit  && jnode_next(j, j->qtail) != j->qhead) {
				size_t diff = len - j->free.len;
				j->fsize += diff; /* Appending increases file size. */
				j->free.len += diff;
				continue;

			} else if (!already_rewound) {
				/*  Rewind if resize is needed, but the limit is reached. */
				j->free.pos = jnode_base_pos(j->max_nodes);
				j->free.len = 0;
				if (!is_empty) {
					j->free.len = head->pos - j->free.pos;
				}
				already_rewound = true;
			} else {
				/* Already rewound, but couldn't collect enough free space. */
				return KNOT_ESPACE;
			}

			/* Continue until enough free space is collected. */
			continue;
		}

		/* Check if it has been synced to disk. */
		if ((head->flags & JOURNAL_DIRTY) && (head->flags & JOURNAL_VALID)) {
			return KNOT_EBUSY;
		}

		/* Write back evicted node. */
		head->flags = JOURNAL_FREE;
		int seek_ret = lseek(j->fd, JOURNAL_HSIZE + (j->qhead + 1) * node_len, SEEK_SET);
		if (seek_ret < 0 || !sfwrite(head, node_len, j->fd)) {
			return KNOT_ERROR;
		}

		/* Write back query state. */
		j->qhead = (j->qhead + 1) % j->max_nodes;
		uint16_t qstate[2] = {j->qhead, j->qtail};
		seek_ret = lseek(j->fd, JOURNAL_HSIZE - 2 * sizeof(uint16_t), SEEK_SET);
		if (seek_ret < 0 || !sfwrite(qstate, 2 * sizeof(uint16_t), j->fd)) {
			return KNOT_ERROR;
		}

		/* Increase free segment. */
		j->free.len += head->len;
	}

	/* Invalidate tail node and write back. */
	journal_node_t *n = j->nodes + j->qtail;
	n->id = id;
	n->pos = j->free.pos;
	n->len = len;
	n->flags = JOURNAL_FREE;
	journal_update(j, n);
	*rn = n;
	return KNOT_EOK;
}

int journal_write_out(journal_t *journal, journal_node_t *n)
{
	/* Mark node as valid and write back. */
	uint16_t jnext = (journal->qtail + 1) % journal->max_nodes;
	size_t size = n->len;
	const size_t node_len = sizeof(journal_node_t);
	n->flags = JOURNAL_VALID | journal->bflags;
	journal_update(journal, n);

	/* Mark used space. */
	journal->free.pos += size;
	journal->free.len -= size;

	/* Write back free segment state. */
	int seek_ret = lseek(journal->fd, JOURNAL_HSIZE, SEEK_SET);
	if (seek_ret < 0 || !sfwrite(&journal->free, node_len, journal->fd)) {
		/* Node is marked valid and failed to shrink free space,
		 * node will be overwritten on the next write. Return error.
		 */
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

		/* Skip invalid nodes. */
		if (!(n->flags & JOURNAL_VALID)) {
			continue;
		}

		if (cf(n->id, id) == 0) {
			*dst = journal->nodes + i;
			return KNOT_EOK;
		}
	}

	return KNOT_ENOENT;
}

static int journal_read_node(journal_t *journal, journal_node_t *n, char *dst)
{
	/* Check valid flag. */
	if (!(n->flags & JOURNAL_VALID)) {
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

	/* Return if read-only, invalidate if rewritten to avoid duplicates. */
	if (rdonly) {
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else {
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
	}

	/* Align offset to page size (required). */
	const size_t ps = sysconf(_SC_PAGESIZE);
	off_t ps_delta = (n->pos % ps);
	off_t off = n->pos - ps_delta;

	/* Map file region. */
	*dst = mmap(NULL, n->len + ps_delta, PROT_READ | PROT_WRITE, MAP_SHARED,
	            journal->fd, off);
	if (*dst == ((void*)-1)) {
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
		return KNOT_ENOENT;
	}

	/* Realign memory. */
	const size_t ps = sysconf(_SC_PAGESIZE);
	off_t ps_delta = (n->pos % ps);
	ptr = ((char*)ptr - ps_delta);

	/* Unmap memory. */
	if (munmap(ptr, n->len + ps_delta) != 0) {
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

	/* Read changeset flags. */
	if (chs->data == NULL) {
		return KNOT_EMALF;
	}
	size_t remaining = chs->size;

	/* Read initial changeset RRSet - SOA. */
	uint8_t *stream = chs->data + (chs->size - remaining);
	knot_rrset_t rrset;
	int ret = rrset_deserialize(stream, &remaining, &rrset);
	if (ret != KNOT_EOK) {
		return KNOT_EMALF;
	}

	assert(rrset.type == KNOT_RRTYPE_SOA);
	chs->soa_from = knot_rrset_copy(&rrset, NULL);
	knot_rrset_clear(&rrset, NULL);
	if (chs->soa_from == NULL) {
		return KNOT_ENOMEM;
	}

	/* Read remaining RRSets */
	bool in_remove_section = true;
	while (remaining > 0) {

		/* Parse next RRSet. */
		stream = chs->data + (chs->size - remaining);
		knot_rrset_init_empty(&rrset);
		ret = rrset_deserialize(stream, &remaining, &rrset);
		if (ret != KNOT_EOK) {
			return KNOT_EMALF;
		}

		/* Check for next SOA. */
		if (rrset.type == KNOT_RRTYPE_SOA) {
			/* Move to ADD section if in REMOVE. */
			if (in_remove_section) {
				chs->soa_to = knot_rrset_copy(&rrset, NULL);
				if (chs->soa_to == NULL) {
					ret = KNOT_ENOMEM;
					break;
				}
				in_remove_section = false;
			} else {
				/* Final SOA, no-op. */
				;
			}
		} else {
			/* Remove RRSets. */
			if (in_remove_section) {
				ret = changeset_rem_rrset(chs, &rrset, 0);
			} else {
				/* Add RRSets. */
				ret = changeset_add_rrset(chs, &rrset, 0);
			}
		}
		knot_rrset_clear(&rrset, NULL);
		if (ret != KNOT_EOK) {
			break;
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

	changeset_iter_t itt;
	ret = changeset_iter_rem(&itt, chs, false);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_rrset_t rrset = changeset_iter_next(&itt);
	while (!knot_rrset_empty(&rrset)) {
		ret = rrset_write_to_mem(&rrset, &entry, &max_size);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&itt);
			return ret;
		}
		rrset = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	/* Serialize SOA 'to'. */
	ret = rrset_write_to_mem(chs->soa_to, &entry, &max_size);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Serialize RRSets from the 'add' section. */
	ret = changeset_iter_add(&itt, chs, false);
	if (ret != KNOT_EOK) {
		return ret;
	}

	rrset = changeset_iter_next(&itt);
	while (!knot_rrset_empty(&rrset)) {
		ret = rrset_write_to_mem(&rrset, &entry, &max_size);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&itt);
			return ret;
		}
		rrset = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

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
typedef int (*journal_apply_t)(journal_t *, journal_node_t *, const zone_t *, list_t *);
static int journal_walk(const char *fn, uint32_t from, uint32_t to,
                        journal_apply_t cb, const zone_t *zone, list_t *chgs)
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

	size_t i = n - journal->nodes;
	assert(i < journal->max_nodes);

	for (; i != journal->qtail; i = jnode_next(journal, i)) {
		journal_node_t *n = journal->nodes + i;

		/* Skip invalid nodes. */
		if (!(n->flags & JOURNAL_VALID)) {
			continue;
		}

		/* Check for history end. */
		if (to == found_to) {
			break;
		}

		/* Callback. */
		ret = cb(journal, n, zone, chgs);
		if (ret != KNOT_EOK) {
			break;
		}
	}

finish:
	/* Close journal. */
	journal_close(journal);
	return ret;
}

static int load_changeset(journal_t *journal, journal_node_t *n, const zone_t *zone, list_t *chgs)
{
	changeset_t *ch = changeset_new(zone->name);
	if (ch == NULL) {
		return KNOT_ENOMEM;
	}

	/* Initialize changeset. */
	ch->data = malloc(n->len);
	if (!ch->data) {
		return KNOT_ENOMEM;
	}

	/* Read journal entry. */
	int ret = journal_read_node(journal, n, (char*)ch->data);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Update changeset binary size. */
	ch->size = n->len;

	/* Insert into changeset list. */
	add_tail(chgs, &ch->n);

	return KNOT_EOK;
}

int journal_load_changesets(const char *path, const zone_t *zone, list_t *dst,
                            uint32_t from, uint32_t to)
{
	int ret = journal_walk(path, from, to, &load_changeset, zone, dst);
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
	WALK_LIST(chs, *dst) {
		ret = changesets_unpack(chs);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* Check for complete history. */
	changeset_t *last = TAIL(*dst);
	if (to != knot_soa_serial(&last->soa_to->rrs)) {
		return KNOT_ERANGE;
	}

	return KNOT_EOK;
}

int journal_store_changesets(list_t *src, const char *path, size_t size_limit)
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
	WALK_LIST(chs, *src) {
		ret = changeset_pack(chs, journal);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	journal_close(journal);
	return ret;
}

int journal_store_changeset(changeset_t *change, const char *path, size_t size_limit)
{
	if (change == NULL || path == NULL) {
		return KNOT_EINVAL;
	}

	/* Open journal for reading. */
	journal_t *journal = journal_open(path, size_limit);
	if (journal == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = changeset_pack(change, journal);

	journal_close(journal);
	return ret;
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
	for(; i != journal->qtail; i = jnode_next(journal, i)) {
		mark_synced(journal, journal->nodes + i);
	}

	journal_close(journal);

	return KNOT_EOK;
}
