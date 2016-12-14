/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <sys/stat.h>
#include <sys/mman.h>
#include <assert.h>

#include "knot/common/log.h"
#include "contrib/files.h"
#include "knot/journal/old_journal.h"
#include "knot/journal/serialization.h"
#include "libknot/libknot.h"

typedef enum {
	JOURNAL_NULL  = 0 << 0, /*!< Invalid journal entry. */
	JOURNAL_FREE  = 1 << 0, /*!< Free journal entry. */
	JOURNAL_VALID = 1 << 1, /*!< Valid journal entry. */
	JOURNAL_DIRTY = 1 << 2  /*!< Journal entry cannot be evicted. */
} journal_flag_t;

typedef struct {
	uint64_t id;    /*!< Node ID. */
	uint16_t flags; /*!< Node flags. */
	uint16_t next;  /*!< UNUSED */
	uint32_t pos;   /*!< Position in journal file. */
	uint32_t len;   /*!< Entry data length. */
} journal_node_t;

typedef struct {
	int fd;
	char *path;             /*!< Path to journal file. */
	uint16_t tmark;         /*!< Transaction start mark. */
	uint16_t max_nodes;     /*!< Number of nodes. */
	uint16_t qhead;         /*!< Node queue head. */
	uint16_t qtail;         /*!< Node queue tail. */
	uint16_t bflags;        /*!< Initial flags for each written node. */
	size_t fsize;           /*!< Journal file size. */
	size_t fslimit;         /*!< File size limit. */
	journal_node_t free;    /*!< Free segment. */
	journal_node_t *nodes;  /*!< Array of nodes. */
} old_journal_t;

#define JOURNAL_NCOUNT 1024 /*!< Default node count. */
#define JOURNAL_MAGIC {'k', 'n', 'o', 't', '1', '5', '2'}
#define MAGIC_LENGTH 7
/* HEADER = magic, crc, max_entries, qhead, qtail */
#define JOURNAL_HSIZE (MAGIC_LENGTH + sizeof(uint32_t) + sizeof(uint16_t) * 3)

/*! \brief Infinite file size limit. */
#define FSLIMIT_INF (~((size_t)0))

/*! \brief Next node. */
#define jnode_next(j, i) (((i) + 1) % (j)->max_nodes)

/*! \brief Previous node. */
#define jnode_prev(j, i) (((i) == 0) ? (j)->max_nodes - 1 : (i) - 1)

/*! \bref Starting node data position. */
#define jnode_base_pos(max_nodes) (JOURNAL_HSIZE + (max_nodes + 1) * sizeof(journal_node_t))

static inline int sfread(void *dst, size_t len, int fd)
{
	return read(fd, dst, len) == len;
}

/*! \brief Return 'serial_from' part of the key. */
static inline uint32_t journal_key_from(uint64_t k)
{
	return (uint32_t)(k & ((uint64_t)0x00000000ffffffff));
}

/*! \brief Compare function to match entries with starting serial. */
static inline int journal_key_from_cmp(uint64_t k, uint64_t from)
{
	return ((uint64_t)journal_key_from(k)) - from;
}

/*! \brief Open journal file for r/w (returns error if not exists). */
static int old_journal_open_file(old_journal_t *j)
{
	assert(j != NULL);

	int ret = KNOT_EOK;
	j->fd = open(j->path, O_RDWR);
	if (j->fd < 0) {
		return knot_map_errno();
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
		log_warning("old journal '%s', version too old", j->path);
		close(j->fd);
		j->fd = -1;
		return KNOT_ENOTSUP;
	}

	/* Skip CRC */
	if (lseek(j->fd, MAGIC_LENGTH + sizeof(uint32_t), SEEK_SET) < 0) {
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
static int old_journal_close_file(old_journal_t *journal)
{
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

static int old_journal_close(old_journal_t *journal)
{
	/* Check journal. */
	if (journal == NULL) {
		return KNOT_EINVAL;
	}

	/* Close file. */
	old_journal_close_file(journal);

	/* Free allocated resources. */
	free(journal->path);
	free(journal);

	return KNOT_EOK;
}

static int old_journal_open(old_journal_t **journal, const char *path, size_t fslimit)
{
	if (journal == NULL || path == NULL) {
		return KNOT_EINVAL;
	}

	old_journal_t *j = malloc(sizeof(*j));
	if (j == NULL) {
		return KNOT_ENOMEM;
	}

	memset(j, 0, sizeof(*j));
	j->bflags = JOURNAL_DIRTY;
	j->fd = -1;

	j->fslimit = fslimit;

	/* Copy path. */
	j->path = strdup(path);
	if (j->path == NULL) {
		free(j);
		return KNOT_ENOMEM;
	}

	/* Open journal file. */
	int ret = old_journal_open_file(j);
	if (ret != KNOT_EOK) {
		log_error("old journal '%s', failed to open (%s)", path,
		          knot_strerror(ret));
		old_journal_close(j);
		return ret;
	}

	*journal = j;

	return KNOT_EOK;
}

typedef int (*journal_cmp_t)(uint64_t k1, uint64_t k2);

static int old_journal_fetch(old_journal_t *journal, uint64_t id,
		  journal_cmp_t cf, journal_node_t** dst)
{
	if (journal == NULL || dst == NULL) {
		return KNOT_EINVAL;
	}

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

static int old_journal_read_node(old_journal_t *journal, journal_node_t *n, char *dst)
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

bool old_journal_exists(const char *path)
{
	if (path == NULL) {
		return false;
	}
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
				ret = changeset_add_removal(chs, &rrset, 0);
			} else {
				/* Add RRSets. */
				ret = changeset_add_addition(chs, &rrset, 0);
			}
		}
		knot_rrset_clear(&rrset, NULL);
		if (ret != KNOT_EOK) {
			break;
		}
	}
	return ret;
}

/*! \brief Helper for iterating journal (this is temporary until #80) */
typedef int (*journal_apply_t)(old_journal_t *, journal_node_t *, const knot_dname_t *, list_t *);
static int old_journal_walk(const char *fn, uint32_t from, uint32_t to,
			journal_apply_t cb, const knot_dname_t *zone, list_t *chgs)
{
	/* Open journal for reading. */
	old_journal_t *journal = NULL;
	int ret = old_journal_open(&journal, fn, FSLIMIT_INF);
	if (ret != KNOT_EOK) {
		return ret;
	}
	/* Read entries from starting serial until finished. */
	uint32_t found_to = from;
	journal_node_t *n = 0;
	ret = old_journal_fetch(journal, from, journal_key_from_cmp, &n);
	if (ret != KNOT_EOK) {
		goto finish;
	}

	size_t i = n - journal->nodes;
	assert(i < journal->max_nodes);

	for (; i != journal->qtail; i = jnode_next(journal, i)) {
		journal_node_t *n = journal->nodes + i;

		if (!(n->flags & JOURNAL_VALID)) {
			continue;
		}
		if (to == found_to) {
			break;
		}
		ret = cb(journal, n, zone, chgs);
		if (ret != KNOT_EOK) {
			break;
		}
	}

finish:
	old_journal_close(journal);
	return ret;
}

static int load_changeset(old_journal_t *journal, journal_node_t *n,
                          const knot_dname_t *zone, list_t *chgs)
{
	changeset_t *ch = changeset_new(zone);
	if (ch == NULL) {
		return KNOT_ENOMEM;
	}

	/* Initialize changeset. */
	ch->data = malloc(n->len);
	if (!ch->data) {
		return KNOT_ENOMEM;
	}

	/* Read journal entry. */
	int ret = old_journal_read_node(journal, n, (char*)ch->data);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Update changeset binary size. */
	ch->size = n->len;

	/* Insert into changeset list. */
	add_tail(chgs, &ch->n);

	return KNOT_EOK;
}

int old_journal_load_changesets(const char *path, const knot_dname_t *zone,
                                list_t *dst, uint32_t from, uint32_t to)
{
	int ret = old_journal_walk(path, from, to, &load_changeset, zone, dst);
	if (ret != KNOT_EOK) {
		return ret;
	}

	assert(dst != NULL);

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
