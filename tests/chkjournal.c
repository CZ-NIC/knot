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

    Usage: chkjournal --help

    How to make:
      (for this computer):  make chkjournal
      (for 32bit journals): make chkjournal-i386
      (for 64bit journal):  make chkjournal-amd64
      
   !!! For specific versions, make sure the libknotd.la is compiled
   with -fpack-struct=4 for 32bit or -fpack-struct=8 for 64bit chkjournal.
   f.e.:
     $ cd <knot_root>
     $ CFLAGS="-fpack-struct=4" ./configure
     $ make clean && make -j8
     $ cd tests
     $ make chkjournal-i386
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>
#include <sys/stat.h>

#ifndef KNOT_RRSET_DEBUG
#define KNOT_RRSET_DEBUG 1
#endif

//#define KNOT_RDATA_DEBUG 1
#include "src/common/log.h"
#include "src/common/crc.h"
#include "src/common/errcode.h"
#include "src/knot/server/journal.h"
#include "src/knot/server/zones.h"
#include "src/libknot/updates/changesets.h"
#include "src/libknot/util/debug.h"
#include "src/libknot/util/debug.c"
#include "config.h"

/* Alignment. */
static size_t ALIGNMENT = 1;
static inline size_t a(size_t s) {
	return s + s % ALIGNMENT;
}
static size_t PADDING = 4;

/*! \brief Return 'serial_from' part of the key. */
static inline uint32_t ixfrdb_key_from(uint64_t k)
{
	/*      64    32       0
	 * key = [TO   |   FROM]
	 * Need: Least significant 32 bits.
	 */
	return (uint32_t)(k & ((uint64_t)0x00000000ffffffff));
}

/*----------------------------------------------------------------------------*/

/*! \brief Return 'serial_to' part of the key. */
static inline uint32_t ixfrdb_key_to(uint64_t k)
{
	/*      64    32       0
	 * key = [TO   |   FROM]
	 * Need: Most significant 32 bits.
	 */
	return (uint32_t)(k >> (uint64_t)32);
}

/*----------------------------------------------------------------------------*/

#define MAGIC_LENGTH 7

enum {
	SHOW = 0,
	UPDATE,
	FIXCRC,
	DUMP,
	XDUMP
};

void help(int argc, char **argv)
{
	printf("Usage: chkjournal [parameters] <journal_file>\n");
	printf("Parameters:\n"
	       " -p, --padding=N    Padding after each node.\n"
	       " -a, --align=N      Expect journal structures aligned to N bytes.\n"
	       " -f, --fixcrc       Recompute CRC32.\n"
	       " -u, --update       Update version to latest.\n"
	       " -x, --xdump=id     Dump changeset (hexdump).\n"
	       " -d, --dump=id      Dump changeset (parsed).\n"
	       " -h, --help         Print help and usage.\n"
	       );
}

/* Show. */
int walkf(journal_t *j, journal_node_t *n) {
	printf("entry '%zu' flags=0x%hu fpos=%u len=%u\n", n->id, n->flags, n->pos, n->len);
	return 0;
}

int show(const char *fname)
{
	/* Open journal. */
	journal_t *j = journal_open(fname, -1, 0, 0);
	if (j == NULL) {
		fprintf(stderr, "error: couldn't open journal '%s'\n", fname);
		return 1;
	}

	printf("journal: %s max_nodes=%hu queue=%u..%u\n",
	       fname, j->max_nodes, j->qtail, j->qhead);
	journal_walk(j, walkf);
	journal_close(j);
	return 0;
}

/* Fix CRC. */
int fixcrc(const char *fname)
{
	int fd = open(fname, O_RDONLY);
	if (fd < 0) {
		return 1;
	}
	
	int ret = 1;
	if (journal_update_crc(fd) == 0) {
		ret = 0;
	}
	
	close(fd);
	return ret;
}

/* Fix file positions. */
static int FPOSDELTA = 0;
int walkfix(journal_t *j, journal_node_t *n) {
	n->pos += FPOSDELTA;
	journal_update(j, n);
	return 0;
}

int fixfpos(const char *fname, int delta)
{
	/* Open journal. */
	journal_t *j = journal_open(fname, -1, 0, 0);
	if (j == NULL) {
		fprintf(stderr, "error: couldn't open journal '%s'\n", fname);
		return 1;
	}
	FPOSDELTA = delta;
	journal_walk(j, walkfix);
	journal_close(j);
	return 0;
}

/* Update journal file. */
int update(const char *fname)
{
	int fd = open(fname, O_RDONLY);
	if (fd < 0) {
		return 1;
	}
	
	/* Check source magic bytes. */
	int rb = 0;
	int ret = 0;
	char buf[4096];
	char mbytes[MAGIC_LENGTH] = {};
	read(fd, mbytes, MAGIC_LENGTH);
	if (memcmp(mbytes, "knot100", MAGIC_LENGTH) == 0) {
		/* 100 -> 101 +crc after MB. */
		char *nfname = malloc(strlen(fname) + 4 + 1);
		assert(nfname != NULL);
		strncpy(nfname, fname, strlen(fname));
		strncat(nfname, ".new", 4);
		int nfd = open(nfname, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
		const char nmbytes[] = "knot101";
		if (nfd >= 0) {
			/* Extend header. */
			write(nfd, nmbytes, MAGIC_LENGTH);
			write(nfd, buf, sizeof(crc_t));
			read(fd, buf, sizeof(uint16_t) * 3);
			write(nfd, buf, sizeof(uint16_t) * 3);
			
			/* Copy nodes. */
			uint16_t ncount = *((uint16_t*)buf) + 1;
			printf("Will update %hu nodes.\n", ncount - 1);
			for (uint16_t i = 0; i < ncount; ++i) {
				/* Copy id+flags. */
				read(fd, buf, a(sizeof(uint64_t)+sizeof(uint16_t)));
				write(nfd, buf, a(sizeof(uint64_t)+sizeof(uint16_t)));
				read(fd, buf, a(2*sizeof(uint32_t)));
				*((uint32_t*)buf) += sizeof(crc_t);
				write(nfd, buf, a(2*sizeof(uint32_t)));
				/* Copy padding. */
				read(fd, buf, PADDING);
				write(nfd, buf, PADDING);
			}
			
			/* Copy remaining. */
			while((rb = read(fd, buf, sizeof(buf))) > 0) {
				if (write(nfd, buf, rb) != rb) {
					ret = 1;
					break;
				}
			}
			/* Update CRC. */
			if (ret == 0) {
				journal_update_crc(nfd);
			}
		}
		
		/* Replace if success. */
		close(nfd);
		close(fd);
		if (ret == 0) {
			remove(fname);
			rename(nfname, fname);
			printf("Converted journal v1.0.0 -> v1.0.1\n");
		}
		free(nfname);
	} else if (memcmp(mbytes, "knot101", MAGIC_LENGTH) == 0) {
		/* 101 -> 102, transactions, +uint16 'next' in jnode */
		char *nfname = malloc(strlen(fname) + 4 + 1);
		assert(nfname != NULL);
		strncpy(nfname, fname, strlen(fname));
		strncat(nfname, ".new", 4);
		int nfd = open(nfname, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
		size_t hs102 = (MAGIC_LENGTH + sizeof(crc_t) + sizeof(uint16_t) * 3);
		const char nmbytes[] = "knot102";
		
		if (nfd >= 0) {
			/* Copy header. */
			lseek(fd, 0, SEEK_SET);
			read(fd, buf, hs102);
			write(nfd, buf, hs102);
			lseek(nfd, 0, SEEK_SET);
			write(nfd, nmbytes, MAGIC_LENGTH);
			
			/* Read node count. */
			lseek(fd, MAGIC_LENGTH + sizeof(crc_t), SEEK_SET);
			uint16_t ncount = 0;
			read(fd, &ncount, sizeof(uint16_t));
			printf("Will update %hu nodes.\n", ncount);
			ncount += 1; /* Free segment. */
			lseek(fd, hs102, SEEK_SET);
			lseek(nfd, hs102, SEEK_SET);
			
			/* Extend nodes. */
			/*! \todo Calculate offset from difference of struct size. */
			for (uint16_t i = 0; i < ncount; ++i) {
				/* Copy id+flags. */
				read(fd, buf, a(sizeof(uint64_t)+sizeof(uint16_t)));
				write(nfd, buf, sizeof(uint64_t)+sizeof(uint16_t));
				/* Append 'next'. */
				memset(buf, 0, sizeof(uint16_t));
				write(nfd, buf, sizeof(uint16_t));
				
				/* Copy rest. */
				read(fd, buf, a(2*sizeof(uint32_t)));
				//*((uint32_t*)buf) += offs;
				write(nfd, buf, a(2*sizeof(uint32_t)));
				/* Copy padding. */
				read(fd, buf, PADDING);
				write(nfd, buf, PADDING);
			}
			
			/* Copy remaining. */
			while((rb = read(fd, buf, sizeof(buf))) > 0) {
				if (write(nfd, buf, rb) != rb) {
					ret = 1;
					break;
				}
			}
			/* Update CRC. */
			if (ret == 0) {
				journal_update_crc(nfd);
			}
		}
		
		/* Replace if success. */
		close(nfd);
		close(fd);
		if (ret == 0) {
			remove(fname);
			rename(nfname, fname);
			printf("Converted journal v1.0.1-> v1.0.2\n");
		}
		free(nfname);
	} else if (memcmp(mbytes, "knot102", MAGIC_LENGTH) == 0) {
		/* Update magic bytes. */
		const char nmbytes[] = "knot104";
		int nfd = open(fname, O_RDWR, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
		lseek(nfd, 0, SEEK_SET);
		write(nfd, nmbytes, MAGIC_LENGTH);
		journal_update_crc(nfd);
		close(nfd);
		printf("Converted journal v1.0.2-> v.1.0.4\n");
	} else if (memcmp(mbytes, "knot104", MAGIC_LENGTH) == 0) {
		/* Update magic bytes and add 4bytes to each journal node. */
		const char nmbytes[] = "knot105";
		int nfd = open(fname, O_RDWR, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
		lseek(nfd, 0, SEEK_SET);
		write(nfd, nmbytes, MAGIC_LENGTH);
		journal_update_crc(nfd);
		close(nfd);
		
		/* Fix crc. */
		fixcrc(fname);
		
		/* Open as source journal. */
		journal_t *src = journal_open(fname, 0, 0, 0);
		assert(src != NULL);
		
		/* Recreate as new journal. */
		char *nfname = malloc(strlen(fname) + 4 + 1);
		assert(nfname != NULL);
		strncpy(nfname, fname, strlen(fname));
		strncat(nfname, ".new", 4);
		journal_create(nfname, src->max_nodes);
		journal_t *dst = journal_open(nfname, 0, 0, 0);
		assert(dst != NULL);
		
		/* Convert journal entries, adding dummy flags. */
		uint32_t flags = 1;
		size_t i = src->qhead;
		for(; i != src->qtail; i = (i + 1) % src->max_nodes) {
			journal_node_t *n = src->nodes + i;
			char *ibuf = malloc(n->len + sizeof(uint32_t));
			memset(ibuf, &flags, sizeof(uint32_t));
			journal_read(src, n->id, NULL, ibuf + sizeof(uint32_t));
			journal_write(dst, n->id, ibuf, n->len + sizeof(uint32_t));
			free(ibuf);
		}
		journal_close(src);
		journal_close(dst);
		
		/* Switch journals. */
		remove(fname);
		rename(nfname, fname);
		free(nfname);
		printf("Converted journal v1.0.4-> v.1.0.5\n");
	} else {
		close(fd);
	}
	
	
	return ret;
}

/* Hexdump. */
int xdump(const char *fname, uint64_t id)
{
	/* Open journal. */
	journal_t *j = journal_open(fname, -1, 0, 0);
	if (j == NULL) {
		fprintf(stderr, "error: couldn't open journal '%s'\n", fname);
		return 1;
	}
	
	int ret = 1;
	journal_node_t *n = NULL;
	journal_fetch(j, id, NULL, &n);
	if (n != NULL) {
		char *buf = malloc(n->len);
		assert(buf != NULL);
		journal_read(j, id, NULL, buf);
		size_t rf = 0;
		while(rf < n->len) {
			if (rf % 16 == 0) printf("\n%08lx |", (unsigned long)rf);
			printf(" %02x", (unsigned)buf[rf] & 0xffU);
			++rf;
		}
		printf("\n");
		printf("-- index %llu fpos=%u length=%u\n",
		       (unsigned long long)id, n->pos, n->len);
		free(buf);
		ret = 0;
	}
	
	journal_close(j);
	return ret;
}

/* Hexdump. */
int dump(const char *fname, uint64_t id)
{
	/* Open journal. */
	journal_t *j = journal_open(fname, -1, 0, 0);
	if (j == NULL) {
		fprintf(stderr, "error: couldn't open journal '%s'\n", fname);
		return 1;
	}
	
	journal_node_t *n = NULL;
	journal_fetch(j, id, NULL, &n);
	if (n == NULL) {
		journal_close(j);
		return 1;
	}
	
	/* Reserve and read changeset. */
	knot_changesets_t* chsets = malloc(sizeof(knot_changesets_t));
	assert(chsets != NULL);
	memset(chsets, 0, sizeof(knot_changesets_t));
	chsets->count = 1;
	knot_changesets_check_size(chsets);
	assert(chsets->sets != NULL);
	knot_changeset_t *chs = chsets->sets;
	memset(chs, 0, sizeof(knot_changeset_t));
	chs->serial_from = ixfrdb_key_from(n->id);
	chs->serial_to = ixfrdb_key_to(n->id);
	chs->data = malloc(n->len);
	assert(chs->data != NULL);
	journal_read(j, n->id, NULL, chs->data);
	chs->size = chs->allocated = n->len;
	
	/* Unpack */
	int ks = zones_changesets_from_binary(chsets);
	printf("=== index %llu fpos=%u length=%u\n",
	       (unsigned long long)id, n->pos, n->len);
	
	/* TODO: dump wireformat? */
	printf("--- %zu records\n", chs->remove_count);
	for (unsigned i = 0; i < chs->remove_count; ++i) {
		knot_rrset_dump(chs->remove[i], 1);
	}
	printf("+++ %zu records\n", chs->add_count);
	for (unsigned i = 0; i < chs->add_count; ++i) {
		knot_rrset_dump(chs->add[i], 1);
	}
	printf("=== index %llu fpos=%u length=%u\n",
	       (unsigned long long)id, n->pos, n->len);

	/* Close. */
	//knot_free_changesets(&chsets);
	journal_close(j);
	return 0;
}

int main(int argc, char *argv[])
{
	/* Long options. */
	struct option opts[] = {
		{"padding",required_argument, 0, 'p'},
		{"align",  required_argument, 0, 'a'},
		{"fixcrc", no_argument,       0, 'f'},
		{"update", no_argument,       0, 'u'},
	        {"dump",   required_argument, 0, 'd'},
	        {"xdump",  required_argument, 0, 'x'},
		{"help",   no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};
	
	int c = 0, li = 0;
	int action = SHOW;
	uint64_t dump_id = 0;
	while ((c = getopt_long(argc, argv, "p:a:fuhd:x:", opts, &li)) != -1) {
		switch (c)
		{
		case 'p':
			PADDING = strtoull(optarg, NULL, 10);
			break;
		case 'a':
			ALIGNMENT = strtoull(optarg, NULL, 10);
			break;
		case 'f':
			action = FIXCRC;
			break;
		case 'u':
			action = UPDATE;
			break;
		case 'd':
			action = DUMP;
			dump_id = strtoull(optarg, NULL, 10);
			break;
		case 'x':
			action = XDUMP;
			dump_id = strtoull(optarg, NULL, 10);
			break;
		case 'h':
		case '?':
		default:
			help(argc, argv);
			return 1;
		}
	}
	
	/* Check if there's at least one remaining non-option. */
	if (argc - optind < 1) {
		help(argc, argv);
		return 1;
	}
	const char *fname = argv[optind];
	
	/* Init log. */
	log_init();
	log_levels_set(LOGT_SYSLOG, LOG_ANY, 0);
	log_levels_set(LOGT_STDERR, LOG_ANY, 0);
	log_levels_set(LOGT_STDOUT, LOG_ANY, ~0);
	
	/* Execute operation. */
	int ret = 0;
	switch(action) {
	case SHOW:
		ret = show(fname);
		break;
	case UPDATE:
		ret = update(fname);
		break;
	case FIXCRC:
		ret = fixcrc(fname);
		break;
	case DUMP:
		ret = dump(fname, dump_id);
		break;
	case XDUMP:
		ret = xdump(fname, dump_id);
		break;
	default:
		fprintf(stderr, "Unsupported operation.\n");
		break;
	}
	
	return ret;
}
