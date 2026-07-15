/* mdb_load.c - memory-mapped database load tool */
/*
 * Copyright 2011-2021 Howard Chu, Symas Corp.
 * Copyright 2026 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include "contrib/lmdb/mdb_load/mdb_load.h"
#include "lmdb.h"

typedef struct {
	size_t lineno;
	int version;
	int flags;
	int Eof;
	MDB_envinfo info;
	unsigned int pagesize;
} mdb_load_ctx_t;

#define STRLENOF(s)	(sizeof(s)-1)

typedef struct flagbit {
	int bit;
	char *name;
	int len;
} flagbit;

#define S(s)	s, STRLENOF(s)

static flagbit dbflags[] = {
	{ MDB_REVERSEKEY, S("reversekey") },
	{ MDB_DUPSORT, S("dupsort") },
	{ MDB_INTEGERKEY, S("integerkey") },
	{ MDB_DUPFIXED, S("dupfixed") },
	{ MDB_INTEGERDUP, S("integerdup") },
	{ MDB_REVERSEDUP, S("reversedup") },
	{ 0, NULL, 0 }
};

static int readhdr(FILE *in, MDB_val dbuf, char **subname, mdb_load_ctx_t *ctx)
{
	char *ptr;

	ctx->flags = 0;
	while (fgets(dbuf.mv_data, dbuf.mv_size, in) != NULL) {
		ctx->lineno++;
		if (!strncmp(dbuf.mv_data, "VERSION=", STRLENOF("VERSION="))) {
			ctx->version=atoi((char *)dbuf.mv_data+STRLENOF("VERSION="));
			if (ctx->version > 3) {
				return MDB_CORRUPTED;
			}
		} else if (!strncmp(dbuf.mv_data, "HEADER=END", STRLENOF("HEADER=END"))) {
			break;
		} else if (!strncmp(dbuf.mv_data, "format=", STRLENOF("format="))) {
			if (!strncmp((char *)dbuf.mv_data+STRLENOF("FORMAT="), "print", STRLENOF("print")))
				return MDB_INVALID;
			else if (strncmp((char *)dbuf.mv_data+STRLENOF("FORMAT="), "bytevalue", STRLENOF("bytevalue"))) {
				return MDB_CORRUPTED;
			}
		} else if (!strncmp(dbuf.mv_data, "database=", STRLENOF("database="))) {
			ptr = memchr(dbuf.mv_data, '\n', dbuf.mv_size);
			if (ptr) *ptr = '\0';
			if (*subname) free(*subname);
			*subname = strdup((char *)dbuf.mv_data+STRLENOF("database="));
		} else if (!strncmp(dbuf.mv_data, "type=", STRLENOF("type="))) {
			if (strncmp((char *)dbuf.mv_data+STRLENOF("type="), "btree", STRLENOF("btree")))  {
				return MDB_CORRUPTED;
			}
		} else if (!strncmp(dbuf.mv_data, "mapaddr=", STRLENOF("mapaddr="))) {
			int i;
			ptr = memchr(dbuf.mv_data, '\n', dbuf.mv_size);
			if (ptr) *ptr = '\0';
			i = sscanf((char *)dbuf.mv_data+STRLENOF("mapaddr="), "%p", &ctx->info.me_mapaddr);
			if (i != 1) {
				return MDB_CORRUPTED;
			}
		} else if (!strncmp(dbuf.mv_data, "mapsize=", STRLENOF("mapsize="))) {
			int i;
			ptr = memchr(dbuf.mv_data, '\n', dbuf.mv_size);
			if (ptr) *ptr = '\0';
			i = sscanf((char *)dbuf.mv_data+STRLENOF("mapsize="), "%zu", &ctx->info.me_mapsize);
			if (i != 1) {
				return MDB_CORRUPTED;
			}
		} else if (!strncmp(dbuf.mv_data, "maxreaders=", STRLENOF("maxreaders="))) {
			int i;
			ptr = memchr(dbuf.mv_data, '\n', dbuf.mv_size);
			if (ptr) *ptr = '\0';
			i = sscanf((char *)dbuf.mv_data+STRLENOF("maxreaders="), "%u", &ctx->info.me_maxreaders);
			if (i != 1) {
				return MDB_CORRUPTED;
			}
		} else if (!strncmp(dbuf.mv_data, "db_pagesize=", STRLENOF("db_pagesize="))) {
			int i;
			ptr = memchr(dbuf.mv_data, '\n', dbuf.mv_size);
			if (ptr) *ptr = '\0';
			i = sscanf((char *)dbuf.mv_data+STRLENOF("db_pagesize="), "%u", &ctx->pagesize);
			if (i != 1) {
				return MDB_CORRUPTED;
			}
		} else {
			int i;
			for (i=0; dbflags[i].bit; i++) {
				if (!strncmp(dbuf.mv_data, dbflags[i].name, dbflags[i].len) &&
					((char *)dbuf.mv_data)[dbflags[i].len] == '=') {
					ctx->flags |= dbflags[i].bit;
					break;
				}
			}
			if (!dbflags[i].bit) {
				ptr = memchr(dbuf.mv_data, '=', dbuf.mv_size);
				if (!ptr) {
					return MDB_CORRUPTED;
				} else {
					*ptr = '\0';
				}
			}
		}
	}

	return MDB_SUCCESS;
}

static int unhex(unsigned char *c2)
{
	int x, c;
	x = *c2++ & 0x4f;
	if (x & 0x40)
		x -= 55;
	c = x << 4;
	x = *c2 & 0x4f;
	if (x & 0x40)
		x -= 55;
	c |= x;
	return c;
}

static int readline(MDB_val *out, MDB_val *buf, FILE *in, mdb_load_ctx_t *ctx)
{
	unsigned char *c1, *c2, *end;
	size_t len, l2;
	int c;

	c = fgetc(in);
	if (c == EOF) {
		ctx->Eof = 1;
		return EOF;
	}
	if (c != ' ') {
		ctx->lineno++;
		if (fgets(buf->mv_data, buf->mv_size, in) == NULL) {
badend:
			ctx->Eof = 1;
			return EOF;
		}
		if (c == 'D' && !strncmp(buf->mv_data, "ATA=END", STRLENOF("ATA=END")))
			return EOF;
		goto badend;
	}

	if (fgets(buf->mv_data, buf->mv_size, in) == NULL) {
		ctx->Eof = 1;
		return EOF;
	}
	ctx->lineno++;

	c1 = buf->mv_data;
	len = strlen((char *)c1);
	if (!len) {
		/* This can only happen with an intentionally invalid input
		 * with a NUL byte after the leading SPACE
		 */
		goto badend;
	}
	l2 = len;

	/* Is buffer too short? */
	while (c1[len-1] != '\n') {
		buf->mv_data = realloc(buf->mv_data, buf->mv_size*2);
		if (!buf->mv_data) {
			ctx->Eof = 1;
			return EOF;
		}
		c1 = buf->mv_data;
		c1 += l2;
		if (fgets((char *)c1, buf->mv_size+1, in) == NULL) {
			ctx->Eof = 1;
			return EOF;
		}
		buf->mv_size *= 2;
		len = strlen((char *)c1);
		l2 += len;
	}
	c1 = c2 = buf->mv_data;
	len = l2;
	c1[--len] = '\0';
	end = c1 + len;

	/* odd length not allowed */
	if (len & 1) {
		ctx->Eof = 1;
		return EOF;
	}
	while (c2 < end) {
		if (!isxdigit(*c2) || !isxdigit(c2[1])) {
			ctx->Eof = 1;
			return EOF;
		}
		*c1++ = unhex(c2);
		c2 += 2;
	}

	c2 = out->mv_data = buf->mv_data;
	out->mv_size = c1 - c2;

	return 0;
}

static int greater(const MDB_val *a, const MDB_val *b)
{
	return 1;
}

int mdb_load(const char *db_path, FILE *in)
{
	int rc;
	MDB_env *env;
	MDB_txn *txn;
	MDB_cursor *mc;
	MDB_dbi dbi;
	const char *envname;
	char *subname = NULL;
	int envflags = MDB_NOSYNC, putflags = 0;
	int dohdr = 0, append = 0;
	MDB_val kbuf = { 0 }, dbuf;
	MDB_val k0buf;
	MDB_val prevk;

	mdb_load_ctx_t ctx = { 0 };
	envname = db_path;

	dbuf.mv_size = 4096;
	dbuf.mv_data = malloc(dbuf.mv_size);

	rc = readhdr(in, dbuf, &subname, &ctx);
	if (rc) {
		goto cleanup;
	}

	rc = mdb_env_create(&env);
	if (rc) {
		goto cleanup;
	}

	mdb_env_set_maxdbs(env, 2);

	if (ctx.info.me_maxreaders)
		mdb_env_set_maxreaders(env, ctx.info.me_maxreaders);

	if (ctx.info.me_mapsize)
		mdb_env_set_mapsize(env, ctx.info.me_mapsize);

#if MDB_VERSION_MAJOR > 0
	if (ctx.pagesize)
		mdb_env_set_pagesize(env, ctx.pagesize);
#endif

	if (ctx.info.me_mapaddr)
		envflags |= MDB_FIXEDMAP;

	rc = mdb_env_open(env, envname, envflags, 0664);
	if (rc) {
		goto env_close;
	}

	kbuf.mv_size = mdb_env_get_maxkeysize(env) * 2 + 2;
	kbuf.mv_data = malloc(kbuf.mv_size * 2);
	k0buf.mv_size = kbuf.mv_size;
	k0buf.mv_data = (char *)kbuf.mv_data + kbuf.mv_size;
	prevk.mv_data = k0buf.mv_data;

	while(!ctx.Eof) {
		MDB_val key, data;
		int batch = 0;
		int appflag;

		if (!dohdr) {
			dohdr = 1;
		} else {
			rc = readhdr(in, dbuf, &subname, &ctx);
			if (rc)
				goto env_close;
		}

		rc = mdb_txn_begin(env, NULL, 0, &txn);
		if (rc) {
			goto env_close;
		}

		rc = mdb_dbi_open(txn, subname, ctx.flags|MDB_CREATE, &dbi);
		if (rc) {
			goto txn_abort;
		}
		prevk.mv_size = 0;
		if (append) {
			mdb_set_compare(txn, dbi, greater);
			if (ctx.flags & MDB_DUPSORT)
				mdb_set_dupsort(txn, dbi, greater);
		}

		rc = mdb_cursor_open(txn, dbi, &mc);
		if (rc) {
			goto txn_abort;
		}

		while(1) {
			rc = readline(&key, &kbuf, in, &ctx);
			if (rc)  /* rc == EOF */
				break;

			rc = readline(&data, &dbuf, in, &ctx);
			if (rc) {
				goto txn_abort;
			}
			if (!key.mv_size) {
				continue;
			}

			if (append) {
				appflag = MDB_APPEND;
				if (ctx.flags & MDB_DUPSORT) {
					if (prevk.mv_size == key.mv_size && !memcmp(prevk.mv_data, key.mv_data, key.mv_size))
						appflag = MDB_CURRENT|MDB_APPENDDUP;
					else {
						memcpy(prevk.mv_data, key.mv_data, key.mv_size);
						prevk.mv_size = key.mv_size;
					}
				}
			} else {
				appflag = 0;
			}
			rc = mdb_cursor_put(mc, &key, &data, putflags|appflag);
			if (rc == MDB_KEYEXIST && putflags)
				continue;
			if (rc) {
				goto txn_abort;
			}
			batch++;
			if (batch == 100) {
				rc = mdb_txn_commit(txn);
				if (rc) {
					goto env_close;
				}
				rc = mdb_txn_begin(env, NULL, 0, &txn);
				if (rc) {
					goto env_close;
				}
				rc = mdb_cursor_open(txn, dbi, &mc);
				if (rc) {
					goto txn_abort;
				}
				if (append) {
					MDB_val k, d;
					mdb_cursor_get(mc, &k, &d, MDB_LAST);
					memcpy(prevk.mv_data, k.mv_data, k.mv_size);
					prevk.mv_size = k.mv_size;
				}
				batch = 0;
			}
		}
		rc = mdb_txn_commit(txn);
		txn = NULL;
		if (rc) {
			goto env_close;
		}
		if (envflags & MDB_NOSYNC) {
			rc = mdb_env_sync(env, 1);
			if (rc) {
				goto env_close;
			}
		}
		mdb_dbi_close(env, dbi);
	}

txn_abort:
	mdb_txn_abort(txn);
env_close:
	mdb_env_close(env);
cleanup:
	free(dbuf.mv_data);
	free(kbuf.mv_data);
	free(subname);

	return rc;
}
