/* mdb_dump.c - memory-mapped database dump tool */
/*
 * Copyright 2011-2021 Howard Chu, Symas Corp.
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
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include "contrib/lmdb/mdb_dump/mdb_dump.h"
#include "contrib/lmdb/lmdb.h"

typedef struct flagbit {
	int bit;
	char *name;
} flagbit;

static flagbit dbflags[] = {
	{ MDB_REVERSEKEY, "reversekey" },
	{ MDB_DUPSORT, "dupsort" },
	{ MDB_INTEGERKEY, "integerkey" },
	{ MDB_DUPFIXED, "dupfixed" },
	{ MDB_INTEGERDUP, "integerdup" },
	{ MDB_REVERSEDUP, "reversedup" },
	{ 0, NULL }
};

static const char hexc[] = "0123456789abcdef";

static void hex(unsigned char c, FILE *out)
{
	putc(hexc[c >> 4], out);
	putc(hexc[c & 0xf], out);
}

static void byte(MDB_val *v, FILE *out)
{
	unsigned char *c, *end;

	putc(' ', out);
	c = v->mv_data;
	end = c + v->mv_size;
	while (c < end) {
		hex(*c++, out);
	}
	putc('\n', out);
}

/* Dump in BDB-compatible format */
static int dumpit(MDB_txn *txn, MDB_dbi dbi, char *name, FILE *out)
{
	MDB_cursor *mc;
	MDB_stat ms;
	MDB_val key, data;
	MDB_envinfo info;
	unsigned int flags;
	int rc, i;

	rc = mdb_dbi_flags(txn, dbi, &flags);
	if (rc) return rc;

	rc = mdb_stat(txn, dbi, &ms);
	if (rc) return rc;

	rc = mdb_env_info(mdb_txn_env(txn), &info);
	if (rc) return rc;

	fprintf(out, "VERSION=3\n");
	fprintf(out, "format=%s\n", "bytevalue");
	if (name)
		fprintf(out, "database=%s\n", name);
	fprintf(out, "type=btree\n");
	fprintf(out, "mapsize=%zu\n", info.me_mapsize);
	if (info.me_mapaddr)
		fprintf(out, "mapaddr=%p\n", info.me_mapaddr);
	fprintf(out, "maxreaders=%u\n", info.me_maxreaders);

	if (flags & MDB_DUPSORT)
		fprintf(out, "duplicates=1\n");

	for (i=0; dbflags[i].bit; i++)
		if (flags & dbflags[i].bit)
			fprintf(out, "%s=1\n", dbflags[i].name);

	fprintf(out, "db_pagesize=%d\n", ms.ms_psize);
	fprintf(out, "HEADER=END\n");

	rc = mdb_cursor_open(txn, dbi, &mc);
	if (rc) return rc;

	while ((rc = mdb_cursor_get(mc, &key, &data, MDB_NEXT) == MDB_SUCCESS)) {
		byte(&key, out);
		byte(&data, out);
	}

	mdb_cursor_close(mc);

	fprintf(out, "DATA=END\n");
	if (rc == MDB_NOTFOUND)
		rc = MDB_SUCCESS;

	return rc;
}

int mdb_dump(const char *db_path, FILE *out, bool alldbs)
{
	int rc;
	MDB_env *env;
	MDB_txn *txn;
	MDB_dbi dbi;
	const char *envname;
	char *subname = NULL;
	int envflags = 0, list = 0;

	envname = db_path;

	rc = mdb_env_create(&env);
	if (rc) {
		return rc;
	}

	if (alldbs || subname) {
		mdb_env_set_maxdbs(env, 2);
	}

	rc = mdb_env_open(env, envname, envflags | MDB_RDONLY, 0664);
	if (rc) {
		goto env_close;
	}

	rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
	if (rc) {
		goto env_close;
	}

	rc = mdb_open(txn, subname, 0, &dbi);
	if (rc) {
		goto txn_abort;
	}

	if (alldbs) {
		MDB_cursor *cursor;
		MDB_val key;
		int count = 0;

		rc = mdb_cursor_open(txn, dbi, &cursor);
		if (rc) {
			goto txn_abort;
		}
		while ((rc = mdb_cursor_get(cursor, &key, NULL, MDB_NEXT_NODUP)) == 0) {
			char *str;
			MDB_dbi db2;
			if (memchr(key.mv_data, '\0', key.mv_size))
				continue;
			count++;
			str = malloc(key.mv_size+1);
			memcpy(str, key.mv_data, key.mv_size);
			str[key.mv_size] = '\0';
			rc = mdb_open(txn, str, 0, &db2);
			if (rc == MDB_SUCCESS) {
				if (list) {
					list++;
				} else {
					rc = dumpit(txn, db2, str, out);
					if (rc)
						break;
				}
				mdb_close(env, db2);
			}
			free(str);
			if (rc) continue;
		}
		mdb_cursor_close(cursor);
		if (!count) {
			rc = MDB_NOTFOUND;
		} else if (rc == MDB_NOTFOUND) {
			rc = MDB_SUCCESS;
		}
	} else {
		rc = dumpit(txn, dbi, subname, out);
	}

	mdb_close(env, dbi);
txn_abort:
	mdb_txn_abort(txn);
env_close:
	mdb_env_close(env);

	return rc;
}
