#include <string.h>
#include <stdlib.h>
#include <lmdb.h>
#include "knot/modules/dynzone.c"

static int dynzone_add(struct cache *cache, int argc, char *argv[]);
static int dynzone_del(struct cache *cache, int argc, char *argv[]);
static int dynzone_get(struct cache *cache, int argc, char *argv[]);
static int dynzone_list(struct cache *cache, int argc, char *argv[]);

struct tool_action {
	const char *name;
	int (*func)(struct cache *, int, char *[]);
	int min_args;
	const char *info;
};

#define TOOL_ACTION_COUNT 4
static struct tool_action TOOL_ACTION[TOOL_ACTION_COUNT] = {
{ "add",  dynzone_add, 4, "<zone> <ip> <threat_code> <syslog_ip>" },
{ "del",  dynzone_del, 1, "<zone>" },
{ "get",  dynzone_get, 1, "<zone>" },
{ "list", dynzone_list, 0, "" },
};

static int help(void)
{
	printf("Usage: dynzone_tool <dbdir> <action> [params]\n");
	printf("Actions:\n");
	for (unsigned i = 0; i < TOOL_ACTION_COUNT; ++i) {
		struct tool_action *ta = &TOOL_ACTION[i];
		printf("\t%s %s\n", ta->name, ta->info);
	}
	return 1;
}

int main(int argc, char *argv[])
{
	if (argc < 3) {
		return help();
	}

	/* Get mandatory parameters. */
	int ret = EXIT_FAILURE;
	char *dbdir  = argv[1];
	char *action = argv[2];
	argv += 3;
	argc -= 3;

	/* Open cache for operations. */
	struct cache *cache = cache_open(dbdir, 0, NULL);

	/* Execute action. */
	for (unsigned i = 0; i < TOOL_ACTION_COUNT; ++i) {
		struct tool_action *ta = &TOOL_ACTION[i];
		if (strcmp(ta->name, action) == 0) {

			/* Check param count. */
			if (argc < ta->min_args) {
				return help();
			}

			ret = ta->func(cache, argc, argv);
			if (ret != 0) {
				fprintf(stderr, "FAILED\n");
			}

			break;
		}
	}

	cache_close(cache);
	return ret;
}

static int dynzone_add(struct cache *cache, int argc, char *argv[])
{
	printf("ADD %s\t%s\t%s\t%s\n", argv[0], argv[1], argv[2], argv[3]);

	knot_dname_t *key = knot_dname_from_str(argv[0]);
	struct entry entry;
	entry.ip          = argv[1];
	entry.threat_code = argv[2];
	entry.syslog_ip   = argv[3];

	/* Check IPs. */
	struct sockaddr_storage addr;
	if (sockaddr_set(&addr, AF_INET, entry.ip, 0) != KNOT_EOK) {
		fprintf(stderr, "invalid address: '%s'\n", entry.ip);
		return KNOT_ERROR;
	}
	if (sockaddr_set(&addr, AF_INET, entry.syslog_ip, 0) != KNOT_EOK) {
		fprintf(stderr, "invalid address: '%s'\n", entry.syslog_ip);
		return KNOT_ERROR;
	}

	MDB_txn *txn = NULL;
	int ret = mdb_txn_begin(cache->env, NULL, 0, &txn);
	if (ret != 0) {
		return ret;
	}

	ret = cache_insert(txn, cache->dbi, key, &entry);

	mdb_txn_commit(txn);

	return ret;
}

static int dynzone_del(struct cache *cache, int argc, char *argv[])
{
	printf("DEL %s\n", argv[0]);

	MDB_txn *txn = NULL;
	int ret = mdb_txn_begin(cache->env, NULL, 0, &txn);
	if (ret != 0) {
		return ret;
	}

	knot_dname_t *key = knot_dname_from_str(argv[0]);
	ret = cache_remove(txn, cache->dbi, key);
	knot_dname_free(&key, NULL);

	mdb_txn_commit(txn);

	return ret;
}

static int dynzone_get(struct cache *cache, int argc, char *argv[])
{
	MDB_txn *txn = NULL;
	int ret = mdb_txn_begin(cache->env, NULL, MDB_RDONLY, &txn);
	if (ret != 0) {
		return ret;
	}

	struct entry entry;
	knot_dname_t *key = knot_dname_from_str(argv[0]);
	ret = cache_query_fetch(txn, cache->dbi, key, &entry);
	knot_dname_free(&key, NULL);
	if (ret == 0) {
		printf("%s\t%s\t%s\t%s\n", argv[0], entry.ip, entry.threat_code, entry.syslog_ip);
		cache_query_release(&entry);
	}

	mdb_txn_abort(txn);

	return ret;
}

static int dynzone_list(struct cache *cache, int argc, char *argv[])
{
	MDB_txn *txn = NULL;
	int ret = mdb_txn_begin(cache->env, NULL, MDB_RDONLY, &txn);
	if (ret != 0) {
		return ret;
	}

	MDB_cursor *cursor = cursor_acquire(txn, cache->dbi);
	MDB_val key, data;

	ret = mdb_cursor_get(cursor, &key, &data, MDB_FIRST);
	while (ret == 0) {
		struct entry entry;
		unpack_entry(&data, &entry);
		char *zone = knot_dname_to_str(key.mv_data);
		printf("%s\t%s\t%s\t%s\n", zone, entry.ip, entry.threat_code, entry.syslog_ip);
		free(zone);

		ret = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
	}

	cursor_release(cursor);
	mdb_txn_abort(txn);

	return KNOT_EOK;
}
