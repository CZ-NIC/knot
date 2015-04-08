#include <string.h>
#include <stdlib.h>

#include "knot/modules/rosedb.c"
#include "zscanner/scanner.h"
#include "libknot/libknot.h"
#include "common/mem.h"
#include "common/getline.h"

static int rosedb_add(struct cache *cache, MDB_txn *txn, int argc, char *argv[]);
static int rosedb_del(struct cache *cache, MDB_txn *txn, int argc, char *argv[]);
static int rosedb_get(struct cache *cache, MDB_txn *txn, int argc, char *argv[]);
static int rosedb_list(struct cache *cache, MDB_txn *txn, int argc, char *argv[]);
static int rosedb_import(struct cache *cache, MDB_txn *txn, int argc, char *argv[]);

struct tool_action {
	const char *name;
	int (*func)(struct cache *, MDB_txn *, int, char *[]);
	int min_args;
	const char *info;
};

#define TOOL_ACTION_MAXARG 7
#define TOOL_ACTION_COUNT 5
static struct tool_action TOOL_ACTION[TOOL_ACTION_COUNT] = {
{ "add",    rosedb_add,    6, "<zone> <rrtype> <ttl> <rdata> <threat_code> <syslog_ip>" },
{ "del",    rosedb_del,    1, "<zone> [rrtype]" },
{ "get",    rosedb_get,    1, "<zone> [rrtype]" },
{ "import", rosedb_import, 1, "<file>" },
{ "list",   rosedb_list,   0, "" }
};

static int help(void)
{
	printf("Usage: rosedb_tool <dbdir> <action> [params]\n");
	printf("Actions:\n");
	for (unsigned i = 0; i < TOOL_ACTION_COUNT; ++i) {
		struct tool_action *ta = &TOOL_ACTION[i];
		printf("\t%s %s\n", ta->name, ta->info);
	}
	return EXIT_FAILURE;
}

/* Global instance of RR scanner. */
static void parse_err(zs_scanner_t *s) {
	fprintf(stderr, "failed to parse RDATA: %s\n", zs_strerror(s->error_code));
}
static zs_scanner_t *g_scanner = NULL;

int main(int argc, char *argv[])
{
	if (argc < 3) {
		return help();
	}

	/* Get mandatory parameters. */
	int ret = EXIT_SUCCESS;
	char *dbdir  = argv[1];
	char *action = argv[2];
	argv += 3;
	argc -= 3;

	g_scanner = zs_scanner_create(".", KNOT_CLASS_IN, 0, NULL, parse_err, NULL);
	if (g_scanner == NULL) {
		return EXIT_FAILURE;
	}

	/* Open cache for operations. */
	struct cache *cache = cache_open(dbdir, 0, NULL);
	if (cache == NULL) {
		fprintf(stderr, "failed to open db '%s'\n", dbdir);
		zs_scanner_free(g_scanner);
		return EXIT_FAILURE;
	}

	/* Execute action. */
	bool found = false;
	for (unsigned i = 0; i < TOOL_ACTION_COUNT; ++i) {
		struct tool_action *ta = &TOOL_ACTION[i];
		if (strcmp(ta->name, action) == 0) {

			/* Check param count. */
			if (argc < ta->min_args) {
				break;
			}

			/* Now set as found. */
			found = true;

			MDB_txn *txn = NULL;
			int ret = mdb_txn_begin(cache->env, NULL, 0, &txn);
			if (ret != MDB_SUCCESS) {
				fprintf(stderr, "failed to open transaction, aborting\n");
				break;
			}

			/* Execute operation handler. */
			ret = ta->func(cache, txn, argc, argv);
			if (ret != 0) {
				fprintf(stderr, "'%s' failed, aborting transaction\n", action);
				mdb_txn_abort(txn);
			} else {
				mdb_txn_commit(txn);
			}

			break;
		}
	}

	cache_close(cache);
	zs_scanner_free(g_scanner);

	if (!found) {
		return help();
	}

	return ret;
}

static int parse_rdata(struct entry *entry, const char *owner, const char *rrtype, const char *rdata,
		       int ttl, mm_ctx_t *mm)
{
	knot_rdataset_init(&entry->data.rrs);
	int ret = knot_rrtype_from_string(rrtype, &entry->data.type);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Synthetize RR line */
	char *rr_line = sprintf_alloc("%s %u IN %s %s\n", owner, ttl, rrtype, rdata);
	ret = zs_scanner_parse(g_scanner, rr_line, rr_line + strlen(rr_line), true);
	free(rr_line);

	/* Write parsed RDATA. */
	if (ret == KNOT_EOK) {
		knot_rdata_t rr[knot_rdata_array_size(g_scanner->r_data_length)];
		knot_rdata_init(rr, g_scanner->r_data_length, g_scanner->r_data, ttl);
		ret = knot_rdataset_add(&entry->data.rrs, rr, mm);
	}

	return ret;
}

static int rosedb_add(struct cache *cache, MDB_txn *txn, int argc, char *argv[])
{
	printf("ADD %s\t%s\t%s\t%s\t%s\t%s\n", argv[0], argv[1], argv[2], argv[3], argv[4], argv[5]);

	knot_dname_t key[KNOT_DNAME_MAXLEN] = { '\0' };
	knot_dname_from_str(key, argv[0], sizeof(key));
	knot_dname_to_lower(key);

	struct entry entry;
	int ret = parse_rdata(&entry, argv[0], argv[1], argv[3], atoi(argv[2]), cache->pool);
	entry.threat_code = argv[4];
	entry.syslog_ip   = argv[5];
	if (ret != 0) {
		fprintf(stderr, "PARSE: %s\n", knot_strerror(ret));
		return ret;
	}

	ret = cache_insert(txn, cache->dbi, key, &entry);
	if (ret != 0) {
		fprintf(stderr, "%s\n", mdb_strerror(ret));
	}

	return ret;
}

static int rosedb_del(struct cache *cache, MDB_txn *txn, int argc, char *argv[])
{
	printf("DEL %s\n", argv[0]);

	knot_dname_t key[KNOT_DNAME_MAXLEN] = { '\0' };
	knot_dname_from_str(key, argv[0], sizeof(key));
	knot_dname_to_lower(key);

	int ret = cache_remove(txn, cache->dbi, key);
	if (ret != 0) {
		fprintf(stderr, "%s\n", mdb_strerror(ret));
	}

	return ret;
}

static int rosedb_get(struct cache *cache, MDB_txn *txn, int argc, char *argv[])
{
	knot_dname_t key[KNOT_DNAME_MAXLEN] = { '\0' };
	knot_dname_from_str(key, argv[0], sizeof(key));
	knot_dname_to_lower(key);

	char type_str[16] = { '\0' };

	struct iter it;
	int ret = cache_query_fetch(txn, cache->dbi, &it, key);
	while (ret == 0) {
		struct entry entry;
		cache_iter_val(&it, &entry);
		knot_rdata_t *rd = knot_rdataset_at(&entry.data.rrs, 0);
		knot_rrtype_to_string(entry.data.type, type_str, sizeof(type_str));
		printf("%s\t%s\tTTL=%u\tRDLEN=%u\t%s\t%s\n", argv[0], type_str,
		       knot_rdata_ttl(rd), knot_rdata_rdlen(rd), entry.threat_code, entry.syslog_ip);
		if (cache_iter_next(&it) != 0) {
			break;
		}
	}

	cache_iter_free(&it);

	return ret;
}

static int rosedb_list(struct cache *cache, MDB_txn *txn, int argc, char *argv[])
{
	MDB_cursor *cursor = cursor_acquire(txn, cache->dbi);
	MDB_val key, data;
	char dname_str[KNOT_DNAME_MAXLEN] = {'\0'};
	char type_str[16] = { '\0' };

	int ret = mdb_cursor_get(cursor, &key, &data, MDB_FIRST);
	while (ret == 0) {
		struct entry entry;
		unpack_entry(&data, &entry);
		knot_dname_to_str(dname_str, key.mv_data, sizeof(dname_str));
		knot_rrtype_to_string(entry.data.type, type_str, sizeof(type_str));
		printf("%s\t%s RDATA=%zuB\t%s\t%s\n", dname_str, type_str,
		       knot_rdataset_size(&entry.data.rrs), entry.threat_code, entry.syslog_ip);

		ret = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
	}

	cursor_release(cursor);

	return KNOT_EOK;
}

static char *trim(char *line)
{
	int last = strlen(line) - 1;
	if (line[last] == '\n') {
		line[last] = '\0';
		last -= 1;
	}
	if (*line == '"') {
		line[last] = '\0';
		line += 1;
	}

	return line;
}

static int rosedb_import_line(struct cache *cache, MDB_txn *txn, char *line, const char *file, int lineno)
{
	int ret = 0;
	int argc = 0;
	char *argv[TOOL_ACTION_MAXARG];

	/* Tokenize */
	char *saveptr = line;
	char *token = NULL;
	while ((token = strtok_r(saveptr, ";\t", &saveptr)) != NULL) {
		token = trim(token);
		if (*token == '\0') {
			continue;
		}
		if (argc <= TOOL_ACTION_MAXARG) {
			argv[argc] = token;
			argc += 1;
		} else {
			fprintf(stderr, "%s#%d command '%s' - too much parameters (%d)\n",
			        file, lineno, line, argc);
			return KNOT_EPARSEFAIL;
		}
	}

	if (argc < 1) {
		fprintf(stderr, "%s#%d command '%s' - command not recognized\n", file, lineno, line);
		return KNOT_EOK; /* Ignore NOOP */
	}

	/* Execute action. */
	bool found = false;
	for (unsigned i = 0; i < TOOL_ACTION_COUNT; ++i) {
		struct tool_action *ta = &TOOL_ACTION[i];
		if (strcmp(ta->name, argv[0]) == 0) {
			if (argc < ta->min_args) {
				return help();
			}
			found = true;
			ret = ta->func(cache, txn, argc - 1, argv + 1);
			break;
		}
	}
	if (!found) {
		fprintf(stderr, "%s#%d command '%s' - command not recognized\n", file, lineno, line);
		return KNOT_EPARSEFAIL;
	}

	return ret;
}

static int rosedb_import(struct cache *cache, MDB_txn *txn, int argc, char *argv[])
{
	printf("IMPORT %s\n", argv[0]);

	int ret = 0;
	char *line = NULL;
	int lineno = 0;
	size_t line_len = 0;
	FILE *fp = fopen(argv[0], "r");
	if (fp == NULL) {
		return KNOT_ENOENT;
	}

	while (knot_getline(&line, &line_len, fp) != -1) {
		lineno += 1;
		ret = rosedb_import_line(cache, txn, line, argv[0], lineno);
		if (ret != 0) {
			break;
		}
	}

	free(line);
	fclose(fp);

	return ret;
}
