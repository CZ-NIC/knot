/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <pthread.h>

#include "libknot/libknot.h"
#include "libknot/yparser/ypschema.h"
#include "contrib/qp-trie/trie.h"
#include "contrib/ucw/lists.h"
#include "libknot/dynarray.h"
#include "knot/include/module.h"

/*! Default template identifier. */
#define CONF_DEFAULT_ID		((uint8_t *)"\x08""default\0")
/*! Default configuration file. */
#define CONF_DEFAULT_FILE	(CONFIG_DIR "/knot.conf")
/*! Default configuration database. */
#define CONF_DEFAULT_DBDIR	(STORAGE_DIR "/confdb")
/*! Maximum depth of nested transactions. */
#define CONF_MAX_TXN_DEPTH	5

/*! Maximum number of UDP workers. */
#define CONF_MAX_UDP_WORKERS	256
/*! Maximum number of TCP workers. */
#define CONF_MAX_TCP_WORKERS	256
/*! Maximum number of background workers. */
#define CONF_MAX_BG_WORKERS	512
/*! Maximum number of concurrent DB readers. */
#define CONF_MAX_DB_READERS	(CONF_MAX_UDP_WORKERS + CONF_MAX_TCP_WORKERS + \
				 CONF_MAX_BG_WORKERS + 10 + 128 /* Utils, XDP workers */)

/*! Configuration specific logging. */
#define CONF_LOG(severity, msg, ...) do { \
	log_fmt(severity, LOG_SOURCE_SERVER, "config, " msg, ##__VA_ARGS__); \
	} while (0)

#define CONF_LOG_ZONE(severity, zone, msg, ...) do { \
	log_fmt_zone(severity, LOG_SOURCE_ZONE, zone, NULL, "config, " msg, ##__VA_ARGS__); \
	} while (0)

/*! Configuration getter output. */
typedef struct {
	/*! Item description. */
	const yp_item_t *item;
	/*! Whole data (can be array). */
	const uint8_t *blob;
	/*! Whole data length. */
	size_t blob_len;
	// Public items.
	/*! Current single data. */
	const uint8_t *data;
	/*! Current single data length. */
	size_t len;
	/*! Value getter return code. */
	int code;
} conf_val_t;

/*! Shared module types. */
typedef enum {
	/*! Static module. */
	MOD_STATIC = 0,
	/*! Implicit shared module which is always loaded. */
	MOD_IMPLICIT,
	/*! Explicit shared module which is currently loaded. */
	MOD_EXPLICIT,
	/*! Explicit shared temporary module which is loaded during config check. */
	MOD_TEMPORARY
} module_type_t;

/*! Query module context. */
typedef struct {
	/*! Module interface. */
	const knotd_mod_api_t *api;
	/*! Shared library dlopen handler. */
	void *lib_handle;
	/*! Module type. */
	module_type_t type;
} module_t;

/*! Configuration import flags. */
typedef enum {
	/*! Input string is a filename. */
	IMPORT_FILE         = 1 << 0,
	/*! Cache reinitialization is needed. */
	IMPORT_REINIT_CACHE = 1 << 1,
	/*! Don't purge the confdb if non-empty before the import. */
	IMPORT_NO_PURGE     = 1 << 2,
} import_flag_t;

knot_dynarray_declare(mod, module_t *, DYNARRAY_VISIBILITY_NORMAL, 16)
knot_dynarray_declare(old_schema, yp_item_t *, DYNARRAY_VISIBILITY_NORMAL, 16)

struct knot_catalog;

/*! Configuration context. */
typedef struct {
	/*! Cloned configuration indicator. */
	bool is_clone;
	/*! Currently used namedb api. */
	const struct knot_db_api *api;
	/*! Configuration schema. */
	yp_item_t *schema;
	/*! Configuration database. */
	knot_db_t *db;
	/*! LMDB mapsize. */
	size_t mapsize;

	/*! Read-only transaction for config access. */
	knot_db_txn_t read_txn;

	struct {
		/*! The current writing transaction. */
		knot_db_txn_t *txn;
		/*! Stack of nested writing transactions. */
		knot_db_txn_t txn_stack[CONF_MAX_TXN_DEPTH];
		/*! Master transaction flags. */
		yp_flag_t flags;
		/*! Changed zones. */
		trie_t *zones;
		/*! Thread that initiated the txn (should access it exclusively). */
		pthread_t thread_id;
	} io;

	/*! Current config file (for reload if started with config file). */
	char *filename;

	/*! Prearranged hostname string (for automatic NSID or CH ident value). */
	char *hostname;

	/*! Cached critical confdb items. */
	struct {
		uint16_t srv_udp_max_payload_ipv4;
		uint16_t srv_udp_max_payload_ipv6;
		int srv_tcp_idle_timeout;
		int srv_tcp_io_timeout;
		int srv_tcp_remote_io_timeout;
		size_t srv_udp_threads;
		size_t srv_tcp_threads;
		size_t srv_xdp_threads;
		size_t srv_bg_threads;
		size_t srv_tcp_max_clients;
		size_t xdp_tcp_max_clients;
		size_t xdp_tcp_inbuf_max_size;
		size_t xdp_tcp_outbuf_max_size;
		unsigned srv_dbus_event;
		uint32_t xdp_tcp_idle_close;
		uint32_t xdp_tcp_idle_reset;
		uint32_t xdp_tcp_idle_resend;
		size_t srv_quic_max_clients;
		size_t srv_quic_obuf_max_size;
		const uint8_t *srv_nsid_data;
		size_t srv_nsid_len;
		const char *srv_ident;
		const char *srv_version;
		uint32_t srv_quic_idle_close;
		uint16_t xdp_quic;
		uint16_t xdp_ring_size;
		uint16_t xdp_busypoll_budget;
		uint16_t xdp_busypoll_timeout;
		int ctl_timeout;
		bool xdp_udp;
		bool xdp_tcp;
		bool xdp_route_check;
		bool srv_tcp_reuseport;
		bool srv_tcp_fastopen;
		bool srv_socket_affinity;
		bool srv_ecs;
		bool srv_ans_rotate;
		bool srv_auto_acl;
		bool srv_proxy_enabled;
		bool srv_has_version;
	} cache;

	/*! List of dynamically loaded modules. */
	mod_dynarray_t modules;
	/*! List of old schemas (lazy freed). */
	old_schema_dynarray_t old_schemas;
	/*! List of active query modules. */
	list_t *query_modules;
	/*! Default query modules plan. */
	struct query_plan *query_plan;
	/*! Zone catalog database. */
	struct catalog *catalog;
} conf_t;

/*!
 * Configuration access flags.
 */
typedef enum {
	CONF_FNONE       = 0,      /*!< Empty flag. */
	CONF_FREADONLY   = 1 << 0, /*!< Read only access. */
	CONF_FNOCHECK    = 1 << 1, /*!< Disabled confdb check. */
	CONF_FNOHOSTNAME = 1 << 2, /*!< Don't set the hostname. */
	CONF_FREQMODULES = 1 << 3, /*!< Load module schemas (must succeed). */
	CONF_FOPTMODULES = 1 << 4, /*!< Load module schemas (may fail). */
} conf_flag_t;

/*!
 * Configuration update flags.
 */
typedef enum {
	CONF_UPD_FNONE    = 0,      /*!< Empty flag. */
	CONF_UPD_FNOFREE  = 1 << 0, /*!< Disable auto-free of previous config. */
	CONF_UPD_FMODULES = 1 << 1, /*!< Reuse previous global modules. */
	CONF_UPD_FCONFIO  = 1 << 2, /*!< Reuse previous confio reload context. */
} conf_update_flag_t;

/*!
 * Returns the active configuration.
 */
conf_t* conf(void);

/*!
 * Refreshes common read-only transaction.
 *
 * \param[in] conf  Configuration.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_refresh_txn(
	conf_t *conf
);

/*!
 * Creates new or opens old configuration database.
 *
 * \param[out] conf          Configuration.
 * \param[in] schema         Configuration schema.
 * \param[in] db_dir         Database path or NULL.
 * \param[in] max_conf_size  Maximum configuration DB size in bytes (LMDB mapsize).
 * \param[in] flags          Access flags.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_new(
	conf_t **conf,
	const yp_item_t *schema,
	const char *db_dir,
	size_t max_conf_size,
	conf_flag_t flags
);

/*!
 * Creates a partial copy of the active configuration.
 *
 * Shared objects: api, mm, db, filename.
 *
 * \param[out] conf  Configuration.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_clone(
	conf_t **conf
);

/*!
 * Replaces the active configuration with the specified one.
 *
 * \param[in] conf   New configuration.
 * \param[in] flags  Update flags.
 *
 * \return Previous config if CONF_UPD_FNOFREE, else NULL.
 */
conf_t *conf_update(
	conf_t *conf,
	conf_update_flag_t flags
);

/*!
 * Removes the specified configuration.
 *
 * \param[in] conf  Configuration.
 */
void conf_free(
	conf_t *conf
);

/*!
 * Parses textual configuration from the string or from the file.
 *
 * This function is not for direct using, just for includes processing!
 *
 * \param[in] conf     Configuration.
 * \param[in] txn      Transaction.
 * \param[in] input    Configuration string or filename.
 * \param[in] is_file  Specifies if the input is string or input filename.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_parse(
	conf_t *conf,
	knot_db_txn_t *txn,
	const char *input,
	bool is_file
);

/*!
 * Imports textual configuration.
 *
 * \param[in] conf   Configuration.
 * \param[in] input  Configuration string or input filename.
 * \param[in] flags  Import flags.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_import(
	conf_t *conf,
	const char *input,
	import_flag_t flags
);

/*!
 * Exports configuration to textual file.
 *
 * \param[in] conf       Configuration.
 * \param[in] file_name  Output filename (stdout is used if NULL).
 * \param[in] style      Formatting style.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_export(
	conf_t *conf,
	const char *file_name,
	yp_style_t style
);

/*!
 * Exports configuration schema in JSON.
 *
 * \param[in] conf       Configuration.
 * \param[in] file_name  Output filename (stdout is used if NULL).
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_export_schema(
	conf_t *conf,
	const char *file_name
);
