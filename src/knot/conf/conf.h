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
/*!
 * \file conf.h
 *
 * \author Ondrej Sury <ondrej.sury@nic.cz>
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Server configuration structures and API.
 *
 * \addtogroup config
 * @{
 */

#pragma once

#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>

#include <urcu.h>

#include "libknot/dname.h"
#include "libknot/rrtype/tsig.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/policy.h"
#include "common-knot/lists.h"
#include "common/log.h"
#include "knot/updates/acl.h"
#include "common-knot/sockaddr.h"
#include "common-knot/hattrie/hat-trie.h"
#include "knot/nameserver/query_module.h"

/* Constants. */
#define CONFIG_DEFAULT_PORT 53
#define CONFIG_NOTIFY_RETRIES 5  /*!< 5 retries (suggested in RFC1996) */
#define CONFIG_NOTIFY_TIMEOUT 60 /*!< 60s (suggested in RFC1996) */
#define CONFIG_DBSYNC_TIMEOUT 0 /*!< Sync immediately. */
#define CONFIG_REPLY_WD 10 /*!< SOA/NOTIFY query timeout [s]. */
#define CONFIG_HANDSHAKE_WD 5 /*!< [secs] for connection to make a request.*/
#define CONFIG_IDLE_WD  20 /*!< [secs] of allowed inactivity between requests */
#define CONFIG_MAXTCP 100  /*!< Default limit on incoming TCP clients. */
#define CONFIG_RRL_SLIP 1 /*!< Default slip value. */
#define CONFIG_RRL_SIZE 393241 /*!< Htable default size. */
#define CONFIG_XFERS 10
#define CONFIG_SERIAL_DEFAULT CONF_SERIAL_INCREMENT /*!< Default serial policy: increment. */

/*!
 * \brief Configuration for the interface
 *
 * This structure holds the configuration of the various interfaces
 * used in the configuration.  Same interface could be used for
 * listening and outgoing function.
 */
typedef struct conf_iface_t {
	node_t n;
	char *name;                   /*!< Internal name for the interface. */
	knot_tsig_key_t *key;         /*!< TSIG key (only applic for remotes). */
	unsigned prefix;              /*!< IP subnet prefix (only applic for remotes). */
	struct sockaddr_storage addr; /*!< Interface address. */
	struct sockaddr_storage via;  /*!< Used for remotes to specify qry endpoint.*/
} conf_iface_t;

/*!
 * \brief Node containing poiner to remote.
 *
 * Used for zone ACL lists to prevent node duplication.
 */
typedef struct conf_remote_t {
	node_t n;             /*!< List node. */
	conf_iface_t *remote; /*!< Pointer to interface descriptor. */
} conf_remote_t;

/*!
 * \brief Group of remotes list item.
 *
 * Holds the name of a remote in the list.
 */
typedef struct conf_group_remote_t {
	node_t n;
	char *name;
} conf_group_remote_t;

/*!
 * \brief Group of remotes.
 */
typedef struct conf_group_t {
	node_t n;	/*!< List node. */
	char *name;	/*!< Unique name of the group. */
	list_t remotes;	/*!< List of remote names. */
} conf_group_t;

/*!
 * \brief Zone configuration.
 *
 * This structure holds the configuration for the zone.  In it's most
 * basic form, it just allows to read a zone from the specific
 * location on the disk.  It also allows to have multiple DNS servers
 * as a source for the zone transfer and multiple DNS servers to allow
 * zone transfers.  Same logic applies for the NOTIFY.
 */
typedef struct conf_zone_t {
	char *name;                /*!< Zone name. */
	char *file;                /*!< Path to a zone file. */
	char *storage;             /*!< Path to a storage dir. */
	char *dnssec_keydir;       /*!< Path to a DNSSEC key dir. */
	char *ixfr_db;             /*!< Path to a IXFR database file. */
	int dnssec_enable;         /*!< DNSSEC: Online signing enabled. */
	size_t ixfr_fslimit;       /*!< File size limit for IXFR journal. */
	size_t max_zone_size;      /*!< Maximum zone size for XFR */
	int sig_lifetime;          /*!< Validity period of DNSSEC signatures. */
	int dbsync_timeout;        /*!< Interval between syncing to zonefile.*/
	int enable_checks;         /*!< Semantic checks for parser.*/
	int disable_any;           /*!< Disable ANY type queries for AA.*/
	int notify_retries;        /*!< NOTIFY query retries. */
	int notify_timeout;        /*!< Timeout for NOTIFY response (s). */
	int build_diffs;           /*!< Calculate differences from changes. */
	int serial_policy;         /*!< Serial policy when updating zone. */
	int req_edns_code;         /*!< Request EDNS option code. */
	char *req_edns_data;       /*!< Request EDNS option data. */
	size_t req_edns_data_len;  /*!< Request EDNS option data length. */
	struct {
		list_t xfr_in;     /*!< Remotes accepted for for xfr-in.*/
		list_t xfr_out;    /*!< Remotes accepted for xfr-out.*/
		list_t notify_in;  /*!< Remotes accepted for notify-in.*/
		list_t notify_out; /*!< Remotes accepted for notify-out.*/
		list_t update_in;  /*!< Remotes accepted for DDNS.*/
	} acl;

	struct query_plan *query_plan;
	list_t query_modules;
} conf_zone_t;

/*!
 * \brief Serial policy options.
 */
typedef enum conf_serial_policy_t {
	CONF_SERIAL_INCREMENT	= 1 << 0,
	CONF_SERIAL_UNIXTIME	= 1 << 1
} conf_serial_policy_t;

/*!
 * \brief Mapping of loglevels to message sources.
 */
typedef struct conf_log_map_t {
	node_t n;
	int source; /*!< Log message source mask. */
	int prios;  /*!< Log priorities mask. */
} conf_log_map_t;

/*!
 * \brief Log facility descriptor.
 */
typedef struct conf_log_t {
	node_t n;
	logtype_t type;  /*!< Type of the log (SYSLOG/STDERR/FILE). */
	char *file;      /*!< Filename in case of LOG_FILE, else NULL. */
	list_t map;      /*!< Log levels mapping. */
} conf_log_t;

/*!
 * \brief Configuration sections.
 */
typedef enum conf_section_t {
	CONF_LOG    = 1 << 0, /*!< Log section. */
	CONF_IFACES = 1 << 1, /*!< Interfaces. */
	CONF_ZONES  = 1 << 2, /*!< Zones. */
	CONF_OTHER  = 1 << 3, /*!< Other sections. */
	CONF_ALL    = ~0      /*!< All sections. */
} conf_section_t;

/*!
 * \brief TSIG key list item.
 */
typedef struct conf_key_t {
	node_t n;
	knot_tsig_key_t k;
} conf_key_t;

/*!
 * \brief Remote control interface.
 */
typedef struct conf_control_t {
	conf_iface_t *iface; /*!< Remote control interface. */
	list_t allow;        /*!< List of allowed remotes. */
	bool have;           /*!< Set if configured. */
} conf_control_t;

/*!
 * \brief Main config structure.
 *
 * Configuration structure.
 */
typedef struct conf_t {
	/*
	 * System
	 */
	const char *filename; /*!< Name of the config file. */
	char *identity; /*!< Identity to return on CH TXT id.server. or hostname.bind. */
	char *version;  /*!< Version for CH TXT version.{bind|server}. */
	char *rundir;   /*!< Run-time directory path. */
	char *pidfile;  /*!< PID file location. */
	char *nsid;     /*!< Server's NSID. */
	size_t nsid_len;/*!< Server's NSID length. */
	size_t max_udp_payload; /*!< Maximal UDP payload size. */
	int   workers;  /*!< Number of workers per interface. */
	int   bg_workers; /*!< Number of background workers. */
	bool  async_start; /*!< Asynchronous startup. */
	int   uid;      /*!< Specified user id. */
	int   gid;      /*!< Specified group id. */
	int   max_conn_idle; /*!< TCP idle timeout. */
	int   max_conn_hs;   /*!< TCP of inactivity before first query. */
	int   max_conn_reply; /*!< TCP/UDP query timeout. */
	int   max_tcp_clients; /*!< TCP client limit. */
	int    rrl;      /*!< Rate limit (in responses per second). */
	size_t rrl_size; /*!< Rate limit htable size. */
	int    rrl_slip;  /*!< Rate limit SLIP. */
	int    xfers;     /*!< Number of parallel transfers. */

	/*
	 * Log
	 */
	list_t logs;      /*!< List of logging facilites. */

	/*
	 * Interfaces
	 */
	list_t ifaces;    /*!< List of interfaces. */

	/*
	 * TSIG keys
	 */
	list_t keys;   /*!< List of TSIG keys. */

	/*
	 * Remotes
	 */
	list_t remotes;    /*!< List of remotes. */

	/*
	 * Groups of remotes.
	 */
	list_t groups; /*!< List of groups of remotes. */

	/*
	 * Zones
	 */
	hattrie_t *zones;    /*!< List of zones. */
	int zone_checks;     /*!< Semantic checks for parser.*/
	int disable_any;     /*!< Disable ANY type queries for AA.*/
	int notify_retries;  /*!< NOTIFY query retries. */
	int notify_timeout;  /*!< Timeout for NOTIFY response in seconds. */
	int dbsync_timeout;  /*!< Default interval between syncing to zonefile.*/
	size_t ixfr_fslimit; /*!< File size limit for IXFR journal. */
	size_t max_zone_size;/*!< Maximum zone size for XFR */
	int build_diffs;     /*!< Calculate differences from changes. */
	char *storage;       /*!< Storage dir. */
	char *timer_db;      /*!< Path to timer database. */
	char *dnssec_keydir; /*!< DNSSEC: Path to key directory. */
	int dnssec_enable;   /*!< DNSSEC: Online signing enabled. */
	int sig_lifetime;    /*!< DNSSEC: Signature lifetime. */
	int serial_policy;   /*!< Serial policy when updating zone. */
	int req_edns_code;   /*!< Request EDNS option code. */
	char *req_edns_data; /*!< Request EDNS option data. */
	size_t req_edns_data_len; /*!< Request EDNS option data length. */
	struct query_plan *query_plan;
	list_t query_modules;

	/*
	 * Remote control interface.
	 */
	conf_control_t ctl;

	/*
	 * Implementation specifics
	 */
	list_t hooks;    /*!< List of config hooks. */
	int _touched;    /*!< Bitmask of sections touched by last update. */
} conf_t;

/*!
 * \brief Config hook prototype.
 */
typedef struct conf_hook_t {
	node_t n;
	int sections; /*!< Bitmask of watched sections. */
	int (*update)(const conf_t*, void*); /*!< Function executed on config load. */
	void *data;
} conf_hook_t;

/*
 * Specific configuration API.
 */

/*!
 * \brief Create new configuration structure.
 *
 * \param path Path to configuration file.
 * \retval new structure if successful.
 * \retval NULL on error.
 */
conf_t *conf_new(const char *path);

/*!
 * \brief Register on-update callback.
 *
 * \param conf Configuration context.
 * \param sections Bitmask of watched sections or CONF_ALL.
 * \param on_update Callback.
 * \param data User specified data for hook.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ENOMEM out of memory error.
 */
int conf_add_hook(conf_t * conf, int sections,
                  int (*on_update)(const conf_t*, void*), void *data);

/*!
 * \brief Parse configuration from string.
 *
 * \note Registered callbacks may be executed if applicable.
 *
 * \param conf Configuration context.
 * \param src Source string.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EPARSEFAIL on parser error.
 */
int conf_parse_str(conf_t *conf, const char* src);

/*!
 * \brief Truncate configuration context.
 *
 * \param conf Configuration context.
 * \param unload_hooks If true, hooks will be unregistered and freed as well.
 */
void conf_truncate(conf_t *conf, int unload_hooks);

/*!
 * \brief Destroy configuration context.
 *
 * \param conf Configuration context.
 */
void conf_free(conf_t *conf);

/*
 * Singleton configuration API.
 */

/*!
 * \brief Find implicit configuration file.
 *
 * \return Path to implicit configuration file.
 */
const char* conf_find_default();

/*!
 * \brief Open singleton configuration from file.
 *
 * \note Registered callbacks may be executed if applicable.
 *
 * \param path Path to configuration file.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on null path.
 * \retval KNOT_ENOENT if the path doesn't exist.
 */
int conf_open(const char* path);

/* Imported singleton */
extern conf_t *s_config;

/*!
 * \brief Singleton configuration context accessor.
 *
 * \return Configuration context.
 */
static inline conf_t* conf() {
	return s_config; // Inline for performance reasons.
}

/*
 * Utilities.
 */

/*!
 * \brief Normalize file path and expand '~' placeholders.
 *
 * \note Old pointer may be freed.
 *
 * \retval Pointer to normalized path.
 */
char* strcpath(char *path);

/*! \brief Return the number of UDP threads according to the configuration. */
size_t conf_udp_threads(const conf_t *conf);

/*! \brief Return the number of TCP threads according to the configuration. */
size_t conf_tcp_threads(const conf_t *conf);

/*! \brief Return the number of background worker threads. */
int conf_bg_threads(const conf_t *conf);

/* \brief Initialize zone config. */
void conf_init_zone(conf_zone_t *zone);

/*! \brief Free zone config. */
void conf_free_zone(conf_zone_t *zone);

/*! \brief Free TSIG key config. */
void conf_free_key(conf_key_t *k);

/*! \brief Free interface config. */
void conf_free_iface(conf_iface_t *iface);

/*! \brief Free remotes config. */
void conf_free_remote(conf_remote_t *r);

/*! \brief Free group config. */
void conf_free_group(conf_group_t *group);

/*! \brief Free log config. */
void conf_free_log(conf_log_t *log);

/*! @} */
