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

#ifndef _KNOTD_CONF_H_
#define _KNOTD_CONF_H_

#include <sys/types.h>
#include <sys/socket.h>

#include <urcu.h>

#include "libknot/dname.h"
#include "libknot/util/descriptor.h"
#include "libknot/tsig.h"
#include "common/lists.h"
#include "common/log.h"
#include "common/acl.h"
#include "common/sockaddr.h"
#include "common/general-tree.h"

/* Constants. */
#define CONFIG_DEFAULT_PORT 53
#define CONFIG_NOTIFY_RETRIES 5  /*!< 5 retries (suggested in RFC1996) */
#define CONFIG_NOTIFY_TIMEOUT 60 /*!< 60s (suggested in RFC1996) */
#define CONFIG_DBSYNC_TIMEOUT (60*60) /*!< 1 hour. */
#define CONFIG_REPLY_WD 10 /*!< SOA/NOTIFY query timeout [s]. */
#define CONFIG_HANDSHAKE_WD 10 /*!< [secs] for connection to make a request.*/
#define CONFIG_IDLE_WD  60 /*!< [secs] of allowed inactivity between requests */
#define CONFIG_RRL_SLIP 2 /*!< Default slip value. */
#define CONFIG_RRL_SIZE 393241 /*!< Htable default size. */

/*!
 * \brief Configuration for the interface
 *
 * This structure holds the configuration of the various interfaces
 * used in the configuration.  Same interface could be used for
 * listening and outgoing function.
 */
typedef struct conf_iface_t {
	node n;
	char *name;       /*!< Internal name for the interface. */
	char *address;    /*!< IP (IPv4/v6) address for this interface */
	unsigned prefix;  /*!< IP subnet prefix. */
	int port;         /*!< Port number for this interface */
	int family;       /*!< Address family. */
	knot_key_t *key;  /*!< TSIG key (only valid for remotes). */
	sockaddr_t  via;  /*!< Used for remotes to specify qry endpoint.*/
} conf_iface_t;

/*!
 * \brief Node containing poiner to remote.
 *
 * Used for zone ACL lists to prevent node duplication.
 */
typedef struct conf_remote_t {
	node n;               /*!< List node. */
	conf_iface_t *remote; /*!< Pointer to interface descriptor. */
} conf_remote_t;

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
	node n;
	char *name;               /*!< Zone name. */
	enum knot_rr_class cls;   /*!< Zone class (IN or CH). */
	char *file;               /*!< Path to a zone file. */
	char *db;                 /*!< Path to a database file. */
	char *ixfr_db;            /*!< Path to a IXFR database file. */
	size_t ixfr_fslimit;      /*!< File size limit for IXFR journal. */
	int dbsync_timeout;       /*!< Interval between syncing to zonefile.*/
	int enable_checks;        /*!< Semantic checks for parser.*/
	int disable_any;          /*!< Disable ANY type queries for AA.*/
	int notify_retries;       /*!< NOTIFY query retries. */
	int notify_timeout;       /*!< Timeout for NOTIFY response (s). */
	int build_diffs;          /*!< Calculate differences from changes. */
	struct {
		list xfr_in;      /*!< Remotes accepted for for xfr-in.*/
		list xfr_out;     /*!< Remotes accepted for xfr-out.*/
		list notify_in;   /*!< Remotes accepted for notify-in.*/
		list notify_out;  /*!< Remotes accepted for notify-out.*/
		list update_in;  /*!< Remotes accepted for DDNS.*/
	} acl;
} conf_zone_t;

/*!
 * \brief Mapping of loglevels to message sources.
 */
typedef struct conf_log_map_t {
	node n;
	int source; /*!< Log message source mask. */
	int prios;  /*!< Log priorities mask. */
} conf_log_map_t;

/*!
 * \brief Log facility descriptor.
 */
typedef struct conf_log_t {
	node n;
	logtype_t type;  /*!< Type of the log (SYSLOG/STDERR/FILE). */
	char *file;      /*!< Filename in case of LOG_FILE, else NULL. */
	list map;        /*!< Log levels mapping. */
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
	node n;
	knot_key_t k;
} conf_key_t;

/*!
 * \brief Remote control interface.
 */
typedef struct conf_control_t {
	conf_iface_t *iface; /*!< Remote control interface. */
	list allow;          /*!< List of allowed remotes. */
	acl_t* acl;          /*!< ACL. */
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
	char *filename; /*!< Name of the config file. */
	char *identity; /*!< Identity to return on CH TXT id.server. */
	char *version;  /*!< Version for CH TXT version.{bind|server} */
	char *storage;  /*!< Persistent storage path for databases and such. */
	char *pidfile;  /*!< PID file path. */
	char *nsid;     /*!< Server's NSID. */
	size_t nsid_len;/*!< Server's NSID length. */
	int   workers;  /*!< Number of workers per interface. */
	int   uid;      /*!< Specified user id. */
	int   gid;      /*!< Specified group id. */
	int   max_conn_idle; /*!< TCP idle timeout. */
	int   max_conn_hs;   /*!< TCP of inactivity before first query. */
	int   max_conn_reply; /*!< TCP/UDP query timeout. */
	int    rrl;      /*!< Rate limit (in responses per second). */
	size_t rrl_size; /*!< Rate limit htable size. */
	int    rrl_slip;  /*!< Rate limit SLIP. */

	/*
	 * Log
	 */
	list logs;        /*!< List of logging facilites. */
	int logs_count;   /*!< Count of logging facilities. */

	/*
	 * Interfaces
	 */
	list ifaces;      /*!< List of interfaces. */
	int ifaces_count; /*!< Count of interfaces. */

	/*
	 * TSIG keys
	 */
	list keys;     /*!< List of TSIG keys. */
	int key_count; /*!< Count of TSIG keys. */

	/*
	 * Remotes
	 */
	list remotes;     /*!< List of remotes. */
	int remotes_count;/*!< Count of remotes. */

	/*
	 * Zones
	 */
	list zones;       /*!< List of zones. */
	int zones_count;  /*!< Count of zones. */
	int zone_checks;  /*!< Semantic checks for parser.*/
	int disable_any;  /*!< Disable ANY type queries for AA.*/
	int notify_retries; /*!< NOTIFY query retries. */
	int notify_timeout; /*!< Timeout for NOTIFY response in seconds. */
	int dbsync_timeout; /*!< Default interval between syncing to zonefile.*/
	size_t ixfr_fslimit; /*!< File size limit for IXFR journal. */
	int build_diffs;     /*!< Calculate differences from changes. */
	general_tree_t *zone_tree; /*!< Zone tree for duplicate checking. */
	
	/*
	 * Remote control interface.
	 */
	conf_control_t ctl;

	/*
	 * Implementation specifics
	 */
	list hooks;      /*!< List of config hooks. */
	int hooks_count; /*!< Count of config hooks. */
	int _touched;    /*!< Bitmask of sections touched by last update. */
} conf_t;

/*!
 * \brief Config hook prototype.
 */
typedef struct conf_hook_t {
	node n;
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
conf_t *conf_new(const char* path);

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
 * \brief Parse configuration from associated file.
 *
 * \note Registered callbacks may be executed if applicable.
 *
 * \param conf Configuration context.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EPARSEFAIL on parser error.
 */
int conf_parse(conf_t *conf);

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
 * Ordering:
 * 1. ~/.knot/knot.conf (if exists)
 * 2. /etc/knot/knot.conf (fallback)
 *
 * \return Path to implicit configuration file.
 */
char* conf_find_default();

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
 * \brief Create new string from a concatenation of s1 and s2.
 *
 * \param s1 First string.
 * \param s2 Second string.
 *
 * \retval Newly allocated string on success.
 * \retval NULL on error.
 */
char* strcdup(const char *s1, const char *s2);

/*!
 * \brief Normalize file path and expand '~' placeholders.
 *
 * \note Old pointer may be freed.
 *
 * \retval Pointer to normalized path.
 */
char* strcpath(char *path);

/*! \brief Free zone config. */
void conf_free_zone(conf_zone_t *zone);

/*! \brief Free TSIG key config. */
void conf_free_key(conf_key_t *k);

/*! \brief Free interface config. */
void conf_free_iface(conf_iface_t *iface);

/*! \brief Free remotes config. */
void conf_free_remote(conf_remote_t *r);

/*! \brief Free log config. */
void conf_free_log(conf_log_t *log);

#endif /* _KNOTD_CONF_H_ */

/*! @} */
