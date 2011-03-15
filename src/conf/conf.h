/*!
 * \file conf.h
 *
 * \author Ondrej Sury <ondrej.sury\nic.cz>
 *
 * \brief Server configuration structures and API.
 *
 * \addtogroup config
 * \{
 */

#ifndef _KNOT_CONF_H_
#define _KNOT_CONF_H_

#include <sys/types.h>
#include <sys/socket.h>

#include <urcu.h>

#include "dnslib/descriptor.h"
#include "lib/lists.h"
#include "other/log.h"

/* Constants. */
#define CONFIG_DEFAULT_PORT 53

/*!
 * \brief Configuration for the interface
 *
 * This structure holds the configuration of the various interfaces
 * used in the configuration.  Same interface could be used for
 * listening and outgoing function.
 */
typedef struct {
	node n;
	char *name;       /*!< Internal name for the interface. */
	char *address;    /*!< IP (IPv4/v6) address for this interface */
	int   port;       /*!< Port number for this interface */
	int family;       /*!< Address family. */
} conf_iface_t;

/*!
 * \brief List of TSIG algoritms.
 *
 * Master list of TSIG algoritms as per IANA registry
 * http://www.iana.org/assignments/tsig-algorithm-names/tsig-algorithm-names.xhtml
 */
typedef enum {
	GSS_TSIG,
	HMAC_MD5,
	HMAC_SHA1,
	HMAC_SHA224,
	HMAC_SHA256,
	HMAC_SHA384,
	HMAC_SHA512
} tsig_alg_t;

/*!
 * \brief Configuration for the TSIG key.
 */
typedef struct {
	tsig_alg_t algorithm; /*!< Key algorithm.  */
	char *secret;         /*!< Key data. */
} conf_key_t;

/*!
 * \brief Zone configuration.
 *
 * This structure holds the configuration for the zone.  In it's most
 * basic form, it just allows to read a zone from the specific
 * location on the disk.  It also allows to have multiple DNS servers
 * as a source for the zone transfer and multiple DNS servers to allow
 * zone transfers.  Same logic applies for the NOTIFY.
 *
 * \todo Missing XFR type (AXFR/IXFR/IXFR-ONLY) for each server.
 */
typedef struct {
	node n;
	char *name;                  /*!< Zone name. */
	enum dnslib_rr_class cls;    /*!< Zone class (IN or CH). */
	char *file;                  /*!< Path to a zone file. */
	char *db;                    /*!< Path to a database file. */
} conf_zone_t;

/*!
 * \brief Mapping of loglevels to message sources.
 */
typedef struct {
	node n;
	int source; /*!< Log message source mask. */
	int prios;  /*!< Log priorities mask. */
} conf_log_map_t;

/*!
 * \brief Log facility descriptor.
 */
typedef struct {
	node n;
	logtype_t type;  /*!< Type of the log (SYSLOG/STDERR/FILE). */
	char *file;      /*!< Filename in case of LOG_FILE, else NULL. */
	list map;        /*!< Log levels mapping. */
} conf_log_t;

/*!
 * \brief Configuration sections.
 */
typedef enum {
	CONF_LOG    = 1 << 0, /*!< Log section. */
	CONF_IFACES = 1 << 1, /*!< Interfaces. */
	CONF_ZONES  = 1 << 2, /*!< Zones. */
	CONF_OTHER  = 1 << 3, /*!< Other sections. */
	CONF_ALL    = ~0      /*!< All sections. */
} conf_section_t;

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
	conf_key_t key; /*!< Server TSIG key. */

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
	 * Zones
	 */
	list zones;       /*!< List of zones. */
	int zones_count;  /*!< Count of zones. */

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
typedef struct {
	node n;
	int sections; /*!< Bitmask of watched sections. */
	int (*update)(const conf_t*); /*!< Function executed on config load. */
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
 *
 * \retval 0 on success.
 * \retval <0 on error.
 *
 * \todo There might be some issues with reloading config
 *       on-the-fly in multithreaded environment, check afterwards.
 */
int conf_add_hook(conf_t * conf, int sections, int (*on_update)(const conf_t*));

/*!
 * \brief Parse configuration from associated file.
 *
 * \note Registered callbacks may be executed if applicable.
 *
 * \param conf Configuration context.
 *
 * \retval 0 on success.
 * \retval <0 on error.
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
 * \retval 0 on success.
 * \retval <0 on error.
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
 * \retval 0 on success.
 * \retval <0 on error.
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

/*!
 * \brief Lock configuration for reading.
 *
 * \return Configuration context.
 */
static inline void conf_read_lock() {
	rcu_read_lock();
}

/*!
 * \brief Unlock configuration for reading.
 */
static inline void conf_read_unlock() {
	rcu_read_unlock();
}

/*
 * Utilities.
 */

/*!
 * \brief Return normalized path.
 *
 * \note Old pointer may be freed.
 *
 * \retval Pointer to normalized path.
 */
char* strcpath(char *path);

#endif /* _KNOT_CONF_H_ */

/*! \} */
