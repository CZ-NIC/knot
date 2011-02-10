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

#ifndef _CUTEDNS_CONF_H_
#define _CUTENDS_CONF_H_

#include <sys/types.h>
#include <sys/socket.h>

#include "lib/lists.h"
#include "other/log.h"

/* Constants. */
#define CONFIG_DEFAULT_PORT 53
#define CONFIG_DEFAULT_PATH "/etc/cutedns/cutedns.conf" //!< Default config path

/*!
 * \brief Configuration for the interface
 *
 * This structure holds the configuration of the various interfaces
 * used in the configuration.  Same interface could be used for
 * listening and outgoing function.
 */
typedef struct {
	node n;                /*!< */

	/*! \brief Internal name for the interface (not system names). */
	char *name;
	char *address;         /*!< IP (IPv4/v6) address for this interface */
	int   port;            /*!< Port number for this interface */
	struct sockaddr *sa;   /*!< */
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
	/*!
	 * \brief Key algorithm.
	 *
	 * \todo IANA lists that as strings
	 */
	tsig_alg_t algorithm;
	char *secret;       /*!< Key data. */
} conf_key_t;

/*!
 * \todo Import from dns library.
 */
typedef enum {
	RRCLASS_IN,
	RRCLASS_CH
} conf_class_t;

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
	node n;             /*!< */
	char *name;         /*!< Zone name. */
	conf_class_t cls;   /*!< Zone class (IN or CH). */

	/*! Path to a zone file. */
	char *file;
} conf_zone_t;

/*!
 * \brief Mapping of loglevels to message sources.
 */
typedef struct {
	node n;
	int source; /*!< Log message source mask. */
	int levels; /*!< Log levels bitmask. */
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
 * \brief Main config structure.
 *
 * Main configuration structure.
 *
 * \todo More documentation.
 */
typedef struct {
	char *filename; /*!< Name of the config file. */

	char *identity; /*!< Identity to return on CH TXT id.server. */

	/*!
	 * \brief Version to return on CH TXT version.bind. and version.server.
	 */
	char *version;

	char *storage; /*!< Persistent storage path for pidfile, databases etc. */

	conf_key_t key; /*!< Server TSIG key. */

	list logs; /*!< List of logging destinations. */
	list ifaces; /*!< List of interfaces. */
	list zones; /*!< List of zones. */
} config_t;

/* Specific configuration API. */
config_t *config_new(const char* path);
int config_parse(config_t *conf);
int config_parse_str(config_t *conf, const char* src);
void config_free(config_t *conf);

/* Singleton configuration API. */
int config_open(const char* path);
const config_t* config_get();
int config_close();


#endif /* _CUTEDNS_CONF_H_ */

/*! \} */
