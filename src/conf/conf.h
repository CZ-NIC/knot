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
#include <unistd.h>

#include "lib/lists.h"

/*!
 * \brief Configuration for the interface
 *
 * This structure holds the configuration of the various interfaces
 * used in the configuration.  Same interface could be used for
 * listening and outgoing function.
 */
struct conf_iface {
	node n;                /*!< */

	/*! \brief Internal name for the interface (not system names). */
	char *name;
	char *address;         /*!< IP (IPv4/v6) address for this interface */
	int   port;            /*!< Port number for this interface */
	struct sockaddr *sa;   /*!< */
};

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
struct conf_key {
	node n;            /*!< */
	char *name;        /*!< Name of the key. */

	/*!
	 * \brief Key algorithm.
	 *
	 * \todo IANA lists that as strings
	 */
	tsig_alg_t algorithm;
	char *secret;       /*!< Key data. */
};

/*!
 * \brief Remote server for XFR/NOTIFY.
 *
 * \todo Long description.
 */
struct conf_server {
	node n;
	char *name;     /*!< Name of the server in the configuration. */
	char *address;  /*!< Hostname or IP address of the server. */
	int   port;     /*!< Remote port. */

	/*! \brief TSIG key used to authenticate messages from/to server. */
	struct conf_key *key;

	/*!
	 * \brief Interface to use to communicate with the server (including
	 *        outgoing IP address).
	 */
	struct conf_iface *iface;
};

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
struct conf_zone {
	node n;             /*!< */
	char *name;         /*!< Zone name. */
	conf_class_t class; /*!< Zone class (IN or CH). */

	/*! \todo Generic storage, now just a filename on the disk. */
	char *storage;

	list xfr_in;   /*!< List of DNS servers to get zone from. */
	list xfr_out;  /*!< List of DNS servers allowed to transfer a zone. */

	/*! \brief List of DNS servers allowed to send NOTIFY for the zone. */
	list notify_in;

	/*! \brief List of DNS servers to be notified on zone change. */
	list notify_out;
};

/*!
 * \brief Maps internal category to the (sys)log facility.
 *
 * \todo ref #1
 */
struct conf_log_map {
	node n;
	int facility; /*!< (Sys)log facility, see man 3 syslog. */
	int category; /*!< Internal log category. */
};

/*!
 * \brief Types of log output.
 */
typedef enum {
	LOG_SYSLOG,  /*!< Logging to standard syslog(3). */
	LOG_STDERR,  /*!< Print error messages on the stderr. */
	LOG_FILE     /*!< Generic logging to (unbuffered) file on the disk. */
} log_type_t;

/*!
 * \brief Where to send log messages.
 *
 * \todo Give it some more thought (ref #1).
 */
struct conf_log {
	node n;              /*!< */
	log_type_t log_type; /*!< Type of the log (SYSLOG/STDERR/FILE). */
	char *log_output;    /*!< Filename in case of LOG_FILE, else NULL. */
	list log_map;        /*!< What type of messages to log. */
};

/*!
 * \brief Main config structure.
 *
 * Main configuration structure.
 *
 * \todo More documentation.
 */
struct config {
	char *filename; /*!< Name of the config file. */

	char *identity; /*!< Identity to return on CH TXT id.server. */

	/*!
	 * \brief Version to return on CH TXT version.bind. and version.server.
	 */
	char *version;

	list logs; /*!< List of logging destinations. */
	list ifaces; /*!< List of interfaces. */
	list keys; /*!< List of TSIG keys. */
	list servers; /*!< List of remote servers. */
	list zones; /*!< List of zones. */
};

extern struct config *new_config;

extern int (*cf_read_hook)(unsigned char *buf, unsigned int max);

struct config *config_alloc();
int config_parse(struct config *);
void config_free(struct config *);

#endif /* _CUTEDNS_CONF_H_ */

/*! \} */
