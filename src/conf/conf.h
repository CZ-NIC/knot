#ifndef _CUTEDNS_CONF_H
#define _CUTENDS_CONF_H

#include <sys/types.h>
#include <sys/socket.h>

#include "lists.h"

/**
 * struct conf_interface - configuration for the interface
 * @name: internal name for the interface (not system interface names)
 * @address: IP (IPv4/v6) address for this interface
 * @port: port number for this interface
 * @sa: 
 *
 * This structure holds the configuration of the various interfaces
 * used in the configuration.  Same interface could be used for
 * listening and outgoing function.
 **/
struct conf_interface {
	node n;
	char *name;
	char *address;
	int   port;
	struct sockaddr *sa;
};

/**
 * enum tsig_alg_t - list of TSIG algoritms
 *
 * Master list of TSIG algoritms as per IANA registry
 * http://www.iana.org/assignments/tsig-algorithm-names/tsig-algorithm-names.xhtml
 *
 **/
typedef enum {
	GSS_TSIG,
	HMAC_MD5,
	HMAC_SHA1,
	HMAC_SHA224,
	HMAC_SHA256,
	HMAC_SHA384,
	HMAC_SHA512
} tsig_alg_t;

/**
 * struct conf_key - configuration for the TSIG key
 * @name: name of the key
 * @algorithm: key algorithm, FIXME: IANA lists that as strings
 * @secret: key data
 * @
 **/
struct conf_key {
	node n;
	char *name;
	tsig_alg_t algorithm;
	char *secret;
};

/**
 * struct conf_server - remote server for XFR/NOTIFY
 * @name: name of the server in the configuration
 * @address: hostname or IP address of the server
 * @port: remote port
 * @key: TSIG key used to authenticate messages from/to server
 * @interface: interface to use to communicate with the server (including outgoing IP address)
 *
 * FIXME: Long description
 **/
struct conf_server {
	node n;
	char *name;
	char *address;
	int   port;
	struct conf_key *key;
	struct conf_interface *interface;
};

/**
 * enum conf_class_t - FIXME: import from dns library
 **/
typedef enum {
	RRCLASS_IN,
	RRCLASS_CH
} conf_class_t;

/**
 * struct conf_zone - zone configuration
 * @name: zone name
 * @class: zone class (IN or CH)
 * @storage: FIXME: generic storage, now just a filename on the disk
 * @xfr_in: list of DNS servers to get zone from
 * @xfr_out: list of DNS servers allowed to transfer a zone
 * @notify_in: list of DNS servers allowed to send NOTIFY for the zone
 * @notify_out: list of DNS servers to be notified on zone change
 *
 * This structure holds the configuration for the zone.  In it's most
 * basic form, it just allows to read a zone from the specific
 * location on the disk.  It also allows to have multiple DNS servers
 * as a source for the zone transfer and multiple DNS servers to allow
 * zone transfers.  Same logic applies for the NOTIFY.
 * FIXME: missing XFR type (AXFR/IXFR/IXFR-ONLY) for each server
 **/
struct conf_zone {
	node n;
	char *name;
	conf_class_t class;
	char *storage;
	list xfr_in;
	list xfr_out;
	list notify_in;
	list notify_out;
};

/**
 * struct conf_log_map - maps internal category to the (sys)log facility
 * @facility: (sys)log facility, see man 3 syslog
 * @category: internal log category
 *
 * FIXME: ref #1
 **/
struct conf_log_map {
	node n;
	int facility;
	int category;
};

/**
 * enum log_type_t - types of log output
 * @LOG_SYSLOG: logging to standard syslog(3)
 * @LOG_STDERR: print error messages on the stderr
 * @LOG_FILE: generic logging to (unbuffered) file on the disk
 *
 **/
typedef enum {
	LOG_SYSLOG,
	LOG_STDERR,
	LOG_FILE
} log_type_t;

/**
 * struct conf_log - where to send log messages
 * @log_type: type of the log (SYSLOG/STDERR/FILE)
 * @log_output: filename in case of LOG_FILE, else NULL
 * @log_map: what type of messages to log
 *
 * FIXME: give it some more thought (ref #1)
 **/
struct conf_log {
	node n;
	log_type_t log_type;
	char *log_output;
	list log_map; // array of log mappings
};

/**
 * struct config - main config structure
 * @identity: identity to return on CH TXT id.server.
 * @version: version to return on CH TXT version.bind. and version.server.
 * @logs: list of logging destinations
 * @interfaces: list of interfaces
 * @keys: list of TSIG keys
 * @servers: list of remote servers
 * @zones: list of zones
 *
 * Main configuration structure...  FIXME: more documentation
 **/
struct config {
	char *identity;
	char *version;

	list logs;	
	list interfaces;
	list keys;
	list servers;
	list zones;    
};


#endif /* _CUTEDNS_CONF_H */
