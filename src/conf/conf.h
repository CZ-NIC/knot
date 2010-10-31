#ifndef _CUTEDNS_CONF_H
#define _CUTENDS_CONF_H

#include <sys/types.h>
#include <sys/socket.h>

struct conf_interface {
    char *name;
    char *address;
    int   port;
    struct sockaddr *sa;
};

typedef struct conf_interface *conf_interface_t;

/* as per IANA registry @ http://www.iana.org/assignments/tsig-algorithm-names/tsig-algorithm-names.xhtml */
/* Tohle je potřeba vzít z nějakého master seznamu */
typedef enum {
    GSS_TSIG,
    HMAC_MD5,
    HMAC_SHA1,
    HMAC_SHA224,
    HMAC_SHA256,
    HMAC_SHA384,
    HMAC_SHA512
} tsig_algo_name;

struct conf_key {
    char *name;
    tsig_algo_name algorithm;
    char *secret;
};
typedef struct conf_key *conf_key_t;

struct conf_server {
    char *name;
    char *address;
    int   port;
    conf_key_t key;
    conf_interface_t interface;
};
typedef struct conf_server *conf_server_t;

/* Tohle je opět určitě v nějakém master */
typedef enum {
    RRCLASS_IN,
    RRCLASS_CH
} conf_class_t;

struct conf_zone {
    char *name;
    conf_class_t class;
    char *storage;
    conf_server_t *xfr_in;
    conf_server_t *xfr_out;
    conf_server_t *notify_in;
    conf_server_t *notify_out;
};
typedef struct conf_zone *conf_zone_t;

struct conf_log_map {
    int facility;
    int source;
};
typedef struct conf_log_map *conf_log_map_t;

typedef enum {
    LOG_SYSLOG,
    LOG_STDERR,
    LOG_FILE
} log_type_t;

struct conf_log {
    log_type_t log_type;
    char *log_output;
    conf_log_map_t *log_map; // array of log mappings
};
typedef struct conf_log *conf_log_t;

struct config {
    char *identity;
    char *version;
    conf_log_t *log; // array of logs
    
    conf_interface_t *interfaces;
    conf_key_t *keys;
    conf_server_t *servers;
    conf_zone_t *zones;
    
};
typedef struct config *config_t;


#endif /* _CUTEDNS_CONF_H */
