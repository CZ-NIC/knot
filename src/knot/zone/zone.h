/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "contrib/atomic.h"
#include "contrib/semaphore.h"
#include "knot/catalog/catalog_update.h"
#include "knot/conf/conf.h"
#include "knot/conf/confio.h"
#include "knot/journal/journal_basic.h"
#include "knot/journal/serialization.h"
#include "knot/events/events.h"
#include "knot/updates/changesets.h"
#include "knot/zone/contents.h"
#include "knot/zone/timers.h"
#include "knot/dnssec/zone-keys.h"
#include "libknot/dname.h"
#include "libknot/dynarray.h"
#include "libknot/packet/pkt.h"

struct zone_update;
struct zone_backup_ctx;

/*!
 * \brief Zone flags.
 *
 * When updating check create_zone_reload() if the flag mask is ok.
 */
typedef enum {
	ZONE_FORCE_AXFR     = 1 << 0,  /*!< Force AXFR as next transfer. */
	ZONE_FORCE_RESIGN   = 1 << 1,  /*!< Force zone re-sign. */
	ZONE_FORCE_FLUSH    = 1 << 2,  /*!< Force zone flush. */
	ZONE_FORCE_KSK_ROLL = 1 << 3,  /*!< Force KSK/CSK rollover. */
	ZONE_FORCE_ZSK_ROLL = 1 << 4,  /*!< Force ZSK rollover. */
	ZONE_IS_CATALOG     = 1 << 5,  /*!< This is a catalog. */
	ZONE_IS_CAT_MEMBER  = 1 << 6,  /*!< This zone exists according to a catalog. */
	ZONE_XFR_FROZEN     = 1 << 7,  /*!< Outgoing AXFR/IXFR temporarily disabled. */
	ZONE_USER_FLUSH     = 1 << 8,  /*!< User-triggered flush. */
	ZONE_LAST_SIGN_OK   = 1 << 9,  /*!< Last full-sign event finished OK. */
	ZONE_PREF_MASTER_2X = 1 << 10, /*!< Preferred master has been overwritten at least once. */
	ZONE_RDB_RELOAD     = 1 << 11, /*!< Full zone reload from database. */

	ZONE_DNSSEC_ENABLED = 1 << 14, /*!< DNSSEC is enabled for this zone. */
	ZONE_EPHEMERAL      = 1 << 15, /*!< Ephemeral zone which is not persisted after query processing */

	ZONE_FLAG_MAX       = 1 << 19, /*!< Maximal usable flag below purge_flag_t. */
	ZONE_FLAG_TYPESIZE  = 1 << 30, /*!< Enforces the compiler to use 32-bit variable for this enum. */
} zone_flag_t;

/*!
 * \brief Track unsuccessful NOTIFY targets.
 */
typedef uint64_t notifailed_rmt_hash;
knot_dynarray_declare(notifailed_rmt, notifailed_rmt_hash, DYNARRAY_VISIBILITY_NORMAL, 4);

/*!
 * \brief Zone purging parameter flags.
 *
 * \warning Note they are and must be mutually exclusive with zone_flag_t so that they can be stored in zone->flags.
 */
typedef enum {
	PURGE_ZONE_BEST     = 1 << 20, /*!< Best effort -- continue on failures. */
	PURGE_ZONE_LOG      = 1 << 21, /*!< Log a purged zone even if requested less. */
	PURGE_ZONE_NOSYNC   = 1 << 22, /*!< Remove even zone files with disabled syncing. */
	PURGE_ZONE_TIMERS   = 1 << 23, /*!< Purge the zone timers. */
	PURGE_ZONE_ZONEFILE = 1 << 24, /*!< Purge the zone file. */
	PURGE_ZONE_JOURNAL  = 1 << 25, /*!< Purge the zone journal. */
	PURGE_ZONE_KASPDB   = 1 << 26, /*!< Purge KASP DB. */
	PURGE_ZONE_CATALOG  = 1 << 27, /*!< Purge the catalog. */
	PURGE_ZONE_EXPIRE   = 1 << 28, /*!< Expire the zone, free contents. */
} purge_flag_t;

/*!< All data. */
#define PURGE_ZONE_DATA  (PURGE_ZONE_TIMERS | PURGE_ZONE_ZONEFILE | PURGE_ZONE_JOURNAL | \
                          PURGE_ZONE_KASPDB | PURGE_ZONE_CATALOG)

/*!< Standard purge (respect C_ZONEFILE_SYNC param). */
#define PURGE_ZONE_ALL   (PURGE_ZONE_DATA | PURGE_ZONE_BEST | PURGE_ZONE_LOG)

/*!< All purge-related flags. */
#define PURGE_ZONE_FLAGS (PURGE_ZONE_ALL | PURGE_ZONE_NOSYNC | PURGE_ZONE_EXPIRE)

/*!
 * \brief Structure for holding DNS zone.
 */
typedef struct zone
{
	knot_dname_t *name;
	zone_contents_t *contents;
	zone_flag_t flags;
	bool is_catalog_flag; //!< Lock-less indication of ZONE_IS_CATALOG flag.
	bool started;         //!< Lock-less indication of a started zone.

	/*! \brief Zonefile parameters. */
	struct {
		struct timespec mtime;
		uint32_t serial;
		bool exists;
		bool resigned;
		bool retransfer;
		uint8_t bootstrap_cnt; //!< Rebootstrap count (not related to zonefile).
	} zonefile;

	/*! \brief Zone events. */
	zone_timers_t *timers;        //!< Persistent zone timers.
	zone_timers_t *timers_static; //!< An instance of zone_timers structure which is safe to read from anywhere under rcu_read_lock.
	zone_events_t events;         //!< Zone events timers.

	/*! \brief Track unsuccessful NOTIFY targets. */
	notifailed_rmt_dynarray_t notifailed;

	/*! \brief DDNS queue and lock. */
	pthread_mutex_t ddns_lock;
	size_t ddns_queue_size;
	list_t ddns_queue;

	/*! \brief Control update context. */
	struct zone_update *control_update;
	pthread_mutex_t cu_lock;

	/*! \brief Ensue one COW transaction on zone's trees at a time. */
	knot_sem_t cow_lock;

	/*! \brief Special thread that performs update_clear if delayed by outstanding XFR. */
	pthread_t update_clear_thr;

	/*! \brief Pointer on running server with e.g. KASP db, journal DB, catalog... */
	struct server *server;

	/*! \brief Zone backup context (NULL unless backup pending). */
	knot_atomic_ptr_t backup_ctx;

	/*! \brief Catalog-generate feature. */
	knot_dname_t *catalog_gen;
	catalog_update_t *cat_members;
	const char *catalog_group;

	/*! \brief Auto-generated reverse zones... */
	list_t include_from;
	list_t internal_notify;

	/*! \brief Preferred master lock. Also used for flags access. */
	pthread_mutex_t preferred_lock;
	/*! \brief Preferred master for remote operation. */
	struct sockaddr_storage *preferred_master;

	/*! \brief Zone signing context and keys. (for DNSSEC onlinesign) */
	zone_sign_ctx_t *sign_ctx;

	/*! \brief Query modules. */
	list_t query_modules;
	struct query_plan *query_plan;
} zone_t;

typedef enum {
	ZONE_INCLUDE_REVERSE,
	ZONE_INCLUDE_FLATTEN,
} zone_include_method_t;

typedef struct {
	node_t n;
	zone_t *include;
	zone_include_method_t method;
} zone_include_t;

/*!
 * \brief Creates new zone with empty zone content and marks it as ephemeral. If mm is passed,
 * allocates the zone using mm.
 *
 * \param name  Zone name.
 * \param mm    mempool pointer
 *
 * \return The initialized zone structure or NULL if an error occurred.
 */
zone_t* zone_new_mm(const knot_dname_t *name, knot_mm_t *mm);

/*!
 * \brief Creates new zone with empty zone content.
 *
 * \param name  Zone name.
 *
 * \return The initialized zone structure or NULL if an error occurred.
 */
zone_t* zone_new(const knot_dname_t *name);

/*!
 * \brief Deallocates the zone structure created with zone_new_mm.
 *
 * \note The function also deallocates all bound structures (contents, etc.).
 *
 * \param zone_ptr Zone to be freed.
 */
void zone_free_mm(zone_t **zone_ptr, knot_mm_t *mm);

/*!
 * \brief Deallocates the zone structure.
 *
 * \note The function also deallocates all bound structures (contents, etc.).
 *
 * \param zone_ptr Zone to be freed.
 */
void zone_free(zone_t **zone_ptr);

/*!
 * \brief Clear zone contents (->SERVFAIL), reset modules, plan LOAD.
 *
 * \param conf   Current configuration.
 * \param zone   Zone to be re-set.
 */
void zone_reset(conf_t *conf, zone_t *zone);

/*!
 * \brief Purges selected zone components.
 *
 * \param conf    Current configuration.
 * \param zone    Zone to be purged.
 * \param params  Zone components to be purged and the purging mode
 *                (with PURGE_ZONE_BEST try to purge everything requested,
 *                otherwise exit on the first failure).
 *
 * \return        KNOT_E*
 */
int selective_zone_purge(conf_t *conf, zone_t *zone, purge_flag_t params);

/*!
 * \brief Expire zone, NULL and free zone->contents, clear CTL txn, expire timers, replan events.
 */
void zone_perform_expire(conf_t *conf, zone_t *zone);

/*!
 * \brief Clears possible control update transaction.
 *
 * \param zone Zone to be cleared.
 */
void zone_control_clear(zone_t *zone);

/*!
 * \brief Common database getters.
 */
knot_lmdb_db_t *zone_journaldb(const zone_t *zone);
knot_lmdb_db_t *zone_kaspdb(const zone_t *zone);
catalog_t *zone_catalog(const zone_t *zone);
catalog_update_t *zone_catalog_upd(const zone_t *zone);

/*!
 * \brief Only for RO journal operations.
 */
inline static zone_journal_t zone_journal(zone_t *zone)
{
	zone_journal_t j = { zone_journaldb(zone), zone->name, NULL };
	return j;
}

int zone_change_store(conf_t *conf, zone_t *zone, changeset_t *change, changeset_t *extra);
int zone_diff_store(conf_t *conf, zone_t *zone, const zone_diff_t *diff);
int zone_changes_clear(conf_t *conf, zone_t *zone);
int zone_in_journal_store(conf_t *conf, zone_t *zone, zone_contents_t *new_contents);

/*! \brief Synchronize zone file with journal. */
int zone_flush_journal(conf_t *conf, zone_t *zone, bool verbose);

bool zone_journal_has_zij(zone_t *zone);

bool zone_journal_same_serial(zone_t *zone, uint32_t serial_to);

/*!
 * \brief Clear failed_notify list before planning new NOTIFY.
 */
void zone_notifailed_clear(zone_t *zone);
void zone_schedule_notify(conf_t *conf, zone_t *zone, time_t delay);

void zone_schedule_update(conf_t *conf, zone_t *zone, zone_event_type_t type);

/*!
 * \brief Atomically switch the content of the zone.
 */
zone_contents_t *zone_switch_contents(zone_t *zone, zone_contents_t *new_contents);

/*! \brief Checks if the zone is slave. */
bool zone_is_slave(conf_t *conf, const zone_t *zone);

/*! \brief Sets the address as a preferred master address. */
void zone_set_preferred_master(zone_t *zone, const struct sockaddr_storage *addr);

/*! \brief Clears the current preferred master address. */
void zone_clear_preferred_master(zone_t *zone);

/*! \brief Updates the last master address used. */
void zone_set_last_master(zone_t *zone, const struct sockaddr_storage *addr);

/*! \brief Sets a zone flag. */
void zone_set_flag(zone_t *zone, zone_flag_t flag);

/*! \brief Unsets a zone flag. */
void zone_unset_flag(zone_t *zone, zone_flag_t flag);

/*! \brief Returns if a flag is set (and optionally clears it). */
zone_flag_t zone_get_flag(zone_t *zone, zone_flag_t flag, bool clear);

/*! \brief Get zone SOA RR. */
const knot_rdataset_t *zone_soa(const zone_t *zone);

/*! \brief Get zone SOA EXPIRE field, or 0 if empty zone. */
uint32_t zone_soa_expire(const zone_t *zone);

/*! \brief Check if zone is expired according to timers. */
bool zone_expired(const zone_t *zone);

/*!
 * \brief Set default timers for new zones or invalidate if not valid.
 */
void zone_timers_sanitize(conf_t *conf, zone_t *zone);

int zone_timers_begin(zone_t *zone);
void zone_timers_commit(conf_t *conf, zone_t *zone);

typedef struct {
	bool address;     //!< Fallback to next remote address is required.
	bool remote;      //!< Fallback to next remote server is required.
	bool trying_last; //!< This master try is for the same server as last time.
	uint32_t pin_tol; //!< Configured master pin tolerance (0 for no pin).
} zone_master_fallback_t;

typedef int (*zone_master_cb)(conf_t *conf, zone_t *zone, const conf_remote_t *remote,
                              void *data, zone_master_fallback_t *fallback);

/*!
 * \brief Perform an action with all configured master servers.
 *
 * The function iterates over available masters. For each master, the callback
 * function is called once for its every adresses until the callback function
 * succeeds (\ref KNOT_EOK is returned) and then the iteration continues with
 * the next master.
 *
 * \return Error code from the last callback or KNOT_ENOMASTER.
 */
int zone_master_try(conf_t *conf, zone_t *zone, zone_master_cb callback,
                    void *callback_data, const char *err_str);

/*! \brief Write zone contents to zonefile, but into different directory. */
int zone_dump_to_dir(conf_t *conf, zone_t *zone, const char *dir);

/*!
 * \brief Zone inclusion (reverse generation) related ops.
 */
bool zone_includes_configured(conf_t *conf, zone_t *zone);
int zone_includes_add(zone_t *zone, zone_t *include, zone_include_method_t method);
void zone_includes_rem(zone_t *zone, zone_t *include);
void zone_includes_clear(zone_t *zone);

void zone_local_notify_subscribe(zone_t *zone, zone_t *subscribe);
void zone_local_notify_unsubscribe(zone_t *zone, zone_t *subscribe);
void zone_local_notify(conf_t *conf, zone_t *zone);

int zone_set_master_serial(zone_t *zone, uint32_t serial);

int zone_get_master_serial(zone_t *zone, uint32_t *serial);

void zone_set_lastsigned_serial(conf_t *conf, zone_t *zone, uint32_t serial);

int zone_get_lastsigned_serial(zone_t *zone, uint32_t *serial);

int slave_zone_serial(zone_t *zone, conf_t *conf, uint32_t *serial);

time_t zone_bootstrap_next(uint8_t *count);

void zone_update_error(conf_t *conf, zone_t *zone);
