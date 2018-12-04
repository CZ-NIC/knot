/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "knot/conf/conf.h"
#include "knot/conf/confio.h"
#include "knot/journal/journal.h"
#include "knot/events/events.h"
#include "knot/zone/contents.h"
#include "knot/zone/timers.h"
#include "libknot/dname.h"
#include "libknot/packet/pkt.h"

struct zone_update;

/*!
 * \brief Zone flags.
 */
typedef enum zone_flag_t {
	ZONE_FORCE_AXFR   = 1 << 0, /* Force AXFR as next transfer. */
	ZONE_FORCE_RESIGN = 1 << 1, /* Force zone re-sign. */
	ZONE_FORCE_FLUSH  = 1 << 2, /* Force zone flush. */
} zone_flag_t;

/*!
 * \brief Structure for holding DNS zone.
 */
typedef struct zone
{
	knot_dname_t *name;
	zone_contents_t *contents;
	zone_flag_t flags;

	/*! \brief Dynamic configuration zone change type. */
	conf_io_type_t change_type;

	/*! \brief Zonefile parameters. */
	struct {
		time_t mtime;
		uint32_t serial;
		bool exists;
		bool resigned;
	} zonefile;

	/*! \brief Zone events. */
	zone_timers_t timers;      //!< Persistent zone timers.
	zone_events_t events;      //!< Zone events timers.

	/*! \brief DDNS queue and lock. */
	pthread_mutex_t ddns_lock;
	size_t ddns_queue_size;
	list_t ddns_queue;

	/*! \brief Control update context. */
	struct zone_update *control_update;

	/*! \brief Journal structure. */
	journal_t *journal;

	/*! \brief Journal access lock. */
	pthread_mutex_t journal_lock;

	/*! \brief Ptr to journal DB (in struct server) */
	journal_db_t **journal_db;

	/*! \brief Preferred master lock. */
	pthread_mutex_t preferred_lock;
	/*! \brief Preferred master for remote operation. */
	struct sockaddr_storage *preferred_master;

	/*! \brief Query modules. */
	list_t query_modules;
	struct query_plan *query_plan;
} zone_t;

/*!
 * \brief Creates new zone with emtpy zone content.
 *
 * \param name  Zone name.
 *
 * \return The initialized zone structure or NULL if an error occurred.
 */
zone_t* zone_new(const knot_dname_t *name);

/*!
 * \brief Deallocates the zone structure.
 *
 * \note The function also deallocates all bound structures (contents, etc.).
 *
 * \param zone_ptr Zone to be freed.
 */
void zone_free(zone_t **zone_ptr);

/*!
 * \brief Clears possible control update transaction.
 *
 * \param zone Zone to be cleared.
 */
void zone_control_clear(zone_t *zone);

int zone_change_store(conf_t *conf, zone_t *zone, changeset_t *change);
int zone_changes_clear(conf_t *conf, zone_t *zone);
int zone_changes_load(conf_t *conf, zone_t *zone, list_t *dst, uint32_t from);
int zone_chgset_ctx_load(conf_t *conf, zone_t *zone, chgset_ctx_list_t *dst, uint32_t from);
int zone_in_journal_load(conf_t *conf, zone_t *zone, list_t *dst);
int zone_in_journal_store(conf_t *conf, zone_t *zone, zone_contents_t *new_contents);
int zone_journal_serial(conf_t *conf, zone_t *zone, bool *is_empty, uint32_t *serial_to);

/*! \brief Synchronize zone file with journal. */
int zone_flush_journal(conf_t *conf, zone_t *zone);

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

/*! \brief Get zone SOA RR. */
const knot_rdataset_t *zone_soa(const zone_t *zone);

/*! \brief Check if zone is expired according to timers. */
bool zone_expired(const zone_t *zone);

typedef int (*zone_master_cb)(conf_t *conf, zone_t *zone, const conf_remote_t *remote,
                              void *data);

/*!
 * \brief Perform an action with a first working master server.
 *
 * The function iterates over available masters. For each master, the callback
 * function is called. If the callback function succeeds (\ref KNOT_EOK is
 * returned), the iteration is terminated.
 *
 * \return Error code from the last callback.
 */
int zone_master_try(conf_t *conf, zone_t *zone, zone_master_cb callback,
                    void *callback_data, const char *err_str);


/*! \brief Enqueue UPDATE request for processing. */
int zone_update_enqueue(zone_t *zone, knot_pkt_t *pkt, knotd_qdata_params_t *params);

/*! \brief Dequeue UPDATE request. Returns number of queued updates. */
size_t zone_update_dequeue(zone_t *zone, list_t *updates);

/*! \brief Write zone contents to zonefile, but into different directory. */
int zone_dump_to_dir(conf_t *conf, zone_t *zone, const char *dir);

int zone_set_master_serial(zone_t *zone, uint32_t serial);

int zone_get_master_serial(zone_t *zone, uint32_t *serial);

int zone_set_lastsigned_serial(zone_t *zone, uint32_t serial);

bool zone_get_lastsigned_serial(zone_t *zone, uint32_t *serial);
