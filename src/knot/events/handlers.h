/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "knot/conf/conf.h"
#include "knot/zone/zone.h"
#include "knot/dnssec/zone-events.h" // zone_sign_reschedule_t

/*! \brief Loads or reloads potentially changed zone. */
int event_load(conf_t *conf, zone_t *zone);
/*! \brief Refresh a zone from a master. */
int event_refresh(conf_t *conf, zone_t *zone);
/*! \brief Processes DDNS updates in the zone's DDNS queue. */
int event_update(conf_t *conf, zone_t *zone);
/*! \brief Empties in-memory zone contents. */
int event_expire(conf_t *conf, zone_t *zone);
/*! \brief Flushes zone contents into text file. */
int event_flush(conf_t *conf, zone_t *zone);
/*! \brief Backs up zone contents, metadata, keys, etc to a directory. */
int event_backup(conf_t *conf, zone_t *zone);
/*! \brief Sends notify to slaves. */
int event_notify(conf_t *conf, zone_t *zone);
/*! \brief Signs the zone using its DNSSEC keys, perform key rollovers. */
int event_dnssec(conf_t *conf, zone_t *zone);
/*! \brief NOT A HANDLER, just a helper function to reschedule based on reschedule_t */
void event_dnssec_reschedule(conf_t *conf, zone_t *zone,
                             const zone_sign_reschedule_t *refresh, bool zone_changed);
/*! \brief Validate the wole zone's DNSSEC. */
int event_validate(conf_t *conf, zone_t *zone);
/*! \brief Freeze those events causing zone contents change. */
int event_ufreeze(conf_t *conf, zone_t *zone);
/*! \brief Unfreeze zone updates. */
int event_uthaw(conf_t *conf, zone_t *zone);
/*! \brief When CDS/CDNSKEY published, look for matching DS */
int event_ds_check(conf_t *conf, zone_t *zone);
/*! \brief After change of CDS/CDNSKEY, push the new DS to parent zone as DDNS. */
int event_ds_push(conf_t *conf, zone_t *zone);
/*! \brief After DNSSEC sign, synchronize DNSKEY+CDNSKEY+CDS using DDNS. */
int event_dnskey_sync(conf_t *conf, zone_t *zone);
