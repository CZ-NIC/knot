/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/un.h>

#include "contrib/openbsd/strlcpy.h"
#include "contrib/string.h"
#include "knot/common/log.h"
#include "knot/common/notice.h"

#define PREFIX "notice_event, "

static const char *event_names[] = {
	[NOTICE_EVENT_UPDATE_DS] = "update_ds",
};

const char *event_name(notice_event_t event)
{
	return event_names[event];
}

static void event_write(const char *sock, const knot_dname_t *zone,
                        notice_event_t event, const char *data)
{
	struct sockaddr_un socka = {
		.sun_family = AF_UNIX
	};
	strlcpy(socka.sun_path, sock, sizeof(socka.sun_path));

	int handle = socket(AF_UNIX, SOCK_STREAM, 0);
	if (handle < 0) {
		log_zone_error(zone, PREFIX"unable to create socket '%s' (%s)",
		               sock, strerror(errno));
		return;
	}
	fcntl(handle, F_SETFL, O_NONBLOCK);

	int ret = connect(handle, (struct sockaddr *)&socka, sizeof(socka));
	if (ret >= 0) {
		char buff[KNOT_DNAME_TXT_MAXLEN + 1] = "";
		char *zone_str = knot_dname_to_str(buff, zone, sizeof(buff));
		if (zone_str == NULL) {
			zone_str = "?";
		}

		char *msg = sprintf_alloc("%s %s %s\n", zone_str, event_name(event), data);
		if (msg == NULL) {
			log_zone_error(zone, PREFIX"out of memory");
			close(handle);
			return;
		}
		ret = write(handle, msg, strlen(msg));
		free(msg);
		close(handle);
	}

	if (ret < 0) {
		log_zone_warning(zone, PREFIX"no active listener at socket '%s'", sock);
	}
}

void notice_event(const knot_dname_t *zone, notice_event_t event, const char *data)
{
	if (zone == NULL) {
		log_warning(PREFIX"missing zone specification for event '%s'",
		            event_name(event));
		return;
	}
	if (data == NULL) {
		data = "";
	}

	conf_t *useconf = conf();

	bool event_requested = false;

	for (conf_iter_t iter = conf_iter(useconf, C_NOTICE); iter.code == KNOT_EOK;
	     conf_iter_next(useconf, &iter)) {
		conf_val_t sock = conf_iter_id(useconf, &iter);
		conf_val_t events = conf_id_get(useconf, C_NOTICE, C_EVENT, &sock);
		while (events.code == KNOT_EOK) {
			if (conf_opt(&events) == event) {
				event_write(conf_str(&sock), zone, event, data);
				event_requested = true;
				break;
			}
			conf_val_next(&events);
		}
	}

	if (!event_requested) {
		log_zone_warning(zone, PREFIX"no listener configured for event '%s'",
		                 event_name(event));
	}
}
