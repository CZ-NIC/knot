/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "unreachable.h"

#include <assert.h>
#include <stdlib.h>
#include <time.h>

knot_unreachables_t *global_unreachables = NULL;

static uint32_t get_timestamp(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	uint64_t res = (uint64_t)t.tv_sec * 1000000;
	res += (uint64_t)t.tv_nsec / 1000;
	return res & 0xffffffff; // overflow does not matter since we are working with differences
}

knot_unreachables_t *knot_unreachables_init(uint32_t ttl)
{
	knot_unreachables_t *res = calloc(1, sizeof(*res) + KNOT_UNREACHABLE_COUNT * sizeof(res->urs[0]));
	if (res != NULL) {
		pthread_mutex_init(&res->mutex, NULL);
		res->ttl = ttl;
	}
	return res;
}

void knot_unreachables_deinit(knot_unreachables_t **urs)
{
	if (*urs != NULL) {
		pthread_mutex_destroy(&(*urs)->mutex);
		free(*urs);
		*urs = NULL;
	}
}

static void clear_old(knot_unreachable_t *ur, uint32_t now, uint32_t ttl)
{
	if (ur->time != 0 && now - ur->time > ttl) {
		memset(ur, 0, sizeof(*ur));
	}
}

// also clears up (some) expired unreachables
// returns either match or free space
static knot_unreachable_t *get_ur(knot_unreachables_t *urs,
                                  const struct sockaddr_storage *addr)
{
	assert(urs != NULL);

	uint32_t now = get_timestamp();
	knot_unreachable_t *oldest = NULL, *clear = NULL;

	for (int i = 0; i < KNOT_UNREACHABLE_COUNT; i++) {
		knot_unreachable_t *ur = &urs->urs[i];
		clear_old(ur, now, urs->ttl);

		if (ur->time == 0) {
			if (clear == NULL) {
				clear = ur;
			}
		} else if (sockaddr_cmp(&ur->addr, addr, false) == 0) {
			return ur;
		} else if (oldest == NULL || ur->time < oldest->time) {
			oldest = ur;
		}
	}

	if (clear == NULL) {
		assert(oldest != NULL);
		memset(oldest, 0, sizeof(*oldest));
		clear = oldest;
	}
	return clear;
}

bool knot_unreachable_is(knot_unreachables_t *urs,
                         const struct sockaddr_storage *addr)
{
	if (urs == NULL) {
		return false;
	}

	pthread_mutex_lock(&urs->mutex);

	bool res = (get_ur(urs, addr)->time != 0);

	pthread_mutex_unlock(&urs->mutex);

	return res;
}

void knot_unreachable_add(knot_unreachables_t *urs,
                          const struct sockaddr_storage *addr)
{

	if (urs == NULL) {
		return;
	}

	pthread_mutex_lock(&urs->mutex);

	knot_unreachable_t *ur = get_ur(urs, addr);
	if (ur->time == 0) {
		memcpy(&ur->addr, addr, sizeof(ur->addr));
	}
	ur->time = get_timestamp();

	pthread_mutex_unlock(&urs->mutex);
}
