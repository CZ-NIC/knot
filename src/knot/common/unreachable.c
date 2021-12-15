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

#include <assert.h>
#include <stdlib.h>
#include <time.h>

#include "unreachable.h"

knot_unreachables_t *global_unreachables = NULL;

static uint32_t get_timestamp(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	uint64_t res = (uint64_t)t.tv_sec * 1000;
	res += (uint64_t)t.tv_nsec / 1000000;
	return res & 0xffffffff; // overflow does not matter since we are working with differences
}

knot_unreachables_t *knot_unreachables_init(uint32_t ttl_ms)
{
	knot_unreachables_t *res = calloc(1, sizeof(*res));
	if (res != NULL) {
		pthread_mutex_init(&res->mutex, NULL);
		res->ttl_ms = ttl_ms;
		init_list(&res->urs);
	}
	return res;
}

uint32_t knot_unreachables_ttl(knot_unreachables_t *urs, uint32_t new_ttl_ms)
{
	if (urs == NULL) {
		return 0;
	}

	pthread_mutex_lock(&urs->mutex);

	uint32_t prev = urs->ttl_ms;
	urs->ttl_ms = new_ttl_ms;

	pthread_mutex_unlock(&urs->mutex);

	return prev;
}

void knot_unreachables_deinit(knot_unreachables_t **urs)
{
	if (urs != NULL && *urs != NULL) {
		knot_unreachable_t *ur, *nxt;
		WALK_LIST_DELSAFE(ur, nxt, (*urs)->urs) {
			rem_node((node_t *)ur);
			free(ur);
		}
		pthread_mutex_destroy(&(*urs)->mutex);
		free(*urs);
		*urs = NULL;
	}
}

static bool clear_old(knot_unreachable_t *ur, uint32_t now, uint32_t ttl_ms)
{
	if (ur->time_ms != 0 && now - ur->time_ms > ttl_ms) {
		rem_node((node_t *)ur);
		free(ur);
		return true;
	}
	return false;
}

// also clears up (some) expired unreachables
static knot_unreachable_t *get_ur(knot_unreachables_t *urs,
                                  const struct sockaddr_storage *addr,
                                  const struct sockaddr_storage *via)
{
	assert(urs != NULL);

	uint32_t now = get_timestamp();
	knot_unreachable_t *ur, *nxt;
	WALK_LIST_DELSAFE(ur, nxt, urs->urs) {
		if (clear_old(ur, now, urs->ttl_ms)) {
			continue;
		}

		if (sockaddr_cmp(&ur->addr, addr, false) == 0 &&
		    sockaddr_cmp(&ur->via, via, true) == 0) {
			return ur;
		}
	}

	return NULL;
}

bool knot_unreachable_is(knot_unreachables_t *urs,
                         const struct sockaddr_storage *addr,
                         const struct sockaddr_storage *via)
{
	if (urs == NULL) {
		return false;
	}
	assert(addr);
	assert(via);

	pthread_mutex_lock(&urs->mutex);

	bool res = (get_ur(urs, addr, via) != NULL);

	pthread_mutex_unlock(&urs->mutex);

	return res;
}

void knot_unreachable_add(knot_unreachables_t *urs,
                          const struct sockaddr_storage *addr,
                          const struct sockaddr_storage *via)
{
	if (urs == NULL) {
		return;
	}
	assert(addr);
	assert(via);

	pthread_mutex_lock(&urs->mutex);

	knot_unreachable_t *ur = malloc(sizeof(*ur));
	if (ur != NULL) {
		memcpy(&ur->addr, addr, sizeof(ur->addr));
		memcpy(&ur->via, via, sizeof(ur->via));
		ur->time_ms = get_timestamp();
		add_head(&urs->urs, (node_t *)ur);
	}

	pthread_mutex_unlock(&urs->mutex);
}
