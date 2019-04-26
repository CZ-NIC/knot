/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <pthread.h>
#include <semaphore.h>

#pragma once

typedef struct {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
} knot_sem_mutex_t;

typedef struct {
	int status;
	union {
		sem_t semaphore;
		knot_sem_mutex_t *status_lock;
	};
} knot_sem_t;

void knot_sem_init(knot_sem_t *sem, unsigned int value);

void knot_sem_wait(knot_sem_t *sem);

void knot_sem_post(knot_sem_t *sem);

void knot_sem_destroy(knot_sem_t *sem);
