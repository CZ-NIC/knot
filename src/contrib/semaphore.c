/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "semaphore.h"

#include <assert.h>
#include <limits.h>
#include <stdlib.h>

#if defined(__APPLE__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#define SEM_STATUS_POSIX INT_MIN

void knot_sem_init(knot_sem_t *sem, int value)
{
	assert((sem != NULL) && (value != SEM_STATUS_POSIX));
	if (value < 0) {
		goto nonposix;
	}
	int ret = sem_init(&sem->semaphore, 1, value);
	if (ret == 0) {
		sem->status = SEM_STATUS_POSIX;
		return;
	}
nonposix:
	knot_sem_init_nonposix(sem, value);
}

void knot_sem_init_nonposix(knot_sem_t *sem, int value)
{
	assert((sem != NULL) && (value != SEM_STATUS_POSIX));
	sem->status = value;
	sem->status_lock = malloc(sizeof(*sem->status_lock));
	pthread_mutex_init(&sem->status_lock->mutex, NULL);
	pthread_cond_init(&sem->status_lock->cond, NULL);
	sem->status_lock->init_status = value;
}

void knot_sem_reset(knot_sem_t *sem, int value)
{
	assert((sem != NULL) && (value != SEM_STATUS_POSIX) && (sem->status != SEM_STATUS_POSIX));
	pthread_mutex_lock(&sem->status_lock->mutex);
	sem->status = value;
	sem->status_lock->init_status = value;
	pthread_cond_signal(&sem->status_lock->cond);
	pthread_mutex_unlock(&sem->status_lock->mutex);
}

void knot_sem_wait(knot_sem_t *sem)
{
	assert(sem != NULL);
	if (sem->status == SEM_STATUS_POSIX) {
		int semret;
		do {
			semret = sem_wait(&sem->semaphore);
		} while (semret != 0); // repeat wait as it might be interrupted by a signal
	} else {
		pthread_mutex_lock(&sem->status_lock->mutex);
		while (sem->status <= 0) {
			pthread_cond_wait(&sem->status_lock->cond, &sem->status_lock->mutex);
		}
		sem->status--;
		pthread_mutex_unlock(&sem->status_lock->mutex);
	}
}

void knot_sem_wait_post(knot_sem_t *sem)
{
	assert((sem != NULL) && (sem->status != SEM_STATUS_POSIX));
	pthread_mutex_lock(&sem->status_lock->mutex);
	while (sem->status <= 0) {
		pthread_cond_wait(&sem->status_lock->cond, &sem->status_lock->mutex);
	}
	pthread_cond_signal(&sem->status_lock->cond);
	pthread_mutex_unlock(&sem->status_lock->mutex);
}

void knot_sem_wait4all(knot_sem_t *sem, int keep_locked)
{
	assert((sem != NULL) && (sem->status != SEM_STATUS_POSIX));
	pthread_mutex_lock(&sem->status_lock->mutex);
	while (sem->status < sem->status_lock->init_status) {
		pthread_cond_wait(&sem->status_lock->cond, &sem->status_lock->mutex);
	}
	if (keep_locked) {
		sem->status -= sem->status_lock->init_status;
	}
	pthread_mutex_unlock(&sem->status_lock->mutex);
}

void knot_sem_get_ahead(knot_sem_t *sem)
{
	assert((sem != NULL) && (sem->status != SEM_STATUS_POSIX));
	pthread_mutex_lock(&sem->status_lock->mutex);
	sem->status--;
	pthread_mutex_unlock(&sem->status_lock->mutex);
}

void knot_sem_get_assert(knot_sem_t *sem)
{
	assert((sem != NULL) && (sem->status != SEM_STATUS_POSIX));
	pthread_mutex_lock(&sem->status_lock->mutex);
	assert(sem->status > 0);
	sem->status--;
	pthread_mutex_unlock(&sem->status_lock->mutex);
}

void knot_sem_post(knot_sem_t *sem)
{
	assert(sem != NULL);
	if (sem->status == SEM_STATUS_POSIX) {
		int semret = sem_post(&sem->semaphore);
		(void)semret;
		assert(semret == 0);
	} else {
		pthread_mutex_lock(&sem->status_lock->mutex);
		sem->status++;
		pthread_cond_signal(&sem->status_lock->cond);
		pthread_mutex_unlock(&sem->status_lock->mutex);
	}
}

void knot_sem_destroy(knot_sem_t *sem)
{
	assert(sem != NULL);
	if (sem->status == SEM_STATUS_POSIX) {
		knot_sem_wait(sem); // NOTE this is questionable if the initial value was > 1
		sem_destroy(&sem->semaphore);
	} else {
		knot_sem_wait4all(sem, 0);
		pthread_cond_destroy(&sem->status_lock->cond);
		pthread_mutex_destroy(&sem->status_lock->mutex);
		free(sem->status_lock);
	}
}
