/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
}

void knot_sem_reset(knot_sem_t *sem, int value)
{
	assert((sem != NULL) && (value != SEM_STATUS_POSIX) && (sem->status != SEM_STATUS_POSIX));
	pthread_mutex_lock(&sem->status_lock->mutex);
	sem->status = value;
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
	knot_sem_wait(sem); // NOTE this is questionable if the initial value was > 1
	if (sem->status == SEM_STATUS_POSIX) {
		sem_destroy(&sem->semaphore);
	} else {
		pthread_cond_destroy(&sem->status_lock->cond);
		pthread_mutex_destroy(&sem->status_lock->mutex);
		free(sem->status_lock);
	}
}
