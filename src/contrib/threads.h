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

#include <pthread.h>
#include <signal.h>

/*!
 * \brief Spawn a new thread with different signal handling parameters without
 * risk of signal related race conditions.
 *
 * @param thr pthread_t structure
 * @param attr pthread_attr_t structure
 * @param sa struct sigaction handler to be used within the thread
 * @param sm sigset_t signal mask to be used within the thread
 * @param signals an array of signal numbers to which sigaction should be applied
 * @param nsignals ARR_LEN(signals)
 * @param routine thread entry function
 * @param arg thread argument
 * @returns return value of pthread_create
 */
int thread_create_sigsafe(pthread_t *restrict thr,
			  const pthread_attr_t *restrict attr,
			  const struct sigaction *sa,
			  const sigset_t *sm,
			  const int *signals,
			  int nsignals,
			  void *(*routine)(void *),
			  void *restrict arg);
