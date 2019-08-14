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

/*!
 * \brief Multiplatform spinlock.
 */

#pragma once


/*************/
/* A macOS spinlock, as a fallback. */

#if defined(__APPLE__)

#include <libkern/OSAtomic.h>

#define KNOT_SPIN_T		OSSpinLock
#define KNOT_SPIN_INIT(lock)	*lock = 0
#define KNOT_SPIN_DESTROY(lock)	/* Nothing. */
#define KNOT_SPIN_LOCK(lock)	(OSSpinLockLock(lock))
#define KNOT_SPIN_UNLOCK(lock)	(OSSpinLockUnlock(lock))


/*************/
/* A POSIX pthread spinlock, as a fallback. */

#else

#include <pthread.h>

#define KNOT_SPIN_T		pthread_spinlock_t
#define KNOT_SPIN_INIT(lock)	(pthread_spin_init(lock, PTHREAD_PROCESS_PRIVATE))
#define KNOT_SPIN_DESTROY(lock)	(pthread_spin_destroy(lock))
#define KNOT_SPIN_LOCK(lock)	(pthread_spin_lock(lock))
#define KNOT_SPIN_UNLOCK(lock)	(pthread_spin_unlock(lock))

#endif

