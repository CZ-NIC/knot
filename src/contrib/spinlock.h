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

/*!
 * \brief A C11 atomic implementation of spinlock.
 */

#pragma once

#include <stdbool.h>
#include <stdatomic.h>

/*! \brief Spinlock lock variable type. */
typedef atomic_bool knot_spin_t;

/*! \brief Initialize the spinlock pointed to by the parameter "lock". */
static inline void knot_spin_init(knot_spin_t *lock)
{
	atomic_init(lock, false);
}

/*! \brief Destroy the spinlock pointed to by the parameter "lock". */
static inline void knot_spin_destroy(knot_spin_t *lock)
{
	/* Nothing needed here. */
}

/*! \brief Lock the spinlock pointed to by the parameter "lock". */
static inline void knot_spin_lock(knot_spin_t *lock)
{
	knot_spin_t expected = false;
	while (!atomic_compare_exchange_strong(lock, &expected, true)) {
		expected = false;
	}
}

/*! \brief Unlock the spinlock pointed to by the parameter "lock". */
static inline void knot_spin_unlock(knot_spin_t *lock)
{
	atomic_store(lock, false);
}
