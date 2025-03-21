/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <pthread.h>

/*!
 * \brief New thread using pthread_create() but with signals blocked.
 *
 * \note Some signals that are unpractical to block are still allowed.
 *
 * \param thr     Thread to be launched.
 * \param cb      Callback function to be launched in the thread.
 * \param ctx     Arbitrary context for the callback.
 *
 * \return Return value of ptherad_create().
 *
 * In order to avoid race conditions when the child thread is launched and
 * the signals are blocked within that thread afterwards, this method
 * temporarily blocks the signals in the parent thread, lets the child
 * inherit them blocked, and re-enables in the parent afterwards.
 */
int thread_create_nosignal(pthread_t *thr, void *(*cb)(void *), void *ctx);
