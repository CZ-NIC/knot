/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file caps.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief POSIX 1003.1e capabilities interface.
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef _KNOTD_CAPS_H_
#define _KNOTD_CAPS_H_

#include <unistd.h>
#include <config.h>

/* Include required types. */
#ifdef HAVE_SYS_CAPABILITY_H
#include <sys/capability.h>

/* Check gettid(). */
#ifndef HAVE_GETTID
#include <sys/syscall.h>
static pid_t gettid() {
#ifdef SYS_gettid
	return (pid_t)syscall(SYS_gettid);
#define HAVE_GETTID 1
#else
	return (pid_t)0;
#endif
}
#endif
#else
/* Stub types. */
typedef void* cap_t;
typedef int cap_value_t;
typedef int cap_flag_value_t;
#endif

/* Summarize. */
#ifdef HAVE_SYS_CAPABILITY_H
#ifdef HAVE_GETTID
#define USE_CAPABILITIES
#endif
#endif

/*!
 * \brief Set Permitted & Effective flag.
 * \param caps Capabilities context.
 * \param cp Flag to be set.
 * \retval 0 if success.
 * \retval -1 on error.
 */
static inline int cap_set_pe(cap_t caps, cap_value_t cp) {
#ifdef USE_CAPABILITIES
	return cap_set_flag(caps, CAP_EFFECTIVE, 1, &cp, CAP_SET) +
	       cap_set_flag(caps, CAP_PERMITTED, 1, &cp, CAP_SET);
#else
	return -1;
#endif
}

/*!
 * \brief Apply privileges.
 * \param caps Capabilities context.
 * \retval 0 if success.
 * \retval -1 on error.
 */
static inline int cap_apply(cap_t caps) {
#ifdef USE_CAPABILITIES
	return capsetp(gettid(), caps);
#else
	return -1;
#endif
}

/*!
 * \brief Drop all capabilities.
 * \retval 0 if success.
 * \retval -1 on error.
 */
int cap_drop_all();

#endif //_KNOTD_CAPS_H_
