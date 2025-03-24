/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdio.h>

#define ERROR_		";; ERROR: "
#define INFO_		";; INFO: "
#define WARNING_	";; WARNING: "
#define DEBUG_		";; DEBUG: "

#define ERR(msg, ...)	do { fprintf(stderr, ERROR_   msg "\n", ##__VA_ARGS__); fflush(stderr); } while (0)
#define INFO(msg, ...)	do { fprintf(stdout, INFO_    msg "\n", ##__VA_ARGS__); fflush(stdout); } while (0)
#define WARN(msg, ...)	do { fprintf(stderr, WARNING_ msg "\n", ##__VA_ARGS__); fflush(stderr); } while (0)
#define DBG(msg, ...)	do { msg_debug(DEBUG_         msg "\n", ##__VA_ARGS__); fflush(stdout); } while (0)

/*! \brief Enable/disable debugging. */
int msg_enable_debug(int val);

/*! \brief Print debug message. */
int msg_debug(const char *fmt, ...);

/*! \brief Debug message for null input. */
#define DBG_NULL	DBG("%s: null parameter", __func__)

#define ERR2(msg, ...)	do { fprintf(stderr, "error: "   msg "\n", ##__VA_ARGS__); fflush(stderr); } while (0)
#define WARN2(msg, ...)	do { fprintf(stderr, "warning: " msg "\n", ##__VA_ARGS__); fflush(stderr); } while (0)
#define INFO2(msg, ...)	do { fprintf(stdout,             msg "\n", ##__VA_ARGS__); fflush(stdout); } while (0)
