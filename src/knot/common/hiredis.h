/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief Extension of hiredis to support GnuTLS backend.
 */

#pragma once

#include <hiredis/hiredis.h>

#include "libknot/quic/tls_common.h"

int hiredis_attach_gnutls(redisContext *ctx, struct knot_creds *creds);
