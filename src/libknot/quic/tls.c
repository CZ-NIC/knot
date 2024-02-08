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

#include <gnutls/gnutls.h>
#include <stdlib.h>

#include "libknot/quic/tls.h"

#include "contrib/macros.h"
#include "libknot/attribute.h"
#include "libknot/quic/quic.h"

_public_
knot_tls_conn_t *knot_tls_conn_new(knot_tls_ctx_t *ctx, int sock_fd, bool server)
{
	knot_tls_conn_t *res = calloc(1, sizeof(res));
	if (res == NULL) {
		return NULL;
	}

	int ret = knot_quic_conn_session(&res->session, ctx->creds, "NORMAL" /* FIXME */, "dot", false, server);
	if (ret != GNUTLS_E_SUCCESS) {
		goto fail;
	}

	gnutls_record_set_timeout(res->session, ctx->io_timeout_ms); // TODO other timeouts

fail:
	gnutls_deinit(res->session);
	free(res);
	return NULL;

}
