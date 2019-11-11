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

#include "utils/common/https.h"


int https_ctx_init(https_ctx_t *ctx)
{
    ctx->server.scheme = WGET_IRI_SCHEME_HTTPS;
    ctx->server.host = "1.1.1.1";
    ctx->server.is_ip_address = true;
    ctx->server.port = (uint16_t)443;
    ctx->server.port_given = true;

    ctx->use = true;
    return KNOT_EOK;
}

int https_send_doh_request(const uint8_t *buf, const size_t buf_len)
{
    /** Connect **/
    wget_iri_t *uri = (wget_iri_t*)calloc(1, sizeof(wget_iri_t));
  	wget_http_connection_t *conn = NULL;
    wget_http_request_t *req = NULL;

    uri->scheme = WGET_IRI_SCHEME_HTTPS;
    uri->host = "1.1.1.1";
    uri->is_ip_address = true;
    uri->port = (uint16_t)443;
    uri->port_given = true;

    wget_http_open(&conn, uri);

    /** Send **/

    static const char HTTPS_DOH_QUERY_KEY[] = "dns=";
    const size_t query_size = sizeof(HTTPS_DOH_QUERY_KEY) + 2 + buf_len * 4 / 3;
    uint8_t *query = (uint8_t *)calloc(query_size, sizeof(*buf));
    strcpy(query, HTTPS_DOH_QUERY_KEY);
    base64_encode(buf, buf_len, query + 4, query_size - 4);

    uri->path = "dns-query";
    uri->query = query;
    uri->query_allocated = true;

    req = wget_http_create_request(uri, "GET");
    

	wget_http_add_header(req, "User-Agent", "kdig/"PACKAGE_VERSION);
	wget_http_add_header(req, "Accept", "application/dns-message");

	wget_http_request_set_int(req, WGET_HTTP_RESPONSE_KEEPHEADER, 1);

	if (conn) {
		wget_http_response_t *resp;

		if (wget_http_send_request(conn, req) == 0) {
			resp = wget_http_get_response(conn);

            /** Receive **/

			if (!resp) {
				goto out;
            }

			// server doesn't support or want keep-alive
			if (!resp->keep_alive) {
				wget_http_close(&conn);
            }

            /** Print **/
            for(size_t i = 0; i < resp->content_length; i++) {
                printf("%u %c\n", resp->body->data[i], resp->body->data[i]);
            }
			wget_http_free_response(&resp);
		}
	}

out:
	wget_http_close(&conn);
	wget_http_free_request(&req);
	wget_iri_free(&uri);
    
    return KNOT_EOK;
}
