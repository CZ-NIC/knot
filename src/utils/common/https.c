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


int https_ctx_init(https_ctx_t *ctx, const https_params_t *params, const char *server, const uint16_t port)
{
    if(ctx == NULL || params == NULL || server == NULL) {
        return KNOT_EINVAL;
    }
    ctx->server.scheme = WGET_IRI_SCHEME_HTTPS;
    ctx->server.host = server;
    ctx->server.is_ip_address = true;
    ctx->server.port = port;
    ctx->server.port_given = true;

    ctx->params = params;

    return KNOT_EOK;
}

int https_ctx_connect(https_ctx_t *ctx)
{
    int ret = wget_http_open(&ctx->connection, &ctx->server);
    if (ret != KNOT_EOK) {
        return KNOT_ECONN;
    }
    return KNOT_EOK;
}

int https_receive_doh_response(https_ctx_t *ctx, uint8_t *buf, const size_t buf_len)
{
    if (ctx->connection) {
		wget_http_response_t *resp = wget_http_get_response(ctx->connection);

        if (resp == NULL) {
            return KNOT_NET_ERECV;
		}

        if(buf_len < resp->body->length) {
            wget_http_free_response(&resp);
            return KNOT_NET_ERECV;
        }
        size_t data_len = resp->body->length;
        memcpy(buf, resp->body->data, data_len);
        wget_http_free_response(&resp);
	    return data_len;
	}
    
    return KNOT_ECONN;
}

int https_send_doh_request(https_ctx_t *ctx, const uint8_t *buf, const size_t buf_len)
{
    /** Connect **/
  	wget_iri_t *iri = &ctx->server;
    wget_http_request_t *req = NULL;

    /** Send **/

    static const char HTTPS_DOH_QUERY_KEY[] = "dns=";
    const size_t query_size = sizeof(HTTPS_DOH_QUERY_KEY) + 2 + buf_len * 4 / 3;
    uint8_t *query = (uint8_t *)calloc(query_size, sizeof(*buf));
    strcpy((char *)query, HTTPS_DOH_QUERY_KEY);
    base64_encode(buf, buf_len, query + 4, query_size - 4);

    iri->path = "dns-query";
    iri->query = query;
    iri->query_allocated = true;

    req = wget_http_create_request(iri, "GET");
    

	wget_http_add_header(req, "User-Agent", "kdig/"PACKAGE_VERSION);
	wget_http_add_header(req, "Accept", "application/dns-message");

	wget_http_request_set_int(req, WGET_HTTP_RESPONSE_KEEPHEADER, 1);

	if (ctx->connection) {
		//wget_http_response_t *resp;

		if (wget_http_send_request(ctx->connection, req) != 0) {
            goto out;
			//resp = wget_http_get_response(ctx->connection);

            /** Receive **/

			//if (!resp) {
			//	goto out;
            //}

			// server doesn't support or want keep-alive
			//if (!resp->keep_alive) {
			//	wget_http_close(&ctx->connection);
            //}

            /** Print **/
            //for(size_t i = 0; i < resp->content_length; i++) {
            //    printf("%u %c\n", resp->body->data[i], resp->body->data[i]);
            //}
			//wget_http_free_response(&resp);
		}
	    wget_http_free_request(&req);
        return KNOT_EOK;
	}
out:
	wget_http_close(&ctx->connection);
	wget_http_free_request(&req);
	wget_iri_free(&iri);
    
    return KNOT_ECONN;
}
