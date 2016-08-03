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

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <assert.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <contrib/print.h>
#include <contrib/base64.h>

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#include "utils/common/netio.h"
#include "utils/common/msg.h"
#include "utils/common/cert.h"
#include "libknot/libknot.h"
#include "contrib/sockaddr.h"

srv_info_t* srv_info_create(const char *name, const char *service)
{
	if (name == NULL || service == NULL) {
		DBG_NULL;
		return NULL;
	}

	// Create output structure.
	srv_info_t *server = calloc(1, sizeof(srv_info_t));

	// Check output.
	if (server == NULL) {
		return NULL;
	}

	// Fill output.
	server->name = strdup(name);
	server->service = strdup(service);

	if (server->name == NULL || server->service == NULL) {
		srv_info_free(server);
		return NULL;
	}

	// Return result.
	return server;
}

void srv_info_free(srv_info_t *server)
{
	if (server == NULL) {
		DBG_NULL;
		return;
	}

	free(server->name);
	free(server->service);
	free(server);
}

int get_iptype(const ip_t ip)
{
	switch (ip) {
	case IP_4:
		return AF_INET;
	case IP_6:
		return AF_INET6;
	default:
		return AF_UNSPEC;
	}
}

int get_socktype(const protocol_t proto, const uint16_t type)
{
	switch (proto) {
	case PROTO_TCP:
		return SOCK_STREAM;
	case PROTO_UDP:
		return SOCK_DGRAM;
	default:
		if (type == KNOT_RRTYPE_AXFR || type == KNOT_RRTYPE_IXFR) {
			return SOCK_STREAM;
		} else {
			return SOCK_DGRAM;
		}
	}
}

const char* get_sockname(const int socktype)
{
	switch (socktype) {
	case SOCK_STREAM:
		return "TCP";
	case SOCK_DGRAM:
		return "UDP";
	default:
		return "UNKNOWN";
	}
}

static int get_addr(const srv_info_t *server,
                    const int        iptype,
                    const int        socktype,
                    struct addrinfo  **info)
{
	struct addrinfo hints;

	// Set connection hints.
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = iptype;
	hints.ai_socktype = socktype;

	// Get connection parameters.
	if (getaddrinfo(server->name, server->service, &hints, info) != 0) {
		ERR("can't resolve address %s@%s\n",
		    server->name, server->service);
		return -1;
	}

	return 0;
}

void get_addr_str(const struct sockaddr_storage *ss,
                  const int                     socktype,
                  char                          **dst)
{
	char addr_str[SOCKADDR_STRLEN] = {0};

	// Get network address string and port number.
	sockaddr_tostr(addr_str, sizeof(addr_str), (struct sockaddr *)ss);

	// Calculate needed buffer size
	const char *sock_name = get_sockname(socktype);
	size_t buflen = strlen(addr_str) + strlen(sock_name) + 3 /* () */;

	// Free previous string if any and write result
	free(*dst);
	*dst = malloc(buflen);
	if (*dst != NULL) {
		int ret = snprintf(*dst, buflen, "%s(%s)", addr_str, sock_name);
		if (ret <= 0 || ret >= buflen) {
			**dst = '\0';
		}
	}
}

static char *strip_quotes(char *value) {
	if (value == NULL) {
		return NULL;
	}

	int value_len = strlen(value);
	if (value[0] == '"') {
		value++; value_len--;
		if ((value_len <= 1) || (value[value_len-1] != '"')) {
			return NULL;
		}
		value[value_len-1] = '\0'; value_len--;
	}
	return value;
}

typedef enum {
	KNOT_TLS_PROFILE_PIN_END      = 0, /*!< End of TLS Profile String. */
	KNOT_TLS_PROFILE_PIN_DEFAULT  = 1, /*!< Just use default x509 CA list */
	KNOT_TLS_PROFILE_PIN_HOSTNAME = 2, /*!< hostname="<string>" */
	KNOT_TLS_PROFILE_PIN_SHA256   = 3, /*!< pin-sha256="<base64>" */
	KNOT_TLS_PROFILE_PIN_CAFILE   = 4, /*!< ca-file="<filename>" */
} knot_tls_profile_pin_t;

static int parse_pin(char *tls_pin, char **value, char **saveptr) {
	char *token = strtok_r(tls_pin, ";", saveptr);

	if (token == NULL) {
		return KNOT_TLS_PROFILE_PIN_END;
	}

	char *key = strtok_r(token, "=", value);

	if (key == NULL || (*value = strip_quotes(*value)) == NULL) {
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	if (strcmp(key, "default") == 0) {
		return KNOT_TLS_PROFILE_PIN_DEFAULT;
	} else if (strcmp(key, "hostname") == 0) {
		return KNOT_TLS_PROFILE_PIN_HOSTNAME;
	} else if (strcmp(key, "pin-sha256") == 0) {
		return KNOT_TLS_PROFILE_PIN_SHA256;
	} else if (strcmp(key, "ca-file") == 0) {
		return KNOT_TLS_PROFILE_PIN_CAFILE;
	} else {
		INFO("invalid value = '%s'\n", token);
		return KNOT_EINVAL;
	}
}

static int compare_pin(gnutls_session_t session, uint8_t *pin, size_t pin_len) {
	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509) {	\
		ERR("Invalid certificate type\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	unsigned int raw_certificate_list_size;
	const gnutls_datum_t *raw_certificate_list =			\
		gnutls_certificate_get_peers(session, &raw_certificate_list_size);
	if (raw_certificate_list == NULL || raw_certificate_list_size == 0) {
		ERR("Certificate list is empty\n");
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}

	for (int i = 0; i < raw_certificate_list_size; i++) {
		int ret;
		gnutls_x509_crt_t certificate;
		if ((ret = gnutls_x509_crt_init(&certificate)) < 0) {
			return ret;
		}

		if ((ret = gnutls_x509_crt_import(certificate,
						  &raw_certificate_list[i],
						  GNUTLS_X509_FMT_DER)) < 0) {
			gnutls_x509_crt_deinit(certificate);
			return ret;
		}

		uint8_t cert_pin[CERT_PIN_LEN] = { 0 };
		if ((ret = cert_get_pin(certificate, cert_pin, sizeof(cert_pin))) < 0) {
			gnutls_x509_crt_deinit(certificate);
			return GNUTLS_E_CERTIFICATE_ERROR;
		}
		gnutls_x509_crt_deinit(certificate);

		if (pin_len == sizeof(cert_pin) &&
		    memcmp(cert_pin, pin, sizeof(cert_pin)) == 0) {
			// Matching PIN was found
			return 1;
		}
	}

	// No matching PIN was found
	return 0;
}

static int verify_x509_peers(gnutls_session_t session, gnutls_typed_vdata_st *data, int data_len) {
	if (data_len == 0) {
		// We don't have any data to verify
		return 0;
	}

	unsigned int status;
	int ret;
	ret = gnutls_certificate_verify_peers(session, data, data_len,
					      &status);
	for (int i = 0; i < data_len; i++) {
		if (data[i].type == GNUTLS_DT_DNS_HOSTNAME) {
			free(data[i].data);
		}
	}

	if (ret < 0) {
		ERR("Error in peer certificate verification\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	gnutls_datum_t out;
	if ((ret = gnutls_certificate_verification_status_print(status,
								gnutls_certificate_type_get(session),
								&out, 0)) < 0) {
		ERR("Error in peer certificate verification\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	gnutls_free(out.data);

	if (status != 0)        // Certificate is not trusted
		return GNUTLS_E_CERTIFICATE_ERROR;

	return 0;
}

static int verify_certificate_oob(gnutls_session_t session)
{
	net_t *net = gnutls_session_get_ptr(session);
	bool pin_seen = false, pin_required = false;

	gnutls_typed_vdata_st data[64];
	int data_len = 0;

	for (char *tls_pin = net->tls_pin;;tls_pin = NULL) {
		char *value, *saveptr;
		int ret;

		if ((ret = parse_pin(tls_pin, &value, &saveptr)) < 0) {
			ERR("Invalid TLS Privacy Profile Pin Key: %s.\n", net->tls_pin);
			return GNUTLS_E_CERTIFICATE_ERROR;
		}

		if (ret == KNOT_TLS_PROFILE_PIN_END) {
			break;
		}

		switch (ret) {
		case KNOT_TLS_PROFILE_PIN_DEFAULT:
			// Verify certificate using credentials
			data[data_len].type = GNUTLS_DT_KEY_PURPOSE_OID;
			data[data_len].data = (void *)GNUTLS_KP_TLS_WWW_SERVER;
			data[data_len].size = 0;
			data_len++;
			break;
		case KNOT_TLS_PROFILE_PIN_HOSTNAME:
			// Verify peer hostname
			data[data_len].type = GNUTLS_DT_DNS_HOSTNAME;
			data[data_len].data = (void *)strdup(value);
			data[data_len].size = 0;
			data_len++;
			break;
		case KNOT_TLS_PROFILE_PIN_SHA256:
			// Verify peer certificate using SPKI SHA256 PIN
			pin_required = true;

			if (pin_seen) { // We have already verified the peer certificate
				break;
			}

			uint8_t pin[64] = { 0 };
			int pin_len;
			if ((pin_len = base64_decode((uint8_t *)value, strlen(value),
							 pin, sizeof(pin))) < 0) {
				ERR("Invalid pin-sha256=\"%s\"\n", value);
				return GNUTLS_E_CERTIFICATE_ERROR;
			}

			if ((ret = compare_pin(session, pin, pin_len)) < 0) {
				return ret;
			}
			pin_seen = (ret == 1) ? true : false;
			break;
		case KNOT_TLS_PROFILE_PIN_CAFILE:
			/* This verification function uses the trusted CAs in the credentials
			 * structure. So you must have installed one or more CA certificates.
			 */
			if ((gnutls_certificate_set_x509_trust_file(net->tls_creds, value,
								    GNUTLS_X509_FMT_PEM)) < 0) {
				ERR("Adding trusted CAs from %s failed.\n", value);
				return GNUTLS_E_CERTIFICATE_ERROR;
			}

			data[data_len].type = GNUTLS_DT_KEY_PURPOSE_OID;
			data[data_len].data = (void *)GNUTLS_KP_TLS_WWW_SERVER;
			data[data_len].size = 0;
			data_len++;
			break;
		default:
			ERR("Invalid TLS Privacy Profile Pin Key: %s.\n", net->tls_pin);
			return GNUTLS_E_CERTIFICATE_ERROR;
		}
	}

	if ((pin_required == true) && (pin_seen == false)) {
		ERR("certificate PIN required but not seen.\n");
	}

	return verify_x509_peers(session, data, data_len);
}

static int verify_certificate_callback(gnutls_session_t session)
{
	net_t *net = gnutls_session_get_ptr(session);

	switch (net->tls) {
	case TLS_PROFILE_NONE:
		ERR("TLS in progress, but TLS Profile set to TLS_PROFILE_NONE\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	case TLS_PROFILE_OPPORTUNISTIC:
		// Accept any certificate
		return 0;
	case TLS_PROFILE_OOB_PINNED:
		return verify_certificate_oob(session);
	default:
		ERR("Unknown TLS Privacy Profile.\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}
}

int net_init(const srv_info_t    *local,
             const srv_info_t    *remote,
             const int           iptype,
             const int           socktype,
             const int           wait,
	     const tls_profile_t tls,
	     const char          *tls_pin,
             net_t               *net)
{
	if (remote == NULL || net == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// Clean network structure.
	memset(net, 0, sizeof(*net));

	// Get remote address list.
	if (get_addr(remote, iptype, socktype, &net->remote_info) != 0) {
		return KNOT_NET_EADDR;
	}

	// Set current remote address.
	net->srv = net->remote_info;

	// Get local address if specified.
	if (local != NULL) {
		if (get_addr(local, iptype, socktype, &net->local_info) != 0) {
			return KNOT_NET_EADDR;
		}
	}

	// Store network parameters.
	net->iptype = iptype;
	net->socktype = socktype;
	net->wait = wait;
	net->local = local;
	net->remote = remote;

	if (tls != TLS_PROFILE_NONE) {
		net->tls = tls;
		if (tls == TLS_PROFILE_OOB_PINNED) {
			net->tls_pin = strdup(tls_pin);
		}

		if (gnutls_certificate_allocate_credentials(&net->tls_creds) < 0) {
			return KNOT_ENOMEM;
		}
		gnutls_certificate_set_verify_function(net->tls_creds,
						       verify_certificate_callback);

		int ret;
		if ((ret = gnutls_certificate_set_x509_system_trust(net->tls_creds)) < 0) {
			if (ret != GNUTLS_E_UNIMPLEMENTED_FEATURE) {
				WARN("gnutls_certificate_set_x509_system_trust() failed: (%d) %s\n",
				     ret, gnutls_strerror_name(ret));
			}
		}

		if (gnutls_init(&net->tls_session, GNUTLS_CLIENT | GNUTLS_NONBLOCK) < 0) {
			return KNOT_NET_ECONNECT;
		}
		if (gnutls_set_default_priority(net->tls_session) < 0) {
			return KNOT_NET_ECONNECT;
		}
	}

	return KNOT_EOK;
}

int net_connect(net_t *net)
{
	struct pollfd pfd;
	int           sockfd;

	if (net == NULL || net->srv == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// Set remote information string.
	get_addr_str((struct sockaddr_storage *)net->srv->ai_addr,
	             net->socktype, &net->remote_str);

	// Create socket.
	sockfd = socket(net->srv->ai_family, net->socktype, 0);
	if (sockfd == -1) {
		WARN("can't create socket for %s\n", net->remote_str);
		return KNOT_NET_ESOCKET;
	}

	// Initialize poll descriptor structure.
	pfd.fd = sockfd;
	pfd.events = POLLOUT;
	pfd.revents = 0;

	// Set non-blocking socket.
	if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
		WARN("can't set non-blocking socket for %s\n", net->remote_str);
		return KNOT_NET_ESOCKET;
	}

	// Bind address to socket if specified.
	if (net->local_info != NULL) {
		if (bind(sockfd, net->local_info->ai_addr,
		         net->local_info->ai_addrlen) == -1) {
			WARN("can't assign address %s\n", net->local->name);
			return KNOT_NET_ESOCKET;
		}
	}

	if (net->socktype == SOCK_STREAM) {
		int       cs, err = 0;
		socklen_t err_len = sizeof(err);

		// Connect using socket.
		if (connect(sockfd, net->srv->ai_addr, net->srv->ai_addrlen)
		    == -1 && errno != EINPROGRESS) {
			WARN("can't connect to %s\n", net->remote_str);
			close(sockfd);
			return KNOT_NET_ECONNECT;
		}

		// Check for connection timeout.
		if (poll(&pfd, 1, 1000 * net->wait) != 1) {
			WARN("connection timeout for %s\n", net->remote_str);
			close(sockfd);
			return KNOT_NET_ECONNECT;
		}

		// Check if NB socket is writeable.
		cs = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &err_len);
		if (cs < 0 || err != 0) {
			WARN("can't connect to %s\n", net->remote_str);
			close(sockfd);
			return KNOT_NET_ECONNECT;
		}
	}

	// Store socket descriptor.
	net->sockfd = sockfd;

	if (net->tls) {
		if (gnutls_credentials_set(net->tls_session, GNUTLS_CRD_CERTIFICATE, net->tls_creds) < 0) {
			return KNOT_NET_ECONNECT;
		}
		gnutls_session_set_ptr(net->tls_session, net);
		if (gnutls_server_name_set(net->tls_session, GNUTLS_NAME_DNS, net->remote->name,
					   strlen(net->remote->name)) < 0) {
			return KNOT_NET_ECONNECT;
		}

		if (gnutls_set_default_priority(net->tls_session) < 0) {
			return KNOT_NET_ECONNECT;
		}

		gnutls_transport_set_int(net->tls_session, net->sockfd);

		int ret;

		// Perform the TLS handshake
		do {
			ret = gnutls_handshake(net->tls_session);
		}
		while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
		if (ret < 0) {
			ERR("TLS handshake failed: %s\n", gnutls_strerror(ret));
			return KNOT_NET_ESOCKET;
		}
	}

	return KNOT_EOK;
}

int net_set_local_info(net_t *net)
{
	if (net == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	if (net->local_info != NULL) {
		freeaddrinfo(net->local_info);
	}

	socklen_t local_addr_len = sizeof(struct sockaddr_storage);
	struct sockaddr_storage *local_addr = calloc(1, local_addr_len);

	if (getsockname(net->sockfd, (struct sockaddr *)local_addr,
	                &local_addr_len) == -1) {
		WARN("can't get local address\n");
		free(local_addr);
		return KNOT_NET_ESOCKET;
	}

	net->local_info = calloc(1, sizeof(struct addrinfo));
	net->local_info->ai_family = net->srv->ai_family;
	net->local_info->ai_socktype = net->srv->ai_socktype;
	net->local_info->ai_protocol = net->srv->ai_protocol;
	net->local_info->ai_addrlen = local_addr_len;
	net->local_info->ai_addr = (struct sockaddr *)local_addr;

	get_addr_str((struct sockaddr_storage *)net->local_info->ai_addr,
	             net->socktype, &net->local_str);

	return KNOT_EOK;
}

int net_send(const net_t *net, const uint8_t *buf, const size_t buf_len)
{
	if (net == NULL || buf == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	if (net->socktype == SOCK_STREAM) {

		if (net->tls) {
			// Send data over TLS
			ssize_t ret;
			uint16_t pktsize = htons(buf_len);
			ret = gnutls_record_send(net->tls_session, &pktsize, sizeof(pktsize));
			do {
				ret = gnutls_record_send(net->tls_session, buf, buf_len);
			}
			while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
			if (ret < 0) {
				// Peer has closed the connectin
				WARN("can't send query to %s: %s\n", net->remote_str, gnutls_strerror(ret));
				return KNOT_NET_ESEND;
			}
			if (ret == 0) {
				WARN("can't send query to %s\n", net->remote_str);
				return KNOT_NET_ESEND;
			}
			do {
				ret = gnutls_record_send(net->tls_session, buf, buf_len);
			}
			while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
			if (ret < 0) {
				// Peer has closed the connectin
				WARN("can't send query to %s: %s\n", net->remote_str, gnutls_strerror(ret));
				return KNOT_NET_ESEND;
			}
			if (ret == 0) {
				WARN("can't send query to %s\n", net->remote_str);
				return KNOT_NET_ESEND;
			}

		} else {
			// Send data over TCP
			struct iovec iov[2];

			// Leading packet length bytes.
			uint16_t pktsize = htons(buf_len);

			iov[0].iov_base = &pktsize;
			iov[0].iov_len = sizeof(pktsize);
			iov[1].iov_base = (uint8_t *)buf;
			iov[1].iov_len = buf_len;

			// Compute packet total length.
			ssize_t total = iov[0].iov_len + iov[1].iov_len;

			if (writev(net->sockfd, iov, 2) != total) {
				WARN("can't send query to %s\n", net->remote_str);
				return KNOT_NET_ESEND;
			}
		}
	} else {
		// Send data over UDP
		if (sendto(net->sockfd, buf, buf_len, 0, net->srv->ai_addr,
		           net->srv->ai_addrlen) != (ssize_t)buf_len) {
			WARN("can't send query to %s\n", net->remote_str);
			return KNOT_NET_ESEND;
		}
	}

	return KNOT_EOK;
}

int net_receive(const net_t *net, uint8_t *buf, const size_t buf_len)
{
	ssize_t       ret;
	struct pollfd pfd;
	uint32_t total = 0;

	if (net == NULL || buf == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// Initialize poll descriptor structure.
	pfd.fd = net->sockfd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	if (net->socktype == SOCK_STREAM) {

		if (net->tls) {
			uint16_t msg_len = 0;
			do {
				ret = gnutls_record_recv(net->tls_session, &msg_len, sizeof(msg_len));
			}
			while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
			if (ret <= 0) {
				WARN("can't receive reply from %s; peer has closed the TLS connection\n",
				     net->remote_str);
				return KNOT_NET_ERECV;
			}
			// Receive data over TLS
			total = 0;
			do {
				ret = gnutls_record_recv(net->tls_session, buf, buf_len);
			}
			while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
			if (ret <= 0) {
				WARN("can't receive reply from %s; peer has closed the TLS connection\n",
				     net->remote_str);
				return KNOT_NET_ERECV;
			}
			total = ret;
		} else {
			// Receive data over TCP
			uint16_t msg_len = 0;
			uint32_t total = 0;
			// Receive TCP message header.
			while (total < sizeof(msg_len)) {
				if (poll(&pfd, 1, 1000 * net->wait) != 1) {
					WARN("response timeout for %s\n",
					     net->remote_str);
					return KNOT_NET_ETIMEOUT;
				}

				// Receive piece of message.
				ret = recv(net->sockfd, (uint8_t *)&msg_len + total,
					   sizeof(msg_len) - total, 0);
				if (ret <= 0) {
					WARN("can't receive reply from %s\n",
					     net->remote_str);
					return KNOT_NET_ERECV;
				}
				total += ret;
			}

			// Convert number to host format.
			msg_len = ntohs(msg_len);

			total = 0;

			// Receive whole answer message by parts.
			while (total < msg_len) {
				if (poll(&pfd, 1, 1000 * net->wait) != 1) {
					WARN("response timeout for %s\n",
					     net->remote_str);
					return KNOT_NET_ETIMEOUT;
				}

				// Receive piece of message.
				ret = recv(net->sockfd, buf + total, msg_len - total, 0);
				if (ret <= 0) {
					WARN("can't receive reply from %s\n",
					     net->remote_str);
					return KNOT_NET_ERECV;
				}
				total += ret;
			}
		}

		return total;
	} else {
		struct sockaddr_storage from;
		memset(&from, '\0', sizeof(from));

		// Receive replies unless correct reply or timeout.
		while (true) {
			socklen_t from_len = sizeof(from);

			// Wait for datagram data.
			if (poll(&pfd, 1, 1000 * net->wait) != 1) {
				WARN("response timeout for %s\n",
				     net->remote_str);
				return KNOT_NET_ETIMEOUT;
			}

			// Receive whole UDP datagram.
			ret = recvfrom(net->sockfd, buf, buf_len, 0,
			               (struct sockaddr *)&from, &from_len);
			if (ret <= 0) {
				WARN("can't receive reply from %s\n",
				     net->remote_str);
				return KNOT_NET_ERECV;
			}

			// Compare reply address with the remote one.
			if (from_len > sizeof(from) ||
			    memcmp(&from, net->srv->ai_addr, from_len) != 0) {
				char *src = NULL;
				get_addr_str(&from, net->socktype, &src);
				WARN("unexpected reply source %s\n", src);
				free(src);
				continue;
			}

			return ret;
		}
	}

	return KNOT_NET_ERECV;
}

void net_close(net_t *net)
{
	if (net == NULL) {
		DBG_NULL;
		return;
	}

	if (net->tls_session != NULL) {
		char *desc = gnutls_session_get_desc(net->tls_session);
		printf(";; TLS session info: %s\n", desc);
		gnutls_free(desc);
		gnutls_bye(net->tls_session, GNUTLS_SHUT_RDWR);
	}

	close(net->sockfd);
	net->sockfd = -1;

	gnutls_deinit(net->tls_session);

	if (net->tls_pin != NULL) {
		free(net->tls_pin);
	}

	if (net->tls_creds != NULL) {
		gnutls_certificate_free_credentials(net->tls_creds);
	}
}

void net_clean(net_t *net)
{
	if (net == NULL) {
		DBG_NULL;
		return;
	}

	free(net->local_str);
	free(net->remote_str);

	if (net->local_info != NULL) {
		freeaddrinfo(net->local_info);
	}

	if (net->remote_info != NULL) {
		freeaddrinfo(net->remote_info);
	}

	if (net->tls) {
		gnutls_global_deinit();
	}
}
