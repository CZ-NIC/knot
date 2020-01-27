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

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <gnutls/gnutls.h>
#include <stdio.h>
#include <stdlib.h>
#include <urcu.h>
#ifdef HAVE_SYS_UIO_H	// struct iovec (OpenBSD)
#include <sys/uio.h>
#endif // HAVE_SYS_UIO_H

#include "knot/server/server.h"
#include "knot/server/tls-handler.h"
#include "knot/common/log.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/layer.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/time.h"
#include "contrib/ucw/mempool.h"
#include "utils/common/tls.h"

/*! \brief TLS context data. */
typedef struct tls_context {
	knot_layer_t layer;                           /*!< Query processing layer. */
	server_t *server;                             /*!< Name server structure. */
	struct iovec iov[2];                          /*!< TX/RX buffers. */
	unsigned client_threshold;                    /*!< Index of first TLS client. */
	struct timespec last_poll_time;               /*!< Time of the last socket poll. */
	bool is_throttled;                            /*!< TLS connections throttling switch. */
	fdset_t set;                                  /*!< Set of server/client sockets. */
	unsigned thread_id;                           /*!< Thread identifier. */
	unsigned max_worker_fds;                      /*!< Max TLS clients per worker configuration + no. of ifaces. */
	int idle_timeout;                             /*!< [s] TLS idle timeout configuration. */
	int io_timeout;                               /*!< [ms] TLS send/recv timeout configuration. */
	gnutls_certificate_credentials_t credentials; /*!< GnuTLS credentials. */
	gnutls_priority_t prority_cache;              /*!< GnuTLS priority cache. */
} tls_context_t;

#define TLS_SWEEP_INTERVAL 2 /*!< [secs] granularity of connection sweeping. */

static void update_sweep_timer(struct timespec *timer)
{
	*timer = time_now();
	timer->tv_sec += TLS_SWEEP_INTERVAL;
}

static void update_tls_conf(tls_context_t *tls)
{
	rcu_read_lock();
	//TODO TLS conf
	tls->max_worker_fds = tls->client_threshold +
		MAX(conf()->cache.srv_tcp_max_clients / conf()->cache.srv_tcp_threads, 1);
	tls->idle_timeout = conf()->cache.srv_tcp_idle_timeout;
	tls->io_timeout = conf()->cache.srv_tcp_io_timeout;
	//TODO END
	rcu_read_unlock();
}

/*! \brief Sweep TCP connection. */
static enum fdset_sweep_state tls_sweep(fdset_t *set, int i, void *data)
{
	UNUSED(data);
	assert(set && i < set->n && i >= 0);
	int fd = set->pfd[i].fd;

	/* Best-effort, name and shame. */
	struct sockaddr_storage ss;
	socklen_t len = sizeof(struct sockaddr_storage);
	if (getpeername(fd, (struct sockaddr*)&ss, &len) == 0) {
		char addr_str[SOCKADDR_STRLEN] = {0};
		sockaddr_tostr(addr_str, sizeof(addr_str), &ss);
		log_notice("TLS, terminated inactive client, address %s", addr_str);
	}

	close(fd);

	return FDSET_SWEEP;
}

static bool tls_active_state(int state)
{
	return (state == KNOT_STATE_PRODUCE || state == KNOT_STATE_FAIL);
}

static bool tls_send_state(int state)
{
	return (state != KNOT_STATE_FAIL && state != KNOT_STATE_NOOP);
}

static void tls_log_error(struct sockaddr_storage *ss, const char *operation, int ret)
{
	/* Don't log ECONN as it usually means client closed the connection. */
	if (ret == KNOT_ETIMEOUT) {
		char addr_str[SOCKADDR_STRLEN] = { 0 };
		sockaddr_tostr(addr_str, sizeof(addr_str), ss);
		log_debug("TLS, %s, address %s (%s)", operation, addr_str, knot_strerror(ret));
	}
}

/*!
 * \brief Make a TCP fdset from current interfaces list.
 *
 * \param  ifaces    Interface list.
 * \param  fds       File descriptor set.
 * \param  thread_id Thread ID used for geting an ID.
 *
 * \return Number of watched descriptors.
 */
static unsigned tls_set_ifaces(const list_t *ifaces, fdset_t *fds, int thread_id)
{
	if (ifaces == NULL) {
		return 0;
	}

	fdset_clear(fds);
	iface_t *i;
	WALK_LIST(i, *ifaces) {
		int tls_id = 0;
#ifdef ENABLE_REUSEPORT
		if (conf()->cache.srv_tcp_reuseport) {
			/* Note: thread_ids start with UDP threads, TCP threads follow. */
			assert((i->fd_udp_count + i->fd_tcp_count <= thread_id) &&
				(thread_id < i->fd_udp_count + i->fd_tcp_count + i->fd_tls_count)
			);

			tls_id = thread_id - (i->fd_udp_count + i->fd_tcp_count);
		}
#endif
		fdset_add(fds, i->fd_tls[tls_id], POLLIN, NULL);
	}

	return fds->n;
}

static int tls_handle(tls_context_t *tls, int i, struct iovec *rx, struct iovec *tx)
{
	/* Get peer name. */
	struct sockaddr_storage ss;
	socklen_t addrlen = sizeof(struct sockaddr_storage);
	gnutls_session_t *session = tls->set.ctx[i];
	int fd = gnutls_transport_get_int(*session);
	if (getpeername(fd, (struct sockaddr *)&ss, &addrlen) != 0) {
		return KNOT_EADDRNOTAVAIL;
	}

	/* Create query processing parameter. */
	knotd_qdata_params_t params = {
		.remote = &ss,
		.socket = fd,
		.server = tls->server,
		.thread_id = tls->thread_id
	};

	rx->iov_len = KNOT_WIRE_MAX_PKTSIZE;
	tx->iov_len = KNOT_WIRE_MAX_PKTSIZE;

	/* Receive data. */
	int recv = gnutls_record_recv(*session, rx->iov_base, rx->iov_len);
	//int recv = net_dns_tls_recv(fd, rx->iov_base, rx->iov_len, tls->io_timeout);
	if (recv > 0 && ntohs(*(uint16_t *)rx->iov_base) == recv - sizeof(uint16_t)) {
		rx->iov_len = recv - sizeof(uint16_t);
		rx->iov_base += sizeof(uint16_t);
	} else {
		tls_log_error(&ss, "receive", recv);
		return KNOT_EOF;
	}

	/* Initialize processing layer. */
	knot_layer_begin(&tls->layer, &params);

	/* Create packets. */
	knot_pkt_t *query = knot_pkt_new(rx->iov_base, rx->iov_len, tls->layer.mm);
	knot_pkt_t *ans = knot_pkt_new(tx->iov_base, tx->iov_len, tls->layer.mm);

	/* Input packet. */
	(void) knot_pkt_parse(query, 0);
	knot_layer_consume(&tls->layer, query);

	int ret = KNOT_EOK;

	/* Resolve until NOOP or finished. */
	while (tls_active_state(tls->layer.state)) {
		knot_layer_produce(&tls->layer, ans);
		/* Send, if response generation passed and wasn't ignored. */
		if (ans->size > 0 && tls_send_state(tls->layer.state)) {
			gnutls_record_cork(*session);
			//int sent = net_dns_tls_send(fd, ans->wire, ans->size, tls->io_timeout);
			uint16_t size = htons((uint16_t)ans->size);
			gnutls_record_send(*session, &size, sizeof(uint16_t));
			int sent = gnutls_record_send(*session, ans->wire, ans->size);
			while (gnutls_record_check_corked(*session) > 0) {
				int ret = gnutls_record_uncork(*session, GNUTLS_RECORD_WAIT);
				if (ret < 0 && gnutls_error_is_fatal(ret) != 0) {
					tls_log_error(&ss, "send", sent);
					ret = KNOT_EOF;
					break;
				}
			}
			if (sent != ans->size) {
				tls_log_error(&ss, "send", sent);
				ret = KNOT_EOF;
				break;
			}
		}
	}

	/* Reset after processing. */
	knot_layer_finish(&tls->layer);

	/* Flush per-query memory (including query and answer packets). */
	mp_flush(tls->layer.mm->ctx);

	gnutls_bye(*session, GNUTLS_SHUT_RDWR);
	return ret;
}

static void tls_event_accept(tls_context_t *tls, unsigned i)
{
	/* Accept client. */
	int fd = tls->set.pfd[i].fd;
	int client = net_accept(fd, NULL);
	gnutls_session_t *session = (gnutls_session_t *)calloc(1, sizeof(gnutls_session_t));
	/* Setup GnuTLS */
	assert(gnutls_init(session, GNUTLS_SERVER) >= 0);
	assert(gnutls_priority_set(*session, tls->prority_cache) >= 0);
	assert(gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, tls->credentials) >= 0);
	// We don't request any certificate from the client. If we did we would need to verify it.
	gnutls_certificate_server_set_request(*session, GNUTLS_CERT_IGNORE);
	gnutls_handshake_set_timeout(*session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT); //TODO conf

	if (client >= 0) {
		/* Assign to fdset. */ //TODO is nesessary for TLS?! We will see
		int next_id = fdset_add(&tls->set, client, POLLIN, session);
		//int next_id = fdset_add(&tls->set, client, POLLIN, NULL);
		if (next_id < 0) {
			close(client);
			return;
		}
		/* Update watchdog timer. */
		fdset_set_watchdog(&tls->set, next_id, tls->idle_timeout);
	}

	gnutls_transport_set_int(*session, client);
	int ret = 0;
	do {
		ret = gnutls_handshake(*session);
	} while(ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
	if (ret < 0) {
		gnutls_deinit(*session);
		free(session);
		close(client);
	}

}

static int tls_event_serve(tls_context_t *tls, unsigned i)
{
	//int fd = tls->set.pfd[i].fd;
	int ret = tls_handle(tls, i, &tls->iov[0], &tls->iov[1]); //TODO `i` targets fd instead of index
	if (ret == KNOT_EOK) {
		/* Update socket activity timer. */
		fdset_set_watchdog(&tls->set, i, tls->idle_timeout);
	}

	return ret;
}

static void tls_wait_for_events(tls_context_t *tls)
{
	fdset_t *set = &tls->set;

	/* Check if throttled with many open TCP connections. */
	assert(set->n <= tls->max_worker_fds);
	tls->is_throttled = set->n == tls->max_worker_fds;

	/* If throttled, temporarily ignore new TCP connections. */
	unsigned i = tls->is_throttled ? tls->client_threshold : 0;

	/* Wait for events. */
	int nfds = poll(&(set->pfd[i]), set->n - i, TLS_SWEEP_INTERVAL * 1000);

	/* Mark the time of last poll call. */
	tls->last_poll_time = time_now();

	/* Process events. */
	while (nfds > 0 && i < set->n) {
		bool should_close = false;
		if (set->pfd[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
			should_close = (i >= tls->client_threshold);
			--nfds;
		} else if (set->pfd[i].revents & (POLLIN)) {
			/* Master sockets - new connection to accept. */
			if (i < tls->client_threshold) {
				/* Don't accept more clients than configured. */
				if (set->n < tls->max_worker_fds) {
					tls_event_accept(tls, i);
				}
			/* Client sockets - already accepted connection or
			   closed connection :-( */
			} else if (tls_event_serve(tls, i) != KNOT_EOK) {
				should_close = true;
			}
			--nfds;
		}

		/* Evaluate. */
		if (should_close) {
			gnutls_session_t *session = set->ctx[i];
			int ret = 0;
			do {
				ret = gnutls_bye(*session, GNUTLS_SHUT_RDWR);
			} while(ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
			free(session);

			close(set->pfd[i].fd);
			fdset_remove(set, i);
		} else {
			++i;
		}
	}
}

int tls_master(dthread_t *thread)
{
	if (thread == NULL || thread->data == NULL) {
		return KNOT_EINVAL;
	}

	iohandler_t *handler = (iohandler_t *)thread->data;
	int ret = KNOT_EOK;

	/* Create big enough memory cushion. */
	knot_mm_t mm;
	mm_ctx_mempool(&mm, 16 * MM_DEFAULT_BLKSIZE);

	/* Create TLS answering context. */
	tls_context_t tls = {
		.server = handler->server,
		.is_throttled = false,
		.thread_id = handler->thread_id[dt_get_id(thread)]
	};

	/* for backwards compatibility with gnutls < 3.3.0 */
	assert(gnutls_global_init() >= 0);

	/* Prepare certificates */
	assert(gnutls_certificate_allocate_credentials(&tls.credentials) >= 0);
	if (/*TODO has certificate*/0) {
		assert(gnutls_certificate_set_x509_trust_file(tls.credentials, "/etc/ssl/certs/ca-certificates.crt", GNUTLS_X509_FMT_PEM) >= 0);
	} else {
		assert(gnutls_certificate_set_x509_system_trust(tls.credentials) >= 0);
	}
	//assert(gnutls_certificate_set_x509_crl_file(tls.credentials, "crl.pem", GNUTLS_X509_FMT_PEM) >= 0);
	assert(gnutls_certificate_set_x509_key_file(tls.credentials, "/home/jhak/Work/knot-dns/cert.pem", "/home/jhak/Work/knot-dns/key.pem", GNUTLS_X509_FMT_PEM) >= 0);
	//assert(gnutls_certificate_set_ocsp_status_request_file(tls.credentials, "ocsp-status.der", 0) >= 0);

	assert(gnutls_priority_init(&tls.prority_cache, NULL, NULL) >= 0);
#if GNUTLS_VERSION_NUMBER >= 0x030506
        gnutls_certificate_set_known_dh_params(tls.credentials, GNUTLS_SEC_PARAM_MEDIUM);
#endif

	knot_layer_init(&tls.layer, &mm, process_query_layer());

	/* Prepare initial buffer for listening and bound sockets. */
	fdset_init(&tls.set, FDSET_INIT_SIZE);

	/* Create iovec abstraction. */
	for (unsigned i = 0; i < 2; ++i) {
		tls.iov[i].iov_len = KNOT_WIRE_MAX_PKTSIZE;
		tls.iov[i].iov_base = malloc(tls.iov[i].iov_len);
		if (tls.iov[i].iov_base == NULL) {
			ret = KNOT_ENOMEM;
			goto finish;
		}
	}

	/* Initialize sweep interval and TLS configuration. */
	struct timespec next_sweep;
	update_sweep_timer(&next_sweep);
	update_tls_conf(&tls); //TODO

	/* Set descriptors for the configured interfaces. */
	tls.client_threshold = tls_set_ifaces(handler->server->ifaces, &tls.set, tls.thread_id);
	if (tls.client_threshold == 0) {
		goto finish; /* Terminate on zero interfaces. */
	}
	for (;;) {
		/* Check for cancellation. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Serve client requests. */
		tls_wait_for_events(&tls);

		/* Sweep inactive clients and refresh TCP configuration. */
		if (tls.last_poll_time.tv_sec >= next_sweep.tv_sec) {
			fdset_sweep(&tls.set, &tls_sweep, NULL);
			update_sweep_timer(&next_sweep);
			update_tls_conf(&tls);
		}
	}

finish:
	free(tls.iov[0].iov_base);
	free(tls.iov[1].iov_base);
	mp_delete(mm.ctx);
	fdset_clear(&tls.set);

	return ret;
}
