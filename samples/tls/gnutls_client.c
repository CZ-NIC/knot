/* This example code is placed in the public domain. */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void check_alert(gnutls_session_t session, int ret)
{
	int last_alert;

	if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED ||
	    ret == GNUTLS_E_FATAL_ALERT_RECEIVED) {
		last_alert = gnutls_alert_get(session);

		/* The check for renegotiation is only useful if we are 
		 * a server, and we had requested a rehandshake.
		 */
		if (last_alert == GNUTLS_A_NO_RENEGOTIATION &&
		    ret == GNUTLS_E_WARNING_ALERT_RECEIVED)
			printf("* Received NO_RENEGOTIATION alert. "
			       "Client Does not support renegotiation.\n");
		else
			printf("* Received alert '%d': %s.\n", last_alert,
			       gnutls_alert_get_name(last_alert));
	}
}

static int tcp_connect(const char *addr, unsigned port)
{
	int sock;
	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(ss));
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		return -1;
	}

	struct sockaddr_in *sa = (struct sockaddr_in *)&ss;
	sa->sin_family = AF_INET;
	sa->sin_port = htons(port);
	if (inet_pton(AF_INET, addr, &sa->sin_addr) != 1) {
		close(sock);
		return -1;
	}
	if (connect(sock, (struct sockaddr *)sa, sizeof(ss)) != 0) {
		close(sock);
		return -1;
	}
	return sock;
}

static void tcp_close(int sd)
{
	shutdown(sd, SHUT_RDWR); /* no more receptions */
	close(sd);
}

/* A very basic TLS client, with X.509 authentication and server certificate
 * verification as well as session resumption.
 *
 * Note that error recovery is minimal for simplicity.
 */

#define CHECK(x) assert((x) >= 0)
#define LOOP_CHECK(rval, cmd)                                             \
	do {                                                              \
		rval = cmd;                                               \
	} while (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED); \
	assert(rval >= 0)

#define MAX_BUF 1024

int main(void)
{
	int ret;
	int sd, ii;
	gnutls_session_t session;
	char buffer[MAX_BUF + 1];
	gnutls_certificate_credentials_t xcred;

	/* variables used in session resuming 
	 */
	int t;
	gnutls_datum_t sdata;

	/* for backwards compatibility with gnutls < 3.3.0 */
	CHECK(gnutls_global_init());

	CHECK(gnutls_certificate_allocate_credentials(&xcred));
	// CHECK(gnutls_certificate_set_x509_system_trust(xcred));

	for (t = 0; t < 2; t++) { /* connect 2 times to the server */

		sd = tcp_connect("127.0.0.1", 5557);

		CHECK(gnutls_init(&session, GNUTLS_CLIENT));
        gnutls_priority_set_direct(session, "NORMAL:-VERS-ALL:+VERS-TLS1.3", NULL);

		gnutls_transport_set_int(session, sd);
		gnutls_handshake_set_timeout(session,
					     GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

		gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

		if (t > 0) {
			/* if this is not the first time we connect */
			CHECK(gnutls_session_set_data(session, sdata.data,
						      sdata.size));
			gnutls_free(sdata.data);
		}

		/* Perform the TLS handshake
		 */
		do {
			ret = gnutls_handshake(session);
		} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

		if (ret < 0) {
			fprintf(stderr, "*** Handshake failed\n");
			gnutls_perror(ret);
			goto end;
		} else {
			printf("- Handshake was completed\n");
		}

		if (t == 0) { /* the first time we connect */
			/* get the session data */
			CHECK(gnutls_session_get_data2(session, &sdata));
		} else { /* the second time we connect */

			/* check if we actually resumed the previous session */
			if (gnutls_session_is_resumed(session) != 0) {
				printf("- Previous session was resumed\n");
			} else {
				fprintf(stderr,
					"*** Previous session was NOT resumed\n");
			}
		}

		LOOP_CHECK(ret, gnutls_record_recv(session, buffer, MAX_BUF));
		if (ret == 0) {
			printf("- Peer has closed the TLS connection\n");
			goto end;
		} else if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
			fprintf(stderr, "*** Warning: %s\n",
				gnutls_strerror(ret));
		} else if (ret < 0) {
			fprintf(stderr, "*** Error: %s\n",
				gnutls_strerror(ret));
			goto end;
		}

		if (ret > 0) {
			printf("- Received %d bytes: ", ret);
			for (ii = 0; ii < ret; ii++) {
				fputc(buffer[ii], stdout);
			}
			fputs("\n", stdout);
		}

		gnutls_bye(session, GNUTLS_SHUT_RDWR);

	end:

		tcp_close(sd);

		gnutls_deinit(session);

	} /* for() */

	gnutls_certificate_free_credentials(xcred);

	gnutls_global_deinit();

	return 0;
}