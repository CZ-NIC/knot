#include <gnutls/gnutls.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>

#define HOST "localhost"
#define PORT "5557"

int main() {
    gnutls_global_init();
    gnutls_certificate_credentials_t xcred;
    gnutls_certificate_allocate_credentials(&xcred);
    gnutls_datum_t session_data = {0};

    for (int i = 0; i < 2; i++) {
        gnutls_session_t session;
        gnutls_init(&session, GNUTLS_CLIENT);
        gnutls_priority_set_direct(session, "NORMAL:-VERS-ALL:+VERS-TLS1.3", NULL);
        gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
        gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

        if (i) {
            gnutls_session_set_data(session, session_data.data, session_data.size);
            gnutls_free(session_data.data);
        }

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct hostent *h = gethostbyname(HOST);
        struct sockaddr_in sa;
        sa.sin_family = AF_INET;
        sa.sin_port = htons(atoi(PORT));
        memcpy(&sa.sin_addr, h->h_addr, h->h_length);
        connect(sock, (struct sockaddr *)&sa, sizeof(sa));

        gnutls_transport_set_int(session, sock);

        int ret;
        do {
            ret = gnutls_handshake(session);
        } while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
        if (ret < 0) {
            fprintf(stderr, "❌ GnuTLS handshake failed: %s\n", gnutls_strerror(ret));
            gnutls_deinit(session);
            close(sock);
            continue;
        }

        printf("🟡 GnuTLS Session %d: %s\n", i + 1,
               gnutls_session_is_resumed(session) ? "resumed" : "new");

        char buf[128] = {0};
        do {
            ret = gnutls_record_recv(session, buf, sizeof(buf));
        } while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
        printf("📩 GnuTLS Received: %s\n", buf);

        gnutls_session_get_data2(session, &session_data);

        gnutls_bye(session, GNUTLS_SHUT_RDWR);
        gnutls_deinit(session);
        close(sock);
    }

    gnutls_free(session_data.data);
    gnutls_certificate_free_credentials(xcred);
    gnutls_global_deinit();
    return 0;
}
