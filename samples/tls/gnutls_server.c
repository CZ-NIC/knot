#include <gnutls/gnutls.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 5557

int main() {
    gnutls_global_init();
    gnutls_certificate_credentials_t x509_cred;
    gnutls_certificate_allocate_credentials(&x509_cred);
    gnutls_certificate_set_x509_key_file(x509_cred, "cert.pem", "key.pem", GNUTLS_X509_FMT_PEM);
    gnutls_datum_t session_ticket_key = {NULL, 0};
    gnutls_session_ticket_key_generate(&session_ticket_key);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr.s_addr = INADDR_ANY};
    bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    listen(sock, 1);

    printf("🟢 GnuTLS server listening on port %d\n", PORT);

    while (1) {
        int client = accept(sock, NULL, NULL);
        gnutls_session_t session;
        gnutls_init(&session, GNUTLS_SERVER);
        gnutls_priority_set_direct(session, "NORMAL:+VERS-TLS1.3", NULL);
        gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);
        gnutls_session_ticket_enable_server(session, &session_ticket_key);
        gnutls_transport_set_int(session, client);
        gnutls_handshake_set_timeout(session, 1000);
        gnutls_record_set_timeout(session, 1000);

        int ret = gnutls_handshake(session);
        if (ret < 0) {
            fprintf(stderr, "❌ Handshake failed: %s\n", gnutls_strerror(ret));
        } else {
            printf("🔐 GnuTLS session resumed: %s\n", gnutls_session_is_resumed(session) ? "yes" : "no");
            const char msg[] = "Hello from GnuTLS!\n";
            gnutls_record_send(session, msg, sizeof(msg));
        }

        gnutls_bye(session, GNUTLS_SHUT_RDWR);
        gnutls_deinit(session);
        close(client);
    }

    gnutls_free(session_ticket_key.data);
    gnutls_certificate_free_credentials(x509_cred);
    gnutls_global_deinit();
    return 0;
}
