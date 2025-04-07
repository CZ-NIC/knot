#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define HOST "localhost"
#define PORT "5557"

int main() {
    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    SSL_SESSION *session = NULL;

    for (int i = 0; i < 2; i++) {
        SSL *ssl = SSL_new(ctx);

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct hostent *h = gethostbyname(HOST);
        struct sockaddr_in sa;
        sa.sin_family = AF_INET;
        sa.sin_port = htons(atoi(PORT));
        memcpy(&sa.sin_addr, h->h_addr, h->h_length);
        connect(sock, (struct sockaddr *)&sa, sizeof(sa));
        SSL_set_fd(ssl, sock);

        if (session)
            SSL_set_session(ssl, session);

        SSL_connect(ssl);

        printf("🟡 OpenSSL Session %d: %s\n", i + 1,
               SSL_session_reused(ssl) ? "resumed" : "new");

        char buf[128] = {0};
        SSL_read(ssl, buf, sizeof(buf));
        printf("📩 OpenSSL Received: %s", buf);

        if (!session)
            session = SSL_get1_session(ssl);  // Reference counted

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
    }

    SSL_SESSION_free(session);
    SSL_CTX_free(ctx);
    return 0;
}
