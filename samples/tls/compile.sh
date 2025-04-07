#!/bin/sh
gcc gnutls_server.c -o gnutls_server $(pkg-config --cflags --libs gnutls)
gcc gnutls_client.c -o gnutls_client $(pkg-config --cflags --libs gnutls)
gcc openssl_server.c -o openssl_server -lssl -lcrypto
gcc openssl_client.c -o openssl_client -lssl -lcrypto
