#!/bin/sh
cc gnutls_server.c -o gnutls_server $(pkg-config --cflags --libs gnutls)
cc gnutls_client.c -o gnutls_client $(pkg-config --cflags --libs gnutls)
cc openssl_server.c -o openssl_server -lssl -lcrypto
cc openssl_client.c -o openssl_client -lssl -lcrypto
