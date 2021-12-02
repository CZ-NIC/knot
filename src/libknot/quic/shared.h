#pragma once

#include <gnutls/gnutls.h>

int knot_str_to_alpn(gnutls_datum_t *dest, const size_t dest_len,
                     const char *alpn);

int knot_quic_set_ecn(const int fd, const int family, const unsigned char ecn,
                      unsigned char *old_ecn);