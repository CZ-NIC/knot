#pragma once

#include <sys/socket.h>

const char *knot_inet_ntop(int af, const void *restrict a0, char *restrict s, socklen_t l);