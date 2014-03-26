#pragma once

#include "pkcs8.h"

struct dnssec_pkcs8_ctx {
	const dnssec_pkcs8_functions_t *functions;
	void *data;
};
