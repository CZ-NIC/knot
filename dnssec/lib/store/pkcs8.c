#include "binary.h"
#include "error.h"
#include "key.h"

int pkcs8_open(const char *path)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

int pkcs8_close(void *handle)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

int pkcs8_save(void *handle, const dnssec_key_id_t id, const dnssec_binary_t *pem)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

int pkcs8_get(void *handle, const dnssec_key_id_t id, dnssec_binary_t *pem)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}
