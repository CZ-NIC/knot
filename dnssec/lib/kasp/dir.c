#include "error.h"
#include "kasp.h"
#include "kasp/internal.h"
#include "path.h"

/* -- public API ----------------------------------------------------------- */

int dnssec_kasp_open_dir(const char *path, dnssec_kasp_t **kasp_ptr)
{
	if (!path || !kasp_ptr) {
		return DNSSEC_EINVAL;
	}

	dnssec_kasp_t *kasp = calloc(1, sizeof(*kasp));
	if (!kasp) {
		return DNSSEC_ENOMEM;
	}

	kasp->path = path_normalize(path);
	if (!kasp->path) {
		free(kasp);
		return DNSSEC_NOT_FOUND;
	}

	*kasp_ptr = kasp;

	return DNSSEC_EOK;
}

void dnssec_kasp_close(dnssec_kasp_t *kasp)
{
	if (!kasp) {
		return;
	}

	free(kasp->path);
	free(kasp);
}

int dnssec_kasp_get_keys(dnssec_kasp_t *kasp, const char *zone,
			 dnssec_kasp_key_t *keys, size_t *count)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}
