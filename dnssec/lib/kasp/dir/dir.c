/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "error.h"
#include "kasp/dir/zone.h"
#include "kasp/internal.h"
#include "key.h"
#include "list.h"
#include "path.h"
#include "shared.h"

#define KASP_DIR_INIT_MODE (S_IRWXU | S_IRGRP|S_IXGRP)

/* -- internal API --------------------------------------------------------- */

typedef struct kasp_dir_ctx {
	char *path;
} kasp_dir_ctx_t;

static int kasp_dir_init(const char *config)
{
	assert(config);

	// existing directory is no-op

	_cleanup_close_ int fd = open(config, O_RDONLY);
	if (fd != -1) {
		struct stat stat = { 0 };
		if (fstat(fd, &stat) == -1) {
			return dnssec_errno_to_error(errno);
		}

		if (!S_ISDIR(stat.st_mode)) {
			return dnssec_errno_to_error(ENOTDIR);
		}

		// TODO: maybe check if the directory is empty?

		return DNSSEC_EOK;
	}

	// create directory

	int r = mkdir(config, KASP_DIR_INIT_MODE);
	if (r != 0) {
		return dnssec_errno_to_error(errno);
	}

	return DNSSEC_EOK;
}

static int kasp_dir_open(void **ctx_ptr, const char *config)
{
	assert(ctx_ptr);
	assert(config);

	kasp_dir_ctx_t *ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		return DNSSEC_ENOMEM;
	}

	clear_struct(ctx);
	ctx->path = path_normalize(config);
	if (!ctx->path) {
		free(ctx);
		return DNSSEC_NOT_FOUND;
	}

	*ctx_ptr = ctx;
	return DNSSEC_EOK;
}

static void kasp_dir_close(void *_ctx)
{
	assert(_ctx);

	kasp_dir_ctx_t *ctx = _ctx;

	free(ctx->path);
	free(ctx);
}

static int kasp_dir_zone_load(void *_ctx, dnssec_kasp_zone_t *zone)
{
	assert(_ctx);
	assert(zone);

	kasp_dir_ctx_t *ctx = _ctx;

	_cleanup_free_ char *config = zone_config_file(ctx->path, zone->name);
	if (!config) {
		return DNSSEC_ENOMEM;
	}

	return load_zone_config(zone, config);
}

static int kasp_dir_zone_save(void *_ctx, dnssec_kasp_zone_t *zone)
{
	assert(_ctx);
	assert(zone);

	kasp_dir_ctx_t *ctx = _ctx;

	_cleanup_free_ char *config = zone_config_file(ctx->path, zone->name);
	if (!config) {
		return DNSSEC_ENOMEM;
	}

	return save_zone_config(zone, config);
}

static int kasp_dir_zone_remove(void *_ctx, const char *zone_name)
{
	assert(_ctx);
	assert(zone_name);

	kasp_dir_ctx_t *ctx = _ctx;

	_cleanup_free_ char *config = zone_config_file(ctx->path, zone_name);
	if (!config) {
		return DNSSEC_ENOMEM;
	}

	if (unlink(config) != 0) {
		return dnssec_errno_to_error(errno);
	}

	return DNSSEC_EOK;
}

static int kasp_dir_zone_list(void *_ctx, dnssec_list_t *list)
{
	assert(_ctx);
	assert(list);

	kasp_dir_ctx_t *ctx = _ctx;

	_cleanup_closedir_ DIR *dir = opendir(ctx->path);
	if (!dir) {
		return DNSSEC_NOT_FOUND;
	}

	int error;
	struct dirent entry, *result;
	while (error = readdir_r(dir, &entry, &result), error == 0 && result) {
		char *zone = zone_name_from_config_file(entry.d_name);
		if (zone) {
			dnssec_list_append(list, zone);
		}
	}

	if (error != 0) {
		return dnssec_errno_to_error(error);
	}

	return DNSSEC_EOK;
}

static const dnssec_kasp_store_functions_t KASP_DIR_FUNCTIONS = {
	.init = kasp_dir_init,
	.open = kasp_dir_open,
	.close = kasp_dir_close,
	.zone_load = kasp_dir_zone_load,
	.zone_save = kasp_dir_zone_save,
	.zone_remove = kasp_dir_zone_remove,
	.zone_list = kasp_dir_zone_list,
};

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_kasp_init_dir(dnssec_kasp_t **kasp_ptr)
{
	return dnssec_kasp_create(kasp_ptr, &KASP_DIR_FUNCTIONS);
}
