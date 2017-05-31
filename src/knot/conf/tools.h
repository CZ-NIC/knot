/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file
 *
 * Configuration scheme callbacks.
 *
 * \addtogroup config
 *
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "knot/conf/conf.h"
#include "libknot/yparser/ypscheme.h"

typedef struct knotd_conf_check_extra {
	conf_t *conf;
	knot_db_txn_t *txn;
	const char *file_name;
	size_t line;
	bool check; /*!< Indication of the confio check mode. */
} knotd_conf_check_extra_t;

int conf_exec_callbacks(
	knotd_conf_check_args_t *args
);

int mod_id_to_bin(
	YP_TXT_BIN_PARAMS
);

int mod_id_to_txt(
	YP_BIN_TXT_PARAMS
);

int edns_opt_to_bin(
	YP_TXT_BIN_PARAMS
);

int edns_opt_to_txt(
	YP_BIN_TXT_PARAMS
);

int check_ref(
	knotd_conf_check_args_t *args
);

int check_ref_dflt(
	knotd_conf_check_args_t *args
);

int check_modref(
	knotd_conf_check_args_t *args
);

int check_module_id(
	knotd_conf_check_args_t *args
);

int check_server(
	knotd_conf_check_args_t *args
);

int check_keystore(
	knotd_conf_check_args_t *args
);

int check_policy(
	knotd_conf_check_args_t *args
);

int check_key(
	knotd_conf_check_args_t *args
);

int check_acl(
	knotd_conf_check_args_t *args
);

int check_remote(
	knotd_conf_check_args_t *args
);

int check_submission(
	knotd_conf_check_args_t *args
);

int check_template(
	knotd_conf_check_args_t *args
);

int check_zone(
	knotd_conf_check_args_t *args
);

int include_file(
	knotd_conf_check_args_t *args
);

int load_module(
	knotd_conf_check_args_t *args
);

/*! @} */
