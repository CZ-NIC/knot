/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "knot/conf/conf.h"
#include "libknot/yparser/ypschema.h"

typedef struct knotd_conf_check_extra {
	conf_t *conf;
	knot_db_txn_t *txn;
	const char *file_name;
	size_t line;
	bool check; /*!< Indication of the confio check mode. */
} knotd_conf_check_extra_t;

int legacy_item(
	knotd_conf_check_args_t *args
);

int conf_exec_callbacks(
	knotd_conf_check_args_t *args
);

int mod_id_to_bin(
	YP_TXT_BIN_PARAMS
);

int mod_id_to_txt(
	YP_BIN_TXT_PARAMS
);

int rrtype_to_bin(
	YP_TXT_BIN_PARAMS
);

int rrtype_to_txt(
	YP_BIN_TXT_PARAMS
);

int rdname_to_bin(
	YP_TXT_BIN_PARAMS
);

int rdname_to_txt(
	YP_BIN_TXT_PARAMS
);

int check_ref(
	knotd_conf_check_args_t *args
);

int check_ref_dflt(
	knotd_conf_check_args_t *args
);

int check_ref_empty(
	knotd_conf_check_args_t *args
);

int check_listen(
	knotd_conf_check_args_t *args
);

int check_xdp_listen(
	knotd_conf_check_args_t *args
);

int check_cert_pin(
	knotd_conf_check_args_t *args
);

int check_cert_validate(
	knotd_conf_check_args_t *args
);

int check_modulo(
	knotd_conf_check_args_t *args
);

int check_modulo_shift(
	knotd_conf_check_args_t *args
);

int check_ctl_listen(
	knotd_conf_check_args_t *args
);

int check_database(
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

int check_xdp(
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

int check_remotes(
	knotd_conf_check_args_t *args
);

int check_dnskey_sync(
	knotd_conf_check_args_t *args
);

int check_catalog_group(
	knotd_conf_check_args_t *args
);

int check_template(
	knotd_conf_check_args_t *args
);

int check_zonefile_skip(
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

int clear_conf(
	knotd_conf_check_args_t *args
);
