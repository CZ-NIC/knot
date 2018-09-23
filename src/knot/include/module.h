/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
/*!
 * \file
 *
 * \brief Knot DNS module interface.
 *
 * \addtogroup module
 * @{
 */

#pragma once

#include <stdarg.h>
#include <stdint.h>
#include <syslog.h>
#include <sys/socket.h>

#include <libknot/libknot.h>
#include <libknot/yparser/ypschema.h>

/*** Query module API. ***/

/*! Current module ABI version. */
#define KNOTD_MOD_ABI_VERSION	200
/*! Module configuration name prefix. */
#define KNOTD_MOD_NAME_PREFIX	"mod-"

/*! Configuration check function context. */
typedef struct {
	const yp_item_t *item; /*!< Current item descriptor. */
	const uint8_t *id;     /*!< Current section identifier. */
	size_t id_len;         /*!< Current section identifier length. */
	const uint8_t *data;   /*!< Current item data. */
	size_t data_len;       /*!< Current item data length. */
	const char *err_str;   /*!< Output error message. */
	struct knotd_conf_check_extra *extra; /*!< Private items (conf/tools.h). */
} knotd_conf_check_args_t;

/*! Module context. */
typedef struct knotd_mod knotd_mod_t;

/*!
 * Module load callback.
 *
 * Responsibilities:
 *  - Query processing hooks registration
 *  - Optional module specific context initialization
 *  - Module configuration processing
 *  - Query statistics counters registration
 *
 * \param[in] mod  Module context.
 *
 * \return Error code, KNOT_EOK if success.
 */
typedef int (*knotd_mod_load_f)(knotd_mod_t *mod);

/*!
 * Module unload callback.
 *
 * Responsibilities:
 *  - Optional module specific context deinitialization
 *
 * \param[in] mod  Module context.
 */
typedef void (*knotd_mod_unload_f)(knotd_mod_t *mod);

/*!
 * Module configuration section check callback.
 *
 * Responsibilities:
 *  - Optional module configuration section items checks.
 *
 * \note Set args.err_str to proper error message if error.
 *
 * \param[in] args  Configuration check arguments.
 *
 * \return Error code, KNOT_EOK if success.
 */
typedef int (*knotd_conf_check_f)(knotd_conf_check_args_t *args);

/*! Module flags. */
typedef enum {
	KNOTD_MOD_FLAG_NONE         = 0,      /*!< Unspecified. */
	KNOTD_MOD_FLAG_OPT_CONF     = 1 << 0, /*!< Optional module configuration. */
	KNOTD_MOD_FLAG_SCOPE_GLOBAL = 1 << 1, /*!< Can be specified as global module. */
	KNOTD_MOD_FLAG_SCOPE_ZONE   = 1 << 2, /*!< Can be specified as zone module. */
	KNOTD_MOD_FLAG_SCOPE_ANY    = KNOTD_MOD_FLAG_SCOPE_GLOBAL |
	                              KNOTD_MOD_FLAG_SCOPE_ZONE,
} knotd_mod_flag_t;

/*! Module API. */
typedef struct {
	uint32_t version;                /*!< Embedded version of the module ABI. */
	const char *name;                /*!< Module name. */
	knotd_mod_flag_t flags;          /*!< Module flags. */
	knotd_mod_load_f load;           /*!< Module load callback. */
	knotd_mod_unload_f unload;       /*!< Module unload callback. */
	const yp_item_t *config;         /*!< Module configuration schema. */
	knotd_conf_check_f config_check; /*!< Module configuration check callback. */
} knotd_mod_api_t;

/*! Static module API symbol must have a unique name. */
#ifdef KNOTD_MOD_STATIC
 #define KNOTD_MOD_API_NAME(mod_name) knotd_mod_api_##mod_name
#else
 #define KNOTD_MOD_API_NAME(mod_name) knotd_mod_api
#endif

/*! Module API instance initialization helper macro. */
#define KNOTD_MOD_API(mod_name, mod_flags, mod_load, mod_unload, mod_conf, mod_conf_check) \
	__attribute__((visibility("default"))) \
	const knotd_mod_api_t KNOTD_MOD_API_NAME(mod_name) = { \
		.version = KNOTD_MOD_ABI_VERSION, \
		.name = KNOTD_MOD_NAME_PREFIX #mod_name, \
		.flags = mod_flags, \
		.load = mod_load, \
		.unload = mod_unload, \
		.config = mod_conf, \
		.config_check = mod_conf_check, \
	}

/*** Configuration, statistics, logging,... API. ***/

/*!
 * Checks reference item (YP_TREF) value if the destination exists.
 *
 * \note This function is intended to be used in module schema.
 *
 * \param[in] args  Configuration check arguments.
 *
 * \return Error code, KNOT_EOK if success.
 */
int knotd_conf_check_ref(knotd_conf_check_args_t *args);

/*!
 * Gets optional module context.
 *
 * \param[in] mod  Module context.
 *
 * \return Pointer to optional module context.
 */
void *knotd_mod_ctx(knotd_mod_t *mod);

/*!
 * Sets optional module context.
 *
 * \param[in] mod  Module context.
 * \param[in] ctx  Optional module context.
 */
void knotd_mod_ctx_set(knotd_mod_t *mod, void *ctx);

/*!
 * Gets the zone name the module is configured for.
 *
 * \param[in] mod  Module context.
 *
 * \return Zone name.
 */
const knot_dname_t *knotd_mod_zone(knotd_mod_t *mod);

/*!
 * Emits a module specific log message.
 *
 * \param[in] mod       Module context.
 * \param[in] priority  Message priority (LOG_DEBUG...LOG_CRIT).
 * \param[in] fmt       Content of the message.
 */
void knotd_mod_log(knotd_mod_t *mod, int priority, const char *fmt, ...);

/*!
 * Emits a module specific log message (va_list variant).
 *
 * \param[in] mod       Module context.
 * \param[in] priority  Message priority (LOG_DEBUG...LOG_CRIT).
 * \param[in] fmt       Content of the message.
 * \param[in] args      Variable argument list.
 */
void knotd_mod_vlog(knotd_mod_t *mod, int priority, const char *fmt, va_list args);

/*!
 * Statistics multi-counter index to name transformation callback.
 *
 * \param[in] idx        Multi-counter index.
 * \param[in] idx_count  Number of subcounters.
 *
 * \return Index name string.
 */
typedef char* (*knotd_mod_idx_to_str_f)(uint32_t idx, uint32_t idx_count);

/*!
 * Registers a statistics counter.
 *
 * \param[in] mod         Module context.
 * \param[in] ctr_name    Counter name
 * \param[in] idx_count   Number of subcounters (set 1 for single-counter).
 * \param[in] idx_to_str  Subcounter index to name transformation callback
 *                        (set NULL for single-counter).
 *
 * \return Error code, KNOT_EOK if success.
 */
int knotd_mod_stats_add(knotd_mod_t *mod, const char *ctr_name, uint32_t idx_count,
                        knotd_mod_idx_to_str_f idx_to_str);

/*!
 * Increments a statistics counter.
 *
 * \param[in] mod     Module context.
 * \param[in] ctr_id  Counter id (counted in the order the counters were registered).
 * \param[in] idx     Subcounter index (set 0 for single-counter).
 * \param[in] val     Value increment.
 */
void knotd_mod_stats_incr(knotd_mod_t *mod, uint32_t ctr_id, uint32_t idx, uint64_t val);

/*!
 * Decrements a statistics counter.
 *
 * \param[in] mod     Module context.
 * \param[in] ctr_id  Counter id (counted in the order the counters were registered).
 * \param[in] idx     Subcounter index (set 0 for single-counter).
 * \param[in] val     Value decrement.
 */
void knotd_mod_stats_decr(knotd_mod_t *mod, uint32_t ctr_id, uint32_t idx, uint64_t val);

/*!
 * Sets a statistics counter value.
 *
 * \param[in] mod     Module context.
 * \param[in] ctr_id  Counter id (counted in the order the counters were registered).
 * \param[in] idx     Subcounter index (set 0 for single-counter).
 * \param[in] val     Value.
 */
void knotd_mod_stats_store(knotd_mod_t *mod, uint32_t ctr_id, uint32_t idx, uint64_t val);

/*! Configuration single-value abstraction. */
typedef union {
	int64_t integer;
	unsigned option;
	bool boolean;
	const char *string;
	const knot_dname_t *dname;
	struct {
		struct sockaddr_storage addr;
		struct sockaddr_storage addr_max;
		int addr_mask;
	};
	struct {
		const uint8_t *data;
		size_t data_len;
	};
} knotd_conf_val_t;

/*! Configuration value. */
typedef struct {
	knotd_conf_val_t single; /*!< Single-valued item data. */
	knotd_conf_val_t *multi; /*!< Multi-valued item data. */
	size_t count;            /*!< Number of items (0 if default single value). */
} knotd_conf_t;

/*! Environment items. */
typedef enum {
	KNOTD_CONF_ENV_VERSION     = 0, /*!< Software version. */
	KNOTD_CONF_ENV_HOSTNAME    = 1, /*!< Current hostname. */
	KNOTD_CONF_ENV_WORKERS_UDP = 2, /*!< Current number of UDP workers. */
	KNOTD_CONF_ENV_WORKERS_TCP = 3, /*!< Current number of TCP workers. */
} knotd_conf_env_t;

/*!
 * Gets general configuration value.
 *
 * \param[in] mod           Module context.
 * \param[in] section_name  Section name.
 * \param[in] item_name     Section item name.
 * \param[in] id            Section identifier (NULL for simple section).
 *
 * \return Configuration value.
 */
knotd_conf_t knotd_conf(knotd_mod_t *mod, const yp_name_t *section_name,
                        const yp_name_t *item_name, const knotd_conf_t *id);

/*!
 * Gets environment value.
 *
 * \param[in] mod  Module context.
 * \param[in] env  Environment item.
 *
 * \return Configuration value.
 */
knotd_conf_t knotd_conf_env(knotd_mod_t *mod, knotd_conf_env_t env);

/*!
 * Gets module configuration value.
 *
 * \param[in] mod        Module context.
 * \param[in] item_name  Module section item name.
 *
 * \return Configuration value.
 */
knotd_conf_t knotd_conf_mod(knotd_mod_t *mod, const yp_name_t *item_name);

/*!
 * Gets zone configuration value.
 *
 * \param[in] mod        Module context.
 * \param[in] item_name  Zone section item name.
 * \param[in] zone       Zone name.
 *
 * \return Configuration value.
 */
knotd_conf_t knotd_conf_zone(knotd_mod_t *mod, const yp_name_t *item_name,
                             const knot_dname_t *zone);

/*!
 * Gets module configuration value during the checking phase.
 *
 * \note This function is intended to be used in 'knotd_conf_check_f' callbacks.
 *
 * \param[in] args
 * \param[in] item_name
 *
 * \return Configuration value.
 */
knotd_conf_t knotd_conf_check_item(knotd_conf_check_args_t *args,
                                   const yp_name_t *item_name);

/*!
 * \brief Checks if address is in at least one of given ranges.
 *
 * \param[in] range
 * \param[in] addr
 *
 * \return true if addr is in at least one range, false otherwise.
 */
bool knotd_conf_addr_range_match(const knotd_conf_t *range,
                                 const struct sockaddr_storage *addr);

/*!
 * Deallocates multi-valued configuration values.
 *
 * \param[in] conf  Configuration value.
 */
void knotd_conf_free(knotd_conf_t *conf);

/*** Query processing API. ***/

/*!
 * DNS query type.
 *
 * This type encompasses the different query types distinguished by both the
 * OPCODE and the QTYPE.
 */
typedef enum {
	KNOTD_QUERY_TYPE_INVALID, /*!< Invalid query. */
	KNOTD_QUERY_TYPE_NORMAL,  /*!< Normal query. */
	KNOTD_QUERY_TYPE_AXFR,    /*!< Request for AXFR transfer. */
	KNOTD_QUERY_TYPE_IXFR,    /*!< Request for IXFR transfer. */
	KNOTD_QUERY_TYPE_NOTIFY,  /*!< NOTIFY query. */
	KNOTD_QUERY_TYPE_UPDATE,  /*!< Dynamic update. */
} knotd_query_type_t;

/*! Query processing specific flags. */
typedef enum {
	KNOTD_QUERY_FLAG_NO_AXFR    = 1 << 0, /*!< Don't process AXFR. */
	KNOTD_QUERY_FLAG_NO_IXFR    = 1 << 1, /*!< Don't process IXFR. */
	KNOTD_QUERY_FLAG_LIMIT_ANY  = 1 << 2, /*!< Limit ANY QTYPE (respond with TC=1). */
	KNOTD_QUERY_FLAG_LIMIT_SIZE = 1 << 3, /*!< Apply UDP size limit. */
	KNOTD_QUERY_FLAG_COOKIE     = 1 << 4, /*!< Valid DNS Cookie indication. */
} knotd_query_flag_t;

/*! Query processing data context parameters. */
typedef struct {
	knotd_query_flag_t flags;              /*!< Current query flgas. */
	const struct sockaddr_storage *remote; /*!< Current remote address. */
	int socket;                            /*!< Current network socket. */
	unsigned thread_id;                    /*!< Current thread id. */
	void *server;                          /*!< Server object private item. */
} knotd_qdata_params_t;

/*! Query processing data context. */
typedef struct {
	knot_pkt_t *query;              /*!< Query to be solved. */
	knotd_query_type_t type;        /*!< Query packet type. */
	const knot_dname_t *name;       /*!< Currently processed name. */
	uint16_t rcode;                 /*!< Resulting RCODE (Whole extended RCODE). */
	uint16_t rcode_tsig;            /*!< Resulting TSIG RCODE. */
	knot_rrset_t opt_rr;            /*!< OPT record. */
	knot_sign_context_t sign;       /*!< Signing context. */
	knot_edns_client_subnet_t *ecs; /*!< EDNS Client Subnet option. */
	bool err_truncated;             /*!< Set TC bit if error reply. */

	/*! Persistent items on processing reset. */
	knot_mm_t *mm;                /*!< Memory context. */
	knotd_qdata_params_t *params; /*!< Low-level processing parameters. */

	struct knotd_qdata_extra *extra; /*!< Private items (process_query.h). */
} knotd_qdata_t;

/*!
 * Gets the current zone name.
 *
 * \param[in] qdata  Query data.
 *
 * \return Zone name.
 */
const knot_dname_t *knotd_qdata_zone_name(knotd_qdata_t *qdata);

/*!
 * Gets the current zone apex rrset of the given type.
 *
 * \param[in] qdata  Query data.
 * \param[in] type   Rrset type.
 *
 * \return A copy of the zone apex rrset.
 */
knot_rrset_t knotd_qdata_zone_apex_rrset(knotd_qdata_t *qdata, uint16_t type);

/*! General query processing states. */
typedef enum {
	KNOTD_STATE_NOOP  = 0, /*!< No response. */
	KNOTD_STATE_DONE  = 4, /*!< Finished. */
	KNOTD_STATE_FAIL  = 5, /*!< Error. */
	KNOTD_STATE_FINAL = 6, /*!< Finished and finalized (QNAME, EDNS, TSIG). */
} knotd_state_t;

/*! brief Internet query processing states. */
typedef enum {
	KNOTD_IN_STATE_BEGIN,  /*!< Begin name resolution. */
	KNOTD_IN_STATE_NODATA, /*!< Positive result with NO data. */
	KNOTD_IN_STATE_HIT,    /*!< Positive result. */
	KNOTD_IN_STATE_MISS,   /*!< Negative result. */
	KNOTD_IN_STATE_DELEG,  /*!< Result is delegation. */
	KNOTD_IN_STATE_FOLLOW, /*!< Resolution not complete (CNAME/DNAME chain). */
	KNOTD_IN_STATE_TRUNC,  /*!< Finished, packet size limit encountered. */
	KNOTD_IN_STATE_ERROR,  /*!< Resolution failed. */
} knotd_in_state_t;

/*! Query module processing stages. */
typedef enum {
	KNOTD_STAGE_BEGIN = 0,  /*!< Before query processing. */
	KNOTD_STAGE_PREANSWER,  /*!< Before section processing. */
	KNOTD_STAGE_ANSWER,     /*!< Answer section processing. */
	KNOTD_STAGE_AUTHORITY,  /*!< Authority section processing. */
	KNOTD_STAGE_ADDITIONAL, /*!< Additional section processing. */
	KNOTD_STAGE_END,        /*!< After query processing. */
} knotd_stage_t;

/*!
 * General processing hook.
 *
 * \param[in] state    Current processing state.
 * \param[in,out] pkt  Response packet.
 * \param[in] qdata    Query data.
 * \param[in] mod      Module context.
 *
 * \return Next processing state.
 */
typedef knotd_state_t (*knotd_mod_hook_f)
	(knotd_state_t state, knot_pkt_t *pkt, knotd_qdata_t *qdata, knotd_mod_t *mod);

/*!
 * Internet class processing hook.
 *
 * \param[in] state    Current processing state.
 * \param[in,out] pkt  Response packet.
 * \param[in] qdata    Query data.
 * \param[in] mod      Module context.
 *
 * \return Next processing state.
 */
typedef knotd_in_state_t (*knotd_mod_in_hook_f)
	(knotd_in_state_t state, knot_pkt_t *pkt, knotd_qdata_t *qdata, knotd_mod_t *mod);

/*!
 * Registers general processing module hook.
 *
 * \param[in] mod    Module context.
 * \param[in] stage  Processing stage (KNOTD_STAGE_BEGIN or KNOTD_STAGE_END).
 * \param[in] hook   Module hook.
 *
 * \return Error code, KNOT_EOK if success.
 */
int knotd_mod_hook(knotd_mod_t *mod, knotd_stage_t stage, knotd_mod_hook_f hook);

/*!
 * Registers Internet class module hook.
 *
 * \param[in] mod    Module context.
 * \param[in] stage  Processing stage (KNOTD_STAGE_ANSWER..KNOTD_STAGE_ADDITIONAL).
 * \param[in] hook   Module hook.
 *
 * \return Error code, KNOT_EOK if success.
 */
int knotd_mod_in_hook(knotd_mod_t *mod, knotd_stage_t stage, knotd_mod_in_hook_f hook);

/*** DNSSEC API. ***/

/*!
 * Initializes DNSSEC signing context.
 *
 * \param[in] mod  Module context.
 *
 * \return Error code, KNOT_EOK if success.
 */
int knotd_mod_dnssec_init(knotd_mod_t *mod);

/*!
 * Loads available DNSSEC signing keys.
 *
 * \param[in] mod      Module context.
 * \param[in] verbose  Print key summary into log indication.
 *
 * \return Error code, KNOT_EOK if success.
 */
int knotd_mod_dnssec_load_keyset(knotd_mod_t *mod, bool verbose);

/*!
 * Generates RRSIGs for given RRSet.
 *
 * \param[in] mod      Module context.
 * \param[out] rrsigs  Output RRSIG RRSet.
 * \param[in] rrset    Input RRSet to generate RRSIGs for.
 * \param[in] mm       Memory context.
 *
 * \return Error code, KNOT_EOK if success.
 */
int knotd_mod_dnssec_sign_rrset(knotd_mod_t *mod, knot_rrset_t *rrsigs,
                                const knot_rrset_t *rrset, knot_mm_t *mm);

/*! @} */
