/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 
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
#include <stdbool.h>
#include <inttypes.h>

#include "common/debug.h"
#include "common/mem.h"
#include "libknot/errcode.h"
#include "libknot/common.h"
#include "libknot/dname.h"
#include "libknot/consts.h"
#include "libknot/rrtype/dnskey.h"
#include "libknot/dnssec/sign.h"
#include "knot/dnssec/zone-keys.h"

/*!
 * \brief Initialize DNSSEC signing context for each key.
 */
static int init_sign_contexts(knot_zone_keys_t *keys)
{
    assert(keys);
    
    node_t *node = NULL;
    WALK_LIST(node, keys->list) {
        knot_zone_key_t *key = (knot_zone_key_t *)node;
        
        /*printf("DNSSEC, initializing key %s, %s, %s, %s\n",
                      key->is_ksk ? "KSK" : "ZSK",
                      key->is_active ? "active" : "inactive",
                      key->is_public ? "public" : "not-public",
                      key->is_nsec5 ? "NSEC5" : "DNSKEY");
        */
        key->context = knot_dnssec_sign_init(&key->dnssec_key);
        key->nsec5_ctx = knot_nsec5_hash_init(&key->nsec5_key);
        if (key->is_nsec5 && key->nsec5_ctx == NULL) {
            printf("NSEC5KEY context NULL\n");
            return KNOT_ENOMEM;
        }
        if (!(key->is_nsec5) && key->context == NULL) {
            printf("DNSKEY context NULL\n");
            return KNOT_ENOMEM;
        }
}
    //printf("ta ekana ola initialize\n");
    return KNOT_EOK;
}

/*!
 * \brief Get zone key by a keytag.
 */
const knot_zone_key_t *knot_get_zone_key(const knot_zone_keys_t *keys,
                                         uint16_t keytag)
{
    if (!keys) {
        return NULL;
    }
    //printf("PSAXNOUME KEYTAG: %u\n",keytag);
    node_t *node = NULL;
    WALK_LIST(node, keys->list) {
        knot_zone_key_t *key = (knot_zone_key_t *)node;
        //printf("VRIKAME KEYTAG DNS: %u KAI NSEC5: %u \n",key->dnssec_key.keytag ,key->nsec5_key.keytag);
        if (key->is_nsec5 && key->nsec5_key.keytag == keytag) {
            //printf("NSEC5 KAI MPIKA MESA\n");
            return key;
        }
        if (!(key->is_nsec5) && key->dnssec_key.keytag == keytag) {
            //printf("DNSSEC KAI MPIKA MESA\n");
            return key;
        }
    }
    
    return NULL;
}

/*!
 * \brief Get (unique active) NSEC5 key.
 */
knot_zone_key_t *knot_get_nsec5_key(const knot_zone_keys_t *keys)
{
    if (!keys) {
        return NULL;
    }
    
    node_t *node = NULL;
    WALK_LIST(node, keys->list) {
        knot_zone_key_t *key = (knot_zone_key_t *)node;
        if (key->is_nsec5 && key->is_active) {
            //printf("=================================VRETHIKE TO NSEC5KEY KAI EXEI KEYTAG: %d============\n",key->nsec5_key.keytag);
            return key;
        }
    }
    
    return NULL;
}

/*!
 * \brief Get key feature flags from key parameters.
 */
static void set_zone_key_flags(const knot_key_params_t *params,
                               knot_zone_key_t *key)
{
    assert(params);
    assert(key);
    
    uint32_t now = time(NULL);
    
    uint32_t next_event = UINT32_MAX;
    uint32_t timestamps[4] = {
        params->time_publish,
        params->time_activate,
        params->time_inactive,
        params->time_delete
    };
    
    for (int i = 0; i < 4; i++) {
        uint32_t ts = timestamps[i];
        if (ts != 0 && now < ts && ts < next_event) {
            next_event = ts;
        }
    }
    
    key->next_event = next_event;
    
    key->is_ksk = params->flags & KNOT_RDATA_DNSKEY_FLAG_KSK;
    key->is_zsk = !key->is_ksk; // This may be tricky....
    
    key->is_active = params->time_activate <= now &&
    (params->time_inactive == 0 || now < params->time_inactive);
    
    key->is_public = params->time_publish <= now &&
    (params->time_delete == 0 || now < params->time_delete);
}

/*!
 * \brief Algorithm usage information.
 */
typedef struct algorithm_usage {
    unsigned ksk_count;  //!< Available KSK count.
    unsigned zsk_count;  //!< Available ZSK count.
    
    bool is_public;      //!< DNSKEY is published.
    bool is_stss;        //!< Used to sign all types of records.
    bool is_ksk_active;  //!< Used to sign DNSKEY records.
    bool is_zsk_active;  //!< Used to sign non-DNSKEY records.
} algorithm_usage_t;

/*!
 * \brief Check correct key usage, enable Single-Type Signing Scheme if needed.
 *
 * Each record in the zone has to be signed at least by one key for each
 * algorithm published in the DNSKEY RR set in the zone apex.
 *
 * Therefore, publishing a DNSKEY creates a requirement on active keys with
 * the same algorithm. At least one KSK key and one ZSK has to be enabled.
 * If one key type is unavailable (not just inactive and not-published), the
 * algorithm is switched to Single-Type Signing Scheme.
 */
static int prepare_and_check_keys(const knot_dname_t *zone_name,
                                  knot_zone_keys_t *keys)
{
    assert(zone_name);
    assert(keys);
    
    const size_t max_algorithms = KNOT_DNSSEC_ALG_ECDSAP384SHA384 + 2; //dipapado fix
    algorithm_usage_t usage[max_algorithms];
    memset(usage, 0, max_algorithms * sizeof(algorithm_usage_t));
    
    // count available keys
    
    knot_zone_key_t *key = NULL;
    WALK_LIST(key, keys->list) {
        if (!(key->is_nsec5)) {
            assert(key->dnssec_key.algorithm < max_algorithms);
            algorithm_usage_t *u = &usage[key->dnssec_key.algorithm];
            
            if (key->is_ksk) { u->ksk_count += 1; }
            if (key->is_zsk) { u->zsk_count += 1; }
        }
    }
    
    // enable Single-Type Signing scheme if applicable
    
    for (int i = 0; i < max_algorithms; i++) {
        algorithm_usage_t *u = &usage[i];
        
        // either KSK or ZSK keys are available
        if ((u->ksk_count == 0) != (u->zsk_count == 0)) {
            u->is_stss = true;
            log_zone_info(zone_name, "DNSSEC, Single-Type Signing "
                          "scheme enabled, algorithm '%d'", i);
        }
    }
    
    // update key flags for STSS, collect information about usage
    
    WALK_LIST(key, keys->list) {
        if (!(key->is_nsec5)) {
            assert(key->dnssec_key.algorithm < max_algorithms);
            algorithm_usage_t *u = &usage[key->dnssec_key.algorithm];
            
            if (u->is_stss) {
                key->is_ksk = true;
                key->is_zsk = true;
            }
            
            if (key->is_public) { u->is_public = true; }
            if (key->is_active) {
                if (key->is_ksk) { u->is_ksk_active = true; }
                if (key->is_zsk) { u->is_zsk_active = true; }
            }
        }
    }
    // validate conditions for used algorithms
    
    unsigned public_count = 0;
    
    for (int i = 0; i < max_algorithms; i++) {
        algorithm_usage_t *u = &usage[i];
        if (u->is_public) {
            public_count += 1;
            if (!u->is_ksk_active || !u->is_zsk_active) {
                return KNOT_DNSSEC_EMISSINGKEYTYPE;
            }
        }
    }
    
    if (public_count == 0) {
        return KNOT_DNSSEC_ENOKEY;
    }
    
    return KNOT_EOK;
}

/*!
 * \brief Load zone keys from a key directory.
 */
int knot_load_zone_keys(const char *keydir_name, const knot_dname_t *zone_name,
                        bool nsec3_enabled, knot_zone_keys_t *keys)
{
    if (!keydir_name || !zone_name || !keys) {
        return KNOT_EINVAL;
    }
    
    DIR *keydir = opendir(keydir_name);
    if (!keydir) {
        return KNOT_DNSSEC_ENOKEYDIR;
    }
    
    int result = KNOT_EOK;
    
    struct dirent entry_buf = { 0 };
    struct dirent *entry = NULL;
    while (readdir_r(keydir, &entry_buf, &entry) == 0 && entry != NULL) {
        
        char *suffix = strrchr(entry->d_name, '.');
        if (!suffix) {
            continue;
        }
        
        if (strcmp(suffix, ".private") != 0) {
            continue;
        }
        
        size_t path_len = strlen(keydir_name) + 1 + strlen(entry->d_name);
        char *path = malloc((path_len + 1) * sizeof(char));
        if (!path) {
            printf("PATH MALLOC ERROR\n");
            ERR_ALLOC_FAILED;
            closedir(keydir);
            return KNOT_ENOMEM;
        }
        
        int written = snprintf(path, path_len + 1, "%s/%s",
                               keydir_name, entry->d_name);
        UNUSED(written);
        assert(written == path_len);
        
        knot_key_params_t params = { 0 };
        int ret = knot_load_key_params(path, &params);
        free(path);
        
        if (ret != KNOT_EOK) {
            log_zone_warning(zone_name, "DNSSEC, failed to load "
                             "key, file '%s' (%s)",
                             entry->d_name, knot_strerror(ret));
            knot_free_key_params(&params);
            continue;
        }
        
        if (!knot_dname_is_equal(zone_name, params.name)) {
            knot_free_key_params(&params);
            continue;
        }
        
        if ((knot_get_key_type(&params) != KNOT_KEY_DNSSEC) && knot_get_key_type(&params) != KNOT_KEY_NSEC5) {
            knot_free_key_params(&params);
            continue;
        }
        
        knot_zone_key_t *key = malloc(sizeof(*key));
        if (!key) {
            printf("KEY MALLOC ERROR\n");
            result = KNOT_ENOMEM;
            break;
        }
        memset(key, '\0', sizeof(*key));
        set_zone_key_flags(&params, key);
        
        //common
        if (knot_get_zone_key(keys, params.keytag) != NULL) {
            log_zone_notice(zone_name, "DNSSEC, ignoring key %5d, "
                            "file '%s' (duplicate keytag)",
                            params.keytag, entry->d_name);
            knot_free_key_params(&params);
            free(key);
            continue;
        }
        //DNSSEC only
        if (knot_get_key_type(&params) != KNOT_KEY_NSEC5) {
            
            if (!knot_dnssec_algorithm_is_zonesign(params.algorithm,
                                                   nsec3_enabled)) {
                log_zone_notice(zone_name, "DNSSEC, ignoring key %5d, "
                                "file '%s' (incompatible algorithm)",
                                params.keytag, entry->d_name);
                knot_free_key_params(&params);
                free(key);
                continue;
            }
            
            ret = knot_dnssec_key_from_params(&params, &key->dnssec_key);
            if (ret != KNOT_EOK) {
                log_zone_error(zone_name, "DNSSEC, failed to process "
                               "key %5d, file '%s' (%s)",
                               params.keytag, entry->d_name,
                               knot_strerror(ret));
                knot_free_key_params(&params);
                free(key);
                continue;
            }
        }
        //NSEC5 only
        else {
            key->is_nsec5 = true;
            ret = knot_nsec5_key_from_params(&params, &key->nsec5_key);
            if (ret != KNOT_EOK) {
                log_zone_error(zone_name, "DNSSEC, failed to process "
                               "key %5d, file '%s' (%s)",
                               params.keytag, entry->d_name,
                               knot_strerror(ret));
                knot_free_key_params(&params);
                free(key);
                continue;
            }
        }
        log_zone_info(zone_name, "DNSSEC, loaded key %d, %5d, file '%s', %s, %s, %s, %s",
                      params.algorithm, params.keytag, entry->d_name,
                      key->is_ksk ? "KSK" : "ZSK",
                      key->is_active ? "active" : "inactive",
                      key->is_public ? "public" : "not-public",
                      key->is_nsec5 ? "NSEC5" : "DNSKEY");
        
        
        knot_free_key_params(&params);
        
        add_tail(&keys->list, &key->node);
    }
    
    closedir(keydir);
    //printf("KLEISAME K TO DIR\n");
    if (result == KNOT_EOK) {
        //printf("mpipa sto prepare and check\n");

        result = prepare_and_check_keys(zone_name, keys);
    }
    
    if (result == KNOT_EOK) {
        //printf("mpika sto init sign context and \n");

        result = init_sign_contexts(keys);
    }
    
    if (result != KNOT_EOK) {
        //printf("MPIKA STO FREE:\n");
        knot_free_zone_keys(keys);
    }
    
    return result;
}

void knot_init_zone_keys(knot_zone_keys_t *keys)
{
    if (!keys) {
        return;
    }
    
    memset(keys, 0, sizeof(*keys));
    init_list(&keys->list);
}

/*!
 * \brief Free structure with zone keys and associated DNSSEC contexts.
 */
void knot_free_zone_keys(knot_zone_keys_t *keys)
{
    if (!keys) {
        return;
    }
    
    node_t *node = NULL;
    node_t *next = NULL;
    WALK_LIST_DELSAFE(node, next, keys->list) {
        knot_zone_key_t *key = (knot_zone_key_t *)node;
        knot_dnssec_sign_free(key->context);
        knot_nsec5_hash_free(key->nsec5_ctx);
        knot_dnssec_key_free(&key->dnssec_key);
        knot_nsec5_key_free(&key->nsec5_key);
        free(key);
    }
    
    init_list(&keys->list);
}

void knot_free_zone_key(knot_zone_key_t *key)
{
    if (!key) {
        return;
    }

        knot_dnssec_sign_free(key->context);
        knot_nsec5_hash_free(key->nsec5_ctx);
        knot_dnssec_key_free(&key->dnssec_key);
        knot_nsec5_key_free(&key->nsec5_key);
        free(key);
}

/*!
 * \brief Get timestamp of next key event.
 */
uint32_t knot_get_next_zone_key_event(const knot_zone_keys_t *keys)
{
    uint32_t result = UINT32_MAX;
    
    node_t *node = NULL;
    WALK_LIST(node, keys->list) {
        knot_zone_key_t *key = (knot_zone_key_t *)node;
        result = MIN(result, key->next_event);
    }
    
    return result;
}


knot_zone_key_t *knot_load_nsec5_key(const char *keydir_name, const knot_dname_t *zone_name)
{
    if (!keydir_name || !zone_name) {
        printf("First Check Fail\n");
        return NULL;
    }
    
    DIR *keydir = opendir(keydir_name);
    if (!keydir) {
        return NULL;
        printf("Second Check Fail\n");
    }
    
    int result = KNOT_EOK;
    knot_zone_key_t *key = malloc(sizeof(*key));
    
    struct dirent entry_buf = { 0 };
    struct dirent *entry = NULL;
    while (readdir_r(keydir, &entry_buf, &entry) == 0 && entry != NULL) {
        
        char *suffix = strrchr(entry->d_name, '.');
        if (!suffix) {
            continue;
        }
        
        if (strcmp(suffix, ".private") != 0 || !strstr(entry->d_name,"nsec5")) {
            continue;
        }
        //printf("VRIKA ENA NSEC5EY POU EINAI PRIVATE\n");
            
        size_t path_len = strlen(keydir_name) + 1 + strlen(entry->d_name);
        char *path = malloc((path_len + 1) * sizeof(char));
        if (!path) {
            printf("PATH MALLOC ERROR\n");
            ERR_ALLOC_FAILED;
            closedir(keydir);
            return NULL;
        }
        
        int written = snprintf(path, path_len + 1, "%s/%s",
                               keydir_name, entry->d_name);
        UNUSED(written);
        assert(written == path_len);
        
        knot_key_params_t params = { 0 };
        int ret = knot_load_key_params(path, &params);
        free(path);
        
        if (ret != KNOT_EOK) {
            log_zone_warning(zone_name, "DNSSEC, failed to load "
                             "NSEC5key to the zone, file '%s' (%s)",
                             entry->d_name, knot_strerror(ret));
            knot_free_key_params(&params);
            continue;
        }
        
        if (!knot_dname_is_equal(zone_name, params.name)) {
            knot_free_key_params(&params);
            continue;
        }
        
        if ((knot_get_key_type(&params) != KNOT_KEY_NSEC5)) {
            knot_free_key_params(&params);
            continue;
        }
        
        //knot_zone_key_t *key = malloc(sizeof(*key));
        if (!key) {
            printf("KEY MALLOC ERROR\n");
            result = KNOT_ENOMEM;
            break;
        }
        memset(key, '\0', sizeof(*key));
        set_zone_key_flags(&params, key);
        if (!key->is_active) {
            log_zone_info(zone_name, "NSEC5 key with keytag %5d, file '%s',  is inactive.",
                          params.keytag,entry->d_name);
            knot_free_key_params(&params);
            continue;
        }
        //NSEC5 only
            key->is_nsec5 = true;
            ret = knot_nsec5_key_from_params(&params, &key->nsec5_key);
            if (ret != KNOT_EOK) {
                log_zone_error(zone_name, "DNSSEC, failed to process "
                               "key %5d while loading to zone, file '%s' (%s)",
                               params.keytag, entry->d_name,
                               knot_strerror(ret));
                knot_free_key_params(&params);
                continue;
            }
        
        printf(/*zone_name, */"DNSSEC, loaded key to the zone! %d, %5d, file '%s', %s, %s, %s, %s",
                      params.algorithm, params.keytag, entry->d_name,
                      key->is_ksk ? "KSK" : "ZSK",
                      key->is_active ? "active" : "inactive",
                      key->is_public ? "public" : "not-public",
                      key->is_nsec5 ? "NSEC5" : "DNSKEY");
        
        knot_free_key_params(&params);
        if (result == KNOT_EOK) {
            //printf("mpika sto init sign context \n");
            key->nsec5_ctx = knot_nsec5_hash_init(&key->nsec5_key);
            if (key->nsec5_ctx == NULL)
            {
                //printf("Error in initializing sign context\n");
                free(key);
                return NULL;
            }
            //printf("Epistrefw KLEIDI\n");
            return key;
        }
    }
    closedir(keydir);
    //printf("KLEISAME K TO DIR\n");
    //printf("EPISTREFW NULL");
    return NULL;
}




