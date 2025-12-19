
#define CREATE_COUNTER_DEFINITIONS
#include "dnstapcounter.h"

int dnstap_create_counters(knotd_mod_t *mod) {
    int rc = 0;
    for(int i = 0; i < dnstap_counter_max; i++) {
        rc = knotd_mod_stats_add(mod, str_map_dnstap_counter[i], dnstap_counter_dim_size[i], dnstap_counter_map_to_str[i]);
        if (rc) {
            break;
        }
    }

    return rc;
}

void dnstap_delete_counters(knotd_mod_t *mod) {
    // This API is not exposed in knot. So nothing to free at this stage.
    // knotd_mod_stats_free(mod);
}