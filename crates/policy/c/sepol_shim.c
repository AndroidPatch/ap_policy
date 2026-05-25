#include <stdint.h>

#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/policydb.h>

int mark_type_declared(policydb_t *db, uint32_t value) {
    if (db == NULL || value == 0 || db->global == NULL || db->global->branch_list == NULL) {
        return -1;
    }

    return ebitmap_set_bit(
        &db->global->branch_list->declared.p_types_scope,
        value - 1,
        1);
}
