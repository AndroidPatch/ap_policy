#ifndef SEPOL_WRAPPER_H
#define SEPOL_WRAPPER_H

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/avtab.h>

#ifdef __cplusplus
extern "C" {
#endif

// Policy loading/saving (use different names to avoid conflicts with libsepol)
policydb_t *sepol_db_new(void);
void sepol_db_free(policydb_t *db);
policydb_t *sepol_db_from_file(const char *path);
policydb_t *sepol_db_from_data(const uint8_t *data, size_t len);
int sepol_db_to_file(policydb_t *db, const char *path);

// Print functions for policy rules
void sepol_print_types(policydb_t *db, int attributes);
void sepol_print_avtab_rules(policydb_t *db);
void sepol_print_filename_trans(policydb_t *db);
void sepol_print_genfscon(policydb_t *db);

// Rule manipulation functions
int sepol_add_rule(policydb_t *db, const char *s, const char *t, const char *c, const char *p, int effect, int invert);
int sepol_add_xperm_rule(policydb_t *db, const char *s, const char *t, const char *c, uint16_t low, uint16_t high, int reset, int effect);
int sepol_add_type_rule(policydb_t *db, const char *s, const char *t, const char *c, const char *d, int effect);
int sepol_add_filename_trans(policydb_t *db, const char *s, const char *t, const char *c, const char *d, const char *o);
int sepol_add_genfscon(policydb_t *db, const char *fs, const char *path, const char *ctx);
int sepol_add_type(policydb_t *db, const char *name, uint32_t flavor);
int sepol_set_type_state(policydb_t *db, const char *name, int permissive);
int sepol_add_typeattribute(policydb_t *db, const char *type, const char *attr);

#ifdef __cplusplus
}
#endif

#endif // SEPOL_WRAPPER_H
