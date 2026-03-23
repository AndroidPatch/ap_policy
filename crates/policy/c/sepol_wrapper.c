#include "sepol_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Helper function to duplicate a string
static char *dup_str(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s);
    char *r = malloc(len + 1);
    if (r) {
        memcpy(r, s, len + 1);
    }
    return r;
}

// Helper function to find type in hashtab
static type_datum_t *find_type(policydb_t *db, const char *name) {
    if (!name || !db) return NULL;
    return (type_datum_t *)hashtab_search(db->p_types.table, (hashtab_key_t)name);
}

// Helper function to find class in hashtab
static class_datum_t *find_class(policydb_t *db, const char *name) {
    if (!name || !db) return NULL;
    return (class_datum_t *)hashtab_search(db->p_classes.table, (hashtab_key_t)name);
}

// Helper function to find permission in class
static perm_datum_t *find_perm(class_datum_t *cls, const char *name) {
    if (!name || !cls) return NULL;
    perm_datum_t *perm = (perm_datum_t *)hashtab_search(cls->permissions.table, (hashtab_key_t)name);
    if (!perm && cls->comdatum) {
        perm = (perm_datum_t *)hashtab_search(cls->comdatum->permissions.table, (hashtab_key_t)name);
    }
    return perm;
}

// Helper function to format context as string
static char *context_to_str(policydb_t *db, context_struct_t *ctx) {
    if (!db || !ctx) return NULL;

    const char *user = db->p_user_val_to_name[ctx->user - 1];
    const char *role = db->p_role_val_to_name[ctx->role - 1];
    const char *type = db->p_type_val_to_name[ctx->type - 1];

    if (!user || !role || !type) return NULL;

    // Simple context format: user:role:type
    // TODO: Add MLS range if needed
    size_t len = strlen(user) + strlen(role) + strlen(type) + 3;
    char *str = malloc(len);
    if (str) {
        snprintf(str, len, "%s:%s:%s", user, role, type);
    }
    return str;
}

// Create a new policydb
policydb_t *sepol_db_new(void) {
    policydb_t *db = calloc(1, sizeof(policydb_t));
    if (db && policydb_init(db) != 0) {
        free(db);
        return NULL;
    }
    return db;
}

// Free a policydb
void sepol_db_free(policydb_t *db) {
    if (db) {
        policydb_destroy(db);
        free(db);
    }
}

// Load policydb from file
policydb_t *sepol_db_from_file(const char *path) {
    if (!path) return NULL;

    policydb_t *db = sepol_db_new();
    if (!db) return NULL;

    policy_file_t pf;
    policy_file_init(&pf);
    pf.fp = fopen(path, "rb");
    if (!pf.fp) {
        sepol_db_free(db);
        return NULL;
    }
    pf.type = PF_USE_STDIO;

    if (policydb_read(db, &pf, 0) != 0) {
        fclose(pf.fp);
        sepol_db_free(db);
        return NULL;
    }
    fclose(pf.fp);
    return db;
}

// Load policydb from data
policydb_t *sepol_db_from_data(const uint8_t *data, size_t len) {
    if (!data || len == 0) return NULL;

    policydb_t *db = sepol_db_new();
    if (!db) return NULL;

    policy_file_t pf;
    policy_file_init(&pf);
    pf.data = (char *)data;
    pf.len = len;
    pf.type = PF_USE_MEMORY;

    if (policydb_read(db, &pf, 0) != 0) {
        sepol_db_free(db);
        return NULL;
    }
    return db;
}

// Save policydb to file
int sepol_db_to_file(policydb_t *db, const char *path) {
    if (!db || !path) return -1;

    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;

    policy_file_t pf;
    policy_file_init(&pf);
    pf.fp = fp;
    pf.type = PF_USE_STDIO;

    int ret = policydb_write(db, &pf);
    fclose(fp);
    return ret;
}

// Print types (attributes or regular types)
void sepol_print_types(policydb_t *db, int attributes) {
    if (!db) return;

    for (uint32_t i = 0; i < db->p_types.nprim; i++) {
        type_datum_t *type = db->type_val_to_struct[i];
        if (!type) continue;

        const char *name = db->p_type_val_to_name[i];
        if (!name) continue;

        if (attributes && type->flavor == TYPE_ATTRIB) {
            printf("attribute %s\n", name);
        } else if (!attributes && type->flavor == TYPE_TYPE) {
            // Print type with attributes
            int first = 1;
            ebitmap_t *bitmap = &db->type_attr_map[i];

            for (uint32_t j = 0; j <= bitmap->highbit; j++) {
                if (ebitmap_get_bit(bitmap, j)) {
                    type_datum_t *attr_type = db->type_val_to_struct[j];
                    if (attr_type && attr_type->flavor == TYPE_ATTRIB) {
                        const char *attr = db->p_type_val_to_name[j];
                        if (attr) {
                            if (first) {
                                printf("type %s {", name);
                                first = 0;
                            }
                            printf(" %s", attr);
                        }
                    }
                }
            }
            if (!first) {
                printf(" }\n");
            }
        }

        // Print permissive
        if (ebitmap_get_bit(&db->permissive_map, type->s.value)) {
            printf("permissive %s\n", name);
        }
    }
}

// Print avtab rules
void sepol_print_avtab_rules(policydb_t *db) {
    if (!db) return;

    // Iterate through avtab
    for (uint32_t i = 0; i < db->te_avtab.nslot; i++) {
        for (avtab_ptr_t node = db->te_avtab.htable[i]; node; node = node->next) {
            const char *src = db->p_type_val_to_name[node->key.source_type - 1];
            const char *tgt = db->p_type_val_to_name[node->key.target_type - 1];
            const char *cls = db->p_class_val_to_name[node->key.target_class - 1];

            if (!src || !tgt || !cls) continue;

            if (node->key.specified & AVTAB_AV) {
                uint32_t data = node->datum.data;
                const char *name;

                switch (node->key.specified) {
                    case AVTAB_ALLOWED: name = "allow"; break;
                    case AVTAB_AUDITALLOW: name = "auditallow"; break;
                    case AVTAB_AUDITDENY:
                        name = "dontaudit";
                        data = ~data;
                        break;
                    default: continue;
                }

                class_datum_t *clz = db->class_val_to_struct[node->key.target_class - 1];
                if (!clz) continue;

                // Print permissions
                int first = 1;
                for (uint32_t bit = 0; bit < 32; bit++) {
                    if (data & (1u << bit)) {
                        const char *perm = NULL;
                        // Check class permissions
                        if (clz->permissions.table) {
                            for (hashtab_ptr_t p = clz->permissions.table->htable[0]; p && !perm; p = p->next) {
                                perm_datum_t *pd = (perm_datum_t *)p->datum;
                                if (pd && pd->s.value == bit + 1) {
                                    perm = (const char *)p->key;
                                    break;
                                }
                            }
                        }
                        // Check common permissions if not found
                        if (!perm && clz->comdatum && clz->comdatum->permissions.table) {
                            for (hashtab_ptr_t p = clz->comdatum->permissions.table->htable[0]; p && !perm; p = p->next) {
                                perm_datum_t *pd = (perm_datum_t *)p->datum;
                                if (pd && pd->s.value == bit + 1) {
                                    perm = (const char *)p->key;
                                    break;
                                }
                            }
                        }
                        if (perm) {
                            if (first) {
                                printf("%s %s %s %s {", name, src, tgt, cls);
                                first = 0;
                            }
                            printf(" %s", perm);
                        }
                    }
                }
                if (!first) {
                    printf(" }\n");
                }
            } else if (node->key.specified & AVTAB_TYPE) {
                const char *name;
                switch (node->key.specified) {
                    case AVTAB_TRANSITION: name = "type_transition"; break;
                    case AVTAB_MEMBER: name = "type_member"; break;
                    case AVTAB_CHANGE: name = "type_change"; break;
                    default: continue;
                }
                const char *def = db->p_type_val_to_name[node->datum.data - 1];
                if (def) {
                    printf("%s %s %s %s %s\n", name, src, tgt, cls, def);
                }
            } else if (node->key.specified & AVTAB_XPERMS) {
                const char *name;
                switch (node->key.specified) {
                    case AVTAB_XPERMS_ALLOWED: name = "allowxperm"; break;
                    case AVTAB_XPERMS_AUDITALLOW: name = "auditallowxperm"; break;
                    case AVTAB_XPERMS_DONTAUDIT: name = "dontauditxperm"; break;
                    default: continue;
                }

                avtab_extended_perms_t *xperms = node->datum.xperms;
                if (!xperms) continue;

                printf("%s %s %s %s ioctl {", name, src, tgt, cls);

                // Print xperm ranges
                int low = -1;
                for (int i = 0; i < 256; i++) {
                    if (xperm_test(i, xperms->perms)) {
                        if (low < 0) low = i;
                        if (i == 255) {
                            uint16_t v = (xperms->specified == AVTAB_XPERMS_IOCTLFUNCTION)
                                ? (((uint16_t)xperms->driver) << 8) | i
                                : ((uint16_t)i) << 8;
                            if (low == 255) {
                                printf(" 0x%04X", v);
                            } else {
                                uint16_t vlow = (xperms->specified == AVTAB_XPERMS_IOCTLFUNCTION)
                                    ? (((uint16_t)xperms->driver) << 8) | low
                                    : ((uint16_t)low) << 8;
                                printf(" 0x%04X-0x%04X", vlow, v);
                            }
                        }
                    } else if (low >= 0) {
                        uint16_t vlow = (xperms->specified == AVTAB_XPERMS_IOCTLFUNCTION)
                            ? (((uint16_t)xperms->driver) << 8) | low
                            : ((uint16_t)low) << 8;
                        uint16_t vhigh = (xperms->specified == AVTAB_XPERMS_IOCTLFUNCTION)
                            ? (((uint16_t)xperms->driver) << 8) | (i - 1)
                            : ((uint16_t)(i - 1)) << 8;
                        if (low == i - 1) {
                            printf(" 0x%04X", vlow);
                        } else {
                            printf(" 0x%04X-0x%04X", vlow, vhigh);
                        }
                        low = -1;
                    }
                }
                printf(" }\n");
            }
        }
    }
}

// Print filename transitions
void sepol_print_filename_trans(policydb_t *db) {
    if (!db || !db->filename_trans) return;

    for (uint32_t i = 0; i < db->filename_trans->size; i++) {
        for (hashtab_ptr_t node = db->filename_trans->htable[i]; node; node = node->next) {
            filename_trans_key_t *key = (filename_trans_key_t *)node->key;
            filename_trans_datum_t *trans = (filename_trans_datum_t *)node->datum;

            if (!key || !trans) continue;

            const char *tgt = db->p_type_val_to_name[key->ttype - 1];
            const char *cls = db->p_class_val_to_name[key->tclass - 1];
            const char *def = db->p_type_val_to_name[trans->otype - 1];

            if (!tgt || !cls || !def || !key->name) continue;

            for (uint32_t k = 0; k <= trans->stypes.highbit; k++) {
                if (ebitmap_get_bit(&trans->stypes, k)) {
                    const char *src = db->p_type_val_to_name[k];
                    if (src) {
                        printf("type_transition %s %s %s %s %s\n", src, tgt, cls, def, key->name);
                    }
                }
            }
        }
    }
}

// Print genfscon rules
void sepol_print_genfscon(policydb_t *db) {
    if (!db) return;

    for (genfs_t *genfs = db->genfs; genfs; genfs = genfs->next) {
        for (ocontext_t *ctx = genfs->head; ctx; ctx = ctx->next) {
            char *ctx_str = context_to_str(db, &ctx->context[0]);
            if (ctx_str) {
                printf("genfscon %s %s %s\n", genfs->fstype, ctx->u.name, ctx_str);
                free(ctx_str);
            }
        }
    }
}

// Add a rule
int sepol_add_rule(policydb_t *db, const char *s, const char *t, const char *c, const char *p, int effect, int invert) {
    if (!db) return -1;

    type_datum_t *src = s && *s ? find_type(db, s) : NULL;
    type_datum_t *tgt = t && *t ? find_type(db, t) : NULL;
    class_datum_t *cls = c && *c ? find_class(db, c) : NULL;
    perm_datum_t *perm = p && *p && cls ? find_perm(cls, p) : NULL;

    if ((s && *s && !src) || (t && *t && !tgt) || (c && *c && !cls) || (p && *p && !perm)) {
        return -1;
    }

    // Simple implementation for direct rules
    if (src && tgt && cls) {
        avtab_key_t key;
        key.source_type = src->s.value;
        key.target_type = tgt->s.value;
        key.target_class = cls->s.value;
        key.specified = effect;

        avtab_datum_t datum;
        datum.data = perm ? (1U << (perm->s.value - 1)) : ~0U;
        datum.xperms = NULL;

        if (avtab_insert(&db->te_avtab, &key, &datum) != 0) {
            // Try to update existing
            avtab_datum_t *existing = avtab_search(&db->te_avtab, &key);
            if (existing) {
                if (invert) {
                    existing->data &= ~datum.data;
                } else {
                    existing->data |= datum.data;
                }
            }
        }
    }

    return 0;
}

// Add xperm rule (simplified)
int sepol_add_xperm_rule(policydb_t *db, const char *s, const char *t, const char *c, uint16_t low, uint16_t high, int reset, int effect) {
    // Simplified implementation - would need more complex xperm handling
    (void)db; (void)s; (void)t; (void)c; (void)low; (void)high; (void)reset; (void)effect;
    return -1;
}

// Add type rule
int sepol_add_type_rule(policydb_t *db, const char *s, const char *t, const char *c, const char *d, int effect) {
    if (!db || !s || !t || !c || !d) return -1;

    type_datum_t *src = find_type(db, s);
    type_datum_t *tgt = find_type(db, t);
    class_datum_t *cls = find_class(db, c);
    type_datum_t *def = find_type(db, d);

    if (!src || !tgt || !cls || !def) return -1;

    avtab_key_t key;
    key.source_type = src->s.value;
    key.target_type = tgt->s.value;
    key.target_class = cls->s.value;
    key.specified = effect;

    avtab_datum_t datum;
    datum.data = def->s.value;
    datum.xperms = NULL;

    return avtab_insert(&db->te_avtab, &key, &datum);
}

// Add filename trans (simplified)
int sepol_add_filename_trans(policydb_t *db, const char *s, const char *t, const char *c, const char *d, const char *o) {
    (void)db; (void)s; (void)t; (void)c; (void)d; (void)o;
    return -1; // TODO
}

// Add genfscon (simplified)
int sepol_add_genfscon(policydb_t *db, const char *fs, const char *path, const char *ctx) {
    (void)db; (void)fs; (void)path; (void)ctx;
    return -1; // TODO
}

// Add type
int sepol_add_type(policydb_t *db, const char *name, uint32_t flavor) {
    if (!db || !name) return -1;

    if (find_type(db, name)) return 0; // Already exists

    type_datum_t *type = calloc(1, sizeof(type_datum_t));
    if (!type) return -1;

    type_datum_init(type);
    type->primary = 1;
    type->flavor = flavor;

    char *name_copy = dup_str(name);
    uint32_t value = 0;

    if (symtab_insert(db, SYM_TYPES, name_copy, type, SCOPE_DECL, 1, &value) != 0) {
        free(name_copy);
        free(type);
        return -1;
    }

    type->s.value = value;
    ebitmap_set_bit(&db->global->branch_list->declared.p_types_scope, value - 1, 1);

    return 0;
}

// Set type state (permissive)
int sepol_set_type_state(policydb_t *db, const char *name, int permissive) {
    if (!db) return -1;

    if (name && *name) {
        type_datum_t *type = find_type(db, name);
        if (!type) return -1;
        return ebitmap_set_bit(&db->permissive_map, type->s.value, permissive);
    } else {
        // Set all types
        for (uint32_t i = 0; i < db->p_types.nprim; i++) {
            ebitmap_set_bit(&db->permissive_map, i + 1, permissive);
        }
        return 0;
    }
}

// Add typeattribute
int sepol_add_typeattribute(policydb_t *db, const char *type_name, const char *attr_name) {
    if (!db || !type_name || !attr_name) return -1;

    type_datum_t *type = find_type(db, type_name);
    if (!type || type->flavor == TYPE_ATTRIB) return -1;

    type_datum_t *attr = find_type(db, attr_name);
    if (!attr || attr->flavor != TYPE_ATTRIB) return -1;

    ebitmap_set_bit(&db->type_attr_map[type->s.value - 1], attr->s.value - 1, 1);
    ebitmap_set_bit(&db->attr_type_map[attr->s.value - 1], type->s.value - 1, 1);

    return 0;
}
