#include "sepol_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/constraint.h>

// Android-specific flags (may not be in all libsepol versions)
#ifndef POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE
#define POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE  (1U << 31)
#endif
#ifndef POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH
#define POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH (1U << 30)
#endif
#ifndef POLICYDB_CONFIG_ANDROID_EXTRA_MASK
#define POLICYDB_CONFIG_ANDROID_EXTRA_MASK (POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE | POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH)
#endif

#if defined(__ANDROID__) || defined(__BSD__)
// funopen declaration for Android/BSD
FILE *funopen(void *cookie, int (*readfn)(void *, char *, int), int (*writefn)(void *, const char *, int), fpos_t (*seekfn)(void *, fpos_t, int), int (*closefn)(void *));
#define HAVE_FUNOPEN 1
#else
#define HAVE_FUNOPEN 0
#endif

void sepol_disable_neverallow(policydb_t *db) {
    if (!db) return;

    // Remove all constraint nodes from all classes
    // Note: This removes constraints but doesn't free them properly since
    // constraint_node_destroy is not available in standard libsepol.
    // In practice, this is used for live patching where the policy is
    // short-lived, so the memory leak is acceptable.
    for (uint32_t i = 0; i < db->p_classes.table->size; i++) {
        for (hashtab_ptr_t hp = db->p_classes.table->htable[i]; hp; hp = hp->next) {
            class_datum_t *cls = (class_datum_t *)hp->datum;
            if (!cls) continue;

            // Simply clear the constraints pointer
            // Memory will be leaked but this is acceptable for live patching
            cls->constraints = NULL;
        }
    }
}

void sepol_strip_conditional(policydb_t *db) {
    if (!db || !db->cond_list) return;

    cond_node_t *n = db->cond_list;
    db->cond_list = NULL;

    while (n) {
        cond_node_t *next = n->next;
        cond_node_destroy(n);
        n = next;
    }
}

void sepol_preserve_policycaps(policydb_t *dst, policydb_t *src) {
    if (!dst || !src) return;

    ebitmap_destroy(&dst->policycaps);
    ebitmap_init(&dst->policycaps);

    for (uint32_t i = 0; i <= src->policycaps.highbit; i++) {
        if (ebitmap_get_bit(&src->policycaps, i)) {
            ebitmap_set_bit(&dst->policycaps, i, 1);
        }
    }
}

// Android-specific flag handling
uint32_t sepol_get_android_flags(policydb_t *db) {
    if (!db) return 0;
    return db->android_extra;
}

void sepol_set_android_flags(policydb_t *db, uint32_t flags) {
    if (!db) return;
    db->android_extra = flags;
}

int sepol_reindex_full(policydb_t *db) {
    if (!db) return -1;

    if (policydb_index_decls(NULL, db) != 0)
        return -1;

    if (policydb_index_classes(db) != 0)
        return -1;

    if (policydb_index_others(NULL, db, 0) != 0)
        return -1;

    // Note: policydb_expand is not available in standard libsepol
    // For Android live patching, the basic reindexing above is sufficient
    // The type/attribute expansion happens automatically during rule addition

    return 0;
}

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

// Internal libsepol function — produces full "user:role:type[:mls]" string
extern int context_to_string(sepol_handle_t *handle, const policydb_t *policydb,
                             const context_struct_t *context,
                             char **result, size_t *result_len);

// Helper: format context as a heap-allocated string (caller must free)
static char *context_to_str(policydb_t *db, context_struct_t *ctx) {
    if (!db || !ctx) return NULL;
    char *result = NULL;
    size_t result_len = 0;
    if (context_to_string(NULL, db, ctx, &result, &result_len) != 0)
        return NULL;
    return result;   // already NUL-terminated; caller frees
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

// Dynamic buffer for policy write
struct policy_buf {
    char *data;
    size_t size;
    size_t capacity;
};

#if HAVE_FUNOPEN
static int buf_write(void *cookie, const char *buf, int len) {
    struct policy_buf *pb = (struct policy_buf *)cookie;
    size_t new_size = pb->size + len;
    if (new_size > pb->capacity) {
        size_t new_cap = pb->capacity ? pb->capacity * 2 : 64 * 1024;
        while (new_cap < new_size) new_cap *= 2;
        char *new_data = realloc(pb->data, new_cap);
        if (!new_data) return -1;
        pb->data = new_data;
        pb->capacity = new_cap;
    }
    memcpy(pb->data + pb->size, buf, len);
    pb->size = new_size;
    return len;
}
#endif

// Save policydb to file
// Note: /sys/fs/selinux/load requires the entire policy to be written in one write() syscall
int sepol_db_to_file(policydb_t *db, const char *path) {
    if (!db || !path) return -1;

    char *data = NULL;
    size_t size = 0;
    FILE *fp = NULL;

#if HAVE_FUNOPEN
    // Use funopen (Android/BSD) to write to memory buffer
    struct policy_buf pb = { .data = NULL, .size = 0, .capacity = 0 };
    fp = funopen(&pb, NULL, buf_write, NULL, NULL);
    if (!fp) return -1;
#else
    // Use open_memstream (POSIX) for Linux
    fp = open_memstream(&data, &size);
    if (!fp) return -1;
#endif

    // Disable buffering since we're writing directly to memory
    setbuf(fp, NULL);

    policy_file_t pf;
    policy_file_init(&pf);
    pf.fp = fp;
    pf.type = PF_USE_STDIO;

    int ret = policydb_write(db, &pf);
    fclose(fp);

#if HAVE_FUNOPEN
    data = pb.data;
    size = pb.size;
#endif

    if (ret != 0) {
        free(data);
        return -1;
    }

    // Open file for writing
    // NOTE: Do NOT use O_TRUNC for /sys/fs/selinux/load - it's a special kernel interface
    int fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) {
        free(data);
        return -1;
    }

    // If file has existing content, truncate it explicitly
    struct stat st;
    if (fstat(fd, &st) == 0 && st.st_size > 0) {
        ftruncate(fd, 0);
    }

    // Write all data in one write() call (required for /sys/fs/selinux/load)
    // The kernel expects the entire policy in a single write operation
    ssize_t written = write(fd, data, size);
    if (written < 0 || (size_t)written != size) {
        close(fd);
        free(data);
        return -1;
    }

    close(fd);
    free(data);
    return 0;
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
            // Print permissive
            if (ebitmap_get_bit(&db->permissive_map, type->s.value)) {
                printf("permissive %s\n", name);
            }
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

                // Build a value→name lookup table for this class (covers all hash buckets)
                // Max 32 permissions per class (uint32_t bitmask)
                const char *perm_names[32] = { NULL };
                if (clz->permissions.table) {
                    for (uint32_t b = 0; b < clz->permissions.table->size; b++) {
                        for (hashtab_ptr_t hp = clz->permissions.table->htable[b]; hp; hp = hp->next) {
                            perm_datum_t *pd = (perm_datum_t *)hp->datum;
                            if (pd && pd->s.value >= 1 && pd->s.value <= 32)
                                perm_names[pd->s.value - 1] = (const char *)hp->key;
                        }
                    }
                }
                if (clz->comdatum && clz->comdatum->permissions.table) {
                    for (uint32_t b = 0; b < clz->comdatum->permissions.table->size; b++) {
                        for (hashtab_ptr_t hp = clz->comdatum->permissions.table->htable[b]; hp; hp = hp->next) {
                            perm_datum_t *pd = (perm_datum_t *)hp->datum;
                            if (pd && pd->s.value >= 1 && pd->s.value <= 32 && !perm_names[pd->s.value - 1])
                                perm_names[pd->s.value - 1] = (const char *)hp->key;
                        }
                    }
                }

                // Print permissions
                int first = 1;
                for (uint32_t bit = 0; bit < 32; bit++) {
                    if ((data & (1u << bit)) && perm_names[bit]) {
                        if (first) {
                            printf("%s %s %s %s {", name, src, tgt, cls);
                            first = 0;
                        }
                        printf(" %s", perm_names[bit]);
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

// Forward declaration — xperm_remove_node is defined later but used in add_rule_impl
static int xperm_remove_node(avtab_t *h, avtab_ptr_t node);

// Remove a redundant avtab node (data has no effect) — mirrors Magisk's is_redundant check
static int is_redundant(avtab_ptr_t node) {
    switch (node->key.specified) {
        case AVTAB_AUDITDENY:
            return node->datum.data == ~0U;
        default:
            return node->datum.data == 0U;
    }
}

// Core rule insertion for a resolved (src, tgt, cls) triple — mirrors Magisk's add_rule
static void add_rule_impl(policydb_t *db, type_datum_t *src, type_datum_t *tgt,
                          class_datum_t *cls, perm_datum_t *perm, int effect, int invert) {
    avtab_key_t key;
    key.source_type = src->s.value;
    key.target_type = tgt->s.value;
    key.target_class = cls->s.value;
    key.specified = (uint16_t)effect;
    // Find existing node or create a new one
    avtab_ptr_t node = avtab_search_node(&db->te_avtab, &key);
    if (!node) {
        avtab_datum_t init;
        // AUDITDENY nodes are &= assigned, so initialize to all-ones; others to 0
        init.data = (effect == AVTAB_AUDITDENY) ? ~0U : 0U;
        init.xperms = NULL;
        node = avtab_insert_nonunique(&db->te_avtab, &key, &init);
        if (!node) return;
    }

    if (invert) {
        if (perm)
            node->datum.data &= ~(1U << (perm->s.value - 1));
        else
            node->datum.data = 0U;
    } else {
        if (perm)
            node->datum.data |= 1U << (perm->s.value - 1);
        else
            node->datum.data = ~0U;
    }

    // Remove node if it has become redundant (mirrors Magisk's is_redundant cleanup)
    if (is_redundant(node))
        xperm_remove_node(&db->te_avtab, node);
}

// Expand wildcards (NULL src/tgt/cls) and apply rule — mirrors Magisk's add_rule overload
static void expand_rule(policydb_t *db, type_datum_t *src, type_datum_t *tgt,
                        class_datum_t *cls, perm_datum_t *perm,
                        int effect, int invert);

static void expand_rule(policydb_t *db, type_datum_t *src, type_datum_t *tgt,
                        class_datum_t *cls, perm_datum_t *perm,
                        int effect, int invert) {
    // Determine strip_av: for AUDITDENY, stripping means adding (invert=false),
    // for others stripping means removing (invert=true)
    int strip_av = (effect == AVTAB_AUDITDENY) == !invert;

    if (!src) {
        if (strip_av) {
            // Must iterate all types (not just attrs) for correct stripping
            for (uint32_t i = 0; i < db->p_types.table->size; i++) {
                for (hashtab_ptr_t n = db->p_types.table->htable[i]; n; n = n->next) {
                    type_datum_t *type = (type_datum_t *)n->datum;
                    if (type) expand_rule(db, type, tgt, cls, perm, effect, invert);
                }
            }
        } else {
            // Optimization: iterate attributes only
            for (uint32_t i = 0; i < db->p_types.table->size; i++) {
                for (hashtab_ptr_t n = db->p_types.table->htable[i]; n; n = n->next) {
                    type_datum_t *type = (type_datum_t *)n->datum;
                    if (type && type->flavor == TYPE_ATTRIB)
                        expand_rule(db, type, tgt, cls, perm, effect, invert);
                }
            }
        }
    } else if (!tgt) {
        if (strip_av) {
            for (uint32_t i = 0; i < db->p_types.table->size; i++) {
                for (hashtab_ptr_t n = db->p_types.table->htable[i]; n; n = n->next) {
                    type_datum_t *type = (type_datum_t *)n->datum;
                    if (type) expand_rule(db, src, type, cls, perm, effect, invert);
                }
            }
        } else {
            for (uint32_t i = 0; i < db->p_types.table->size; i++) {
                for (hashtab_ptr_t n = db->p_types.table->htable[i]; n; n = n->next) {
                    type_datum_t *type = (type_datum_t *)n->datum;
                    if (type && type->flavor == TYPE_ATTRIB)
                        expand_rule(db, src, type, cls, perm, effect, invert);
                }
            }
        }
    } else if (!cls) {
        for (uint32_t i = 0; i < db->p_classes.table->size; i++) {
            for (hashtab_ptr_t n = db->p_classes.table->htable[i]; n; n = n->next) {
                class_datum_t *c = (class_datum_t *)n->datum;
                if (c) expand_rule(db, src, tgt, c, perm, effect, invert);
            }
        }
    } else {
        add_rule_impl(db, src, tgt, cls, perm, effect, invert);
    }
}

// Add a rule
int sepol_add_rule(policydb_t *db, const char *s, const char *t, const char *c, const char *p, int effect, int invert) {
    if (!db) return -1;

    type_datum_t *src = (s && *s) ? find_type(db, s) : NULL;
    type_datum_t *tgt = (t && *t) ? find_type(db, t) : NULL;
    class_datum_t *cls = (c && *c) ? find_class(db, c) : NULL;
    perm_datum_t *perm = (p && *p && cls) ? find_perm(cls, p) : NULL;

    if ((s && *s && !src) || (t && *t && !tgt) || (c && *c && !cls) || (p && *p && !perm)) {
        return -1;
    }

    expand_rule(db, src, tgt, cls, perm, effect, invert);
    return 0;
}

// Internal: avtab_hash is defined in avtab.c but not in the public header
extern int avtab_hash(struct avtab_key *keyp, uint32_t mask);

#define ioctl_driver(x) ((x) >> 8 & 0xFF)
#define ioctl_func(x)   ((x) & 0xFF)

// Remove a node from the avtab (mirrors Magisk's avtab_remove_node)
static int xperm_remove_node(avtab_t *h, avtab_ptr_t node) {
    if (!h || !h->htable) return -1;
    int hvalue = avtab_hash(&node->key, h->mask);
    avtab_ptr_t prev = NULL;
    avtab_ptr_t cur = h->htable[hvalue];
    while (cur) {
        if (cur == node) break;
        prev = cur;
        cur = cur->next;
    }
    if (!cur) return -1;
    if (prev)
        prev->next = node->next;
    else
        h->htable[hvalue] = node->next;
    h->nel--;
    free(node->datum.xperms);
    free(node);
    return 0;
}

// Core xperm rule application for a resolved (src, tgt, cls) triple
static void add_xperm_rule_impl(policydb_t *db, type_datum_t *src, type_datum_t *tgt,
                                class_datum_t *cls, uint16_t low, uint16_t high,
                                int reset, int effect) {
    avtab_key_t key;
    key.source_type = src->s.value;
    key.target_type = tgt->s.value;
    key.target_class = cls->s.value;
    key.specified = (uint16_t)effect;

    // Collect existing nodes: node_list[0..255] = function nodes indexed by driver byte
    //                         node_list[256]    = driver node
    avtab_ptr_t node_list[257];
    memset(node_list, 0, sizeof(node_list));
    avtab_ptr_t driver_node = NULL;

    for (avtab_ptr_t node = avtab_search_node(&db->te_avtab, &key); node;
         node = avtab_search_node_next(node, key.specified)) {
        if (!node->datum.xperms) continue;
        if (node->datum.xperms->specified == AVTAB_XPERMS_IOCTLDRIVER) {
            driver_node = node;
            node_list[256] = node;
        } else if (node->datum.xperms->specified == AVTAB_XPERMS_IOCTLFUNCTION) {
            node_list[node->datum.xperms->driver] = node;
        }
    }

    // Helper: allocate and insert a new driver node
#define new_driver_node() ({ \
    avtab_datum_t avdatum = { .data = 0, .xperms = NULL }; \
    avtab_ptr_t _n = avtab_insert_nonunique(&db->te_avtab, &key, &avdatum); \
    if (_n) { \
        _n->datum.xperms = calloc(1, sizeof(avtab_extended_perms_t)); \
        if (_n->datum.xperms) { \
            _n->datum.xperms->specified = AVTAB_XPERMS_IOCTLDRIVER; \
            _n->datum.xperms->driver = 0; \
        } \
    } \
    _n; \
})

    // Helper: allocate and insert a new function node for a given driver byte
#define new_func_node(drv) ({ \
    avtab_datum_t avdatum = { .data = 0, .xperms = NULL }; \
    avtab_ptr_t _n = avtab_insert_nonunique(&db->te_avtab, &key, &avdatum); \
    if (_n) { \
        _n->datum.xperms = calloc(1, sizeof(avtab_extended_perms_t)); \
        if (_n->datum.xperms) { \
            _n->datum.xperms->specified = AVTAB_XPERMS_IOCTLFUNCTION; \
            _n->datum.xperms->driver = (uint8_t)(drv); \
        } \
    } \
    _n; \
})

    if (reset) {
        // Remove all existing function nodes
        for (int i = 0; i <= 0xFF; i++) {
            if (node_list[i]) {
                xperm_remove_node(&db->te_avtab, node_list[i]);
                node_list[i] = NULL;
            }
        }
        // Zero out driver node perms if it exists
        if (driver_node && driver_node->datum.xperms) {
            memset(driver_node->datum.xperms->perms, 0,
                   sizeof(avtab_extended_perms_t) - offsetof(avtab_extended_perms_t, perms));
        }

        // Create driver node if needed, fill all driver bits
        if (!driver_node) driver_node = new_driver_node();
        if (!driver_node || !driver_node->datum.xperms) goto cleanup;

        memset(driver_node->datum.xperms->perms, ~0,
               sizeof(driver_node->datum.xperms->perms));

        if (ioctl_driver(low) != ioctl_driver(high)) {
            // Cross-driver range: clear those driver bits
            for (int i = ioctl_driver(low); i <= ioctl_driver(high); i++) {
                xperm_clear(i, driver_node->datum.xperms->perms);
            }
        } else {
            // Same driver: clear that driver bit, create func node with all bits set,
            // then clear the specified function range
            uint8_t drv = (uint8_t)ioctl_driver(low);
            xperm_clear(drv, driver_node->datum.xperms->perms);

            avtab_ptr_t fnode = node_list[drv];
            if (!fnode) {
                fnode = new_func_node(drv);
                node_list[drv] = fnode;
            }
            if (!fnode || !fnode->datum.xperms) goto cleanup;
            // Fill all func bits
            memset(fnode->datum.xperms->perms, ~0,
                   sizeof(fnode->datum.xperms->perms));
            // Clear the specified range
            for (int i = ioctl_func(low); i <= ioctl_func(high); i++) {
                xperm_clear(i, fnode->datum.xperms->perms);
            }
        }
    } else {
        if (ioctl_driver(low) != ioctl_driver(high)) {
            // Cross-driver range: set bits in the driver node
            if (!driver_node) driver_node = new_driver_node();
            if (!driver_node || !driver_node->datum.xperms) goto cleanup;
            for (int i = ioctl_driver(low); i <= ioctl_driver(high); i++) {
                xperm_set(i, driver_node->datum.xperms->perms);
            }
        } else {
            // Same driver: set bits in the function node for that driver
            uint8_t drv = (uint8_t)ioctl_driver(low);
            avtab_ptr_t fnode = node_list[drv];
            if (!fnode) {
                fnode = new_func_node(drv);
                node_list[drv] = fnode;
            }
            if (!fnode || !fnode->datum.xperms) goto cleanup;
            for (int i = ioctl_func(low); i <= ioctl_func(high); i++) {
                xperm_set(i, fnode->datum.xperms->perms);
            }
        }
    }

cleanup:
#undef new_driver_node
#undef new_func_node
    return;
}

// Expand wildcard (NULL src/tgt/cls) and call add_xperm_rule_impl
static void expand_xperm_rule(policydb_t *db, type_datum_t *src, type_datum_t *tgt,
                               class_datum_t *cls, uint16_t low, uint16_t high,
                               int reset, int effect);

static void expand_xperm_rule(policydb_t *db, type_datum_t *src, type_datum_t *tgt,
                               class_datum_t *cls, uint16_t low, uint16_t high,
                               int reset, int effect) {
    if (!src) {
        for (uint32_t i = 0; i < db->p_types.table->size; i++) {
            for (hashtab_ptr_t node = db->p_types.table->htable[i]; node; node = node->next) {
                type_datum_t *type = (type_datum_t *)node->datum;
                if (type && type->flavor == TYPE_ATTRIB)
                    expand_xperm_rule(db, type, tgt, cls, low, high, reset, effect);
            }
        }
    } else if (!tgt) {
        for (uint32_t i = 0; i < db->p_types.table->size; i++) {
            for (hashtab_ptr_t node = db->p_types.table->htable[i]; node; node = node->next) {
                type_datum_t *type = (type_datum_t *)node->datum;
                if (type && type->flavor == TYPE_ATTRIB)
                    expand_xperm_rule(db, src, type, cls, low, high, reset, effect);
            }
        }
    } else if (!cls) {
        for (uint32_t i = 0; i < db->p_classes.table->size; i++) {
            for (hashtab_ptr_t node = db->p_classes.table->htable[i]; node; node = node->next) {
                class_datum_t *c = (class_datum_t *)node->datum;
                if (c) add_xperm_rule_impl(db, src, tgt, c, low, high, reset, effect);
            }
        }
    } else {
        add_xperm_rule_impl(db, src, tgt, cls, low, high, reset, effect);
    }
}

// Add xperm rule (ported from Magisk's sepol_impl::add_xperm_rule)
int sepol_add_xperm_rule(policydb_t *db, const char *s, const char *t, const char *c,
                         uint16_t low, uint16_t high, int reset, int effect) {
    if (!db) return -1;

    if (db->policyvers < POLICYDB_VERSION_XPERMS_IOCTL) {
        fprintf(stderr, "policy version %u does not support ioctl xperms rules\n",
                db->policyvers);
        return -1;
    }

    type_datum_t *src = (s && *s) ? find_type(db, s) : NULL;
    type_datum_t *tgt = (t && *t) ? find_type(db, t) : NULL;
    class_datum_t *cls = (c && *c) ? find_class(db, c) : NULL;

    if ((s && *s && !src) || (t && *t && !tgt) || (c && *c && !cls))
        return -1;

    expand_xperm_rule(db, src, tgt, cls, low, high, reset, effect);
    return 0;
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

// Add filename_trans rule — mirrors Magisk's sepol_impl::add_filename_trans
int sepol_add_filename_trans(policydb_t *db, const char *s, const char *t, const char *c, const char *d, const char *o) {
    if (!db || !s || !t || !c || !d || !o) return -1;

    type_datum_t *src = find_type(db, s);
    if (!src) { fprintf(stderr, "filename_trans: source type %s does not exist\n", s); return -1; }
    type_datum_t *tgt = find_type(db, t);
    if (!tgt) { fprintf(stderr, "filename_trans: target type %s does not exist\n", t); return -1; }
    class_datum_t *cls = find_class(db, c);
    if (!cls) { fprintf(stderr, "filename_trans: class %s does not exist\n", c); return -1; }
    type_datum_t *def = find_type(db, d);
    if (!def) { fprintf(stderr, "filename_trans: default type %s does not exist\n", d); return -1; }

    // Build lookup key (stack-allocated name, same as Magisk)
    filename_trans_key_t key;
    key.ttype  = tgt->s.value;
    key.tclass = cls->s.value;
    key.name   = (char *)o;   /* hashtab search doesn't mutate key */

    // Walk existing chain for this key
    filename_trans_datum_t *trans = (filename_trans_datum_t *)hashtab_search(db->filename_trans, (hashtab_key_t)&key);
    filename_trans_datum_t *last  = NULL;
    while (trans) {
        if (ebitmap_get_bit(&trans->stypes, src->s.value - 1)) {
            // Duplicate entry — just update the default type
            trans->otype = def->s.value;
            return 0;
        }
        if (trans->otype == def->s.value)
            break;      // reuse this node (same otype, different stypes)
        last  = trans;
        trans = trans->next;
    }

    if (!trans) {
        // New datum for this (key, otype) combination
        trans = (filename_trans_datum_t *)calloc(1, sizeof(*trans));
        if (!trans) return -1;
        ebitmap_init(&trans->stypes);
        trans->otype = def->s.value;
    }

    if (last) {
        // Append to existing chain
        last->next = trans;
    } else {
        // First entry for this key — allocate a permanent key and insert
        filename_trans_key_t *new_key = (filename_trans_key_t *)malloc(sizeof(*new_key));
        if (!new_key) { free(trans); return -1; }
        new_key->ttype  = key.ttype;
        new_key->tclass = key.tclass;
        new_key->name   = strdup(o);
        if (!new_key->name) { free(new_key); free(trans); return -1; }
        if (hashtab_insert(db->filename_trans, (hashtab_key_t)new_key, trans) != 0) {
            free(new_key->name); free(new_key); free(trans); return -1;
        }
    }

    db->filename_trans_count++;
    return ebitmap_set_bit(&trans->stypes, src->s.value - 1, 1) == 0 ? 0 : -1;
}

// context_from_string is an internal libsepol function
extern int context_from_string(sepol_handle_t *handle, const policydb_t *policydb,
                               context_struct_t **cptr,
                               const char *con_str, size_t con_str_len);

// Add genfscon rule — mirrors Magisk's sepol_impl::add_genfscon
int sepol_add_genfscon(policydb_t *db, const char *fs, const char *path, const char *ctx) {
    if (!db || !fs || !path || !ctx) return -1;

    // Parse context string into internal representation
    context_struct_t *new_ctx = NULL;
    if (context_from_string(NULL, db, &new_ctx, ctx, strlen(ctx)) != 0) {
        fprintf(stderr, "genfscon: failed to parse context '%s'\n", ctx);
        return -1;
    }

    // Find or create genfs node for this filesystem
    genfs_t *genfs = db->genfs;
    while (genfs) {
        if (strcmp(genfs->fstype, fs) == 0) break;
        genfs = genfs->next;
    }
    if (!genfs) {
        genfs = (genfs_t *)calloc(1, sizeof(*genfs));
        if (!genfs) { free(new_ctx); return -1; }
        genfs->fstype = strdup(fs);
        if (!genfs->fstype) { free(genfs); free(new_ctx); return -1; }
        genfs->next = db->genfs;
        db->genfs   = genfs;
    }

    // Find or create ocontext node for this path within the genfs
    ocontext_t *ocon = genfs->head;
    while (ocon) {
        if (strcmp(ocon->u.name, path) == 0) break;
        ocon = ocon->next;
    }
    if (!ocon) {
        ocon = (ocontext_t *)calloc(1, sizeof(*ocon));
        if (!ocon) { free(new_ctx); return -1; }
        ocon->u.name = strdup(path);
        if (!ocon->u.name) { free(ocon); free(new_ctx); return -1; }
        ocon->next  = genfs->head;
        genfs->head = ocon;
    }

    if (ocon->context[0].user) { 
        context_destroy(&ocon->context[0]);
    }
    memcpy(&ocon->context[0], new_ctx, sizeof(*new_ctx));
    free(new_ctx);
    return 0;
}

// Add type (based on Magisk's implementation)
int sepol_add_type(policydb_t *db, const char *name, uint32_t flavor) {
    if (!db || !name) return -1;

    type_datum_t *type = hashtab_search(db->p_types.table, (hashtab_key_t)name);
    if (type) {
        // Type already exists - this is not an error
        return 0;
    }

    type = calloc(1, sizeof(type_datum_t));
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

    // For modular policies, set scope; kernel policies have global initialized
    if (db->global && db->global->branch_list) {
        ebitmap_set_bit(&db->global->branch_list->declared.p_types_scope, value - 1, 1);
    }

    // Resize type_attr_map and attr_type_map
    size_t new_size = sizeof(ebitmap_t) * db->p_types.nprim;
    ebitmap_t *new_type_attr_map = realloc(db->type_attr_map, new_size);
    if (new_type_attr_map) db->type_attr_map = new_type_attr_map;
    ebitmap_t *new_attr_type_map = realloc(db->attr_type_map, new_size);
    if (new_attr_type_map) db->attr_type_map = new_attr_type_map;
    if (!new_type_attr_map || !new_attr_type_map) {
        return -1;
    }
    db->type_attr_map = new_type_attr_map;
    db->attr_type_map = new_attr_type_map;
    ebitmap_init(&db->type_attr_map[value - 1]);
    ebitmap_init(&db->attr_type_map[value - 1]);
    ebitmap_set_bit(&db->type_attr_map[value - 1], value - 1, 1);

    // Re-index the policy database
    // Note: For POLICY_KERN, policydb_index_decls handles NULL global gracefully
    if (policydb_index_decls(NULL, db) != 0 ||
        policydb_index_classes(db) != 0 ||
        policydb_index_others(NULL, db, 0) != 0) {
        return -1;
    }

    // Add the type to all roles
    for (uint32_t i = 0; i < db->p_roles.nprim; i++) {
        ebitmap_set_bit(&db->role_val_to_struct[i]->types.negset, value - 1, 0);
        ebitmap_set_bit(&db->role_val_to_struct[i]->types.types, value - 1, 1);
        type_set_expand(&db->role_val_to_struct[i]->types, &db->role_val_to_struct[i]->cache, db, 0);
    }

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

    // Expand constraint expressions: for every class constraint, if an expression
    // references the attribute being assigned, add the new type to it as well.
    // This is required for MLS constraints (mlstrustedsubject / mlstrustedobject etc.)
    // to recognise the new type — mirrors Magisk's sepol_impl::add_typeattribute.
    for (uint32_t i = 0; i < db->p_classes.table->size; i++) {
        for (hashtab_ptr_t hp = db->p_classes.table->htable[i]; hp; hp = hp->next) {
            class_datum_t *cls = (class_datum_t *)hp->datum;
            if (!cls) continue;
            for (constraint_node_t *n = cls->constraints; n; n = n->next) {
                for (constraint_expr_t *e = n->expr; e; e = e->next) {
                    if (e->expr_type == CEXPR_NAMES && e->type_names &&
                        ebitmap_get_bit(&e->type_names->types, attr->s.value - 1)) {
                        ebitmap_set_bit(&e->names, type->s.value - 1, 1);
                    }
                }
            }
        }
    }

    return 0;
}
