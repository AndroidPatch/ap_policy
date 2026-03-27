//! FFI bindings to libsepol
//!
//! This module provides unsafe FFI bindings to the libsepol library.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(clippy::upper_case_acronyms)]

use std::os::raw::{c_char, c_int, c_uint, c_void};

// Policy file types
pub const PF_USE_MEMORY: c_uint = 0;
pub const PF_USE_STDIO: c_uint = 1;

// AVTAB rule types
pub const AVTAB_ALLOWED: u16 = 0x0001;
pub const AVTAB_AUDITALLOW: u16 = 0x0002;
pub const AVTAB_AUDITDENY: u16 = 0x0004;
pub const AVTAB_NEVERALLOW: u16 = 0x0080;
pub const AVTAB_AV: u16 = AVTAB_ALLOWED | AVTAB_AUDITALLOW | AVTAB_AUDITDENY;
pub const AVTAB_TRANSITION: u16 = 0x0010;
pub const AVTAB_MEMBER: u16 = 0x0020;
pub const AVTAB_CHANGE: u16 = 0x0040;
pub const AVTAB_TYPE: u16 = AVTAB_TRANSITION | AVTAB_MEMBER | AVTAB_CHANGE;

pub const AVTAB_XPERMS_ALLOWED: u16 = 0x0100;
pub const AVTAB_XPERMS_AUDITALLOW: u16 = 0x0200;
pub const AVTAB_XPERMS_DONTAUDIT: u16 = 0x0400;
pub const AVTAB_XPERMS_NEVERALLOW: u16 = 0x0800;
pub const AVTAB_XPERMS: u16 =
    AVTAB_XPERMS_ALLOWED | AVTAB_XPERMS_AUDITALLOW | AVTAB_XPERMS_DONTAUDIT;

// Extended perms types
pub const AVTAB_XPERMS_IOCTLFUNCTION: u8 = 0x01;
pub const AVTAB_XPERMS_IOCTLDRIVER: u8 = 0x02;

// Type flavors
pub const TYPE_TYPE: u32 = 0;
pub const TYPE_ATTRIB: u32 = 1;
pub const TYPE_ALIAS: u32 = 2;

// Scope declarations
pub const SCOPE_DECL: u32 = 2; // In policydb.h SCOPE_DECL is 2
pub const SYM_TYPES: usize = 3; // SYM_TYPES is 3 in policydb.h

// Symbol table indices
pub const SYM_COMMONS: usize = 0;
pub const SYM_CLASSES: usize = 1;
pub const SYM_ROLES: usize = 2;
pub const SYM_USERS: usize = 4;
pub const SYM_BOOLS: usize = 5;
pub const SYM_LEVELS: usize = 6;
pub const SYM_CATS: usize = 7;
pub const SYM_NUM: usize = 8;
pub const OCON_NUM: usize = 9;

// Policy version with xperms ioctl support
pub const POLICYDB_VERSION_XPERMS_IOCTL: u32 = 30;

// Constraint expression types
pub const CEXPR_NAMES: u32 = 5;

// Android-specific flags
pub const POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE: u32 = 1u32 << 31;
pub const POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH: u32 = 1u32 << 30;
pub const POLICYDB_CONFIG_ANDROID_EXTRA_MASK: u32 =
    POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE | POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH;

// ---- ebitmap ----

#[repr(C)]
pub struct ebitmap_node {
    pub startbit: u32,
    pub map: u64, // MAPTYPE = uint64_t
    pub next: *mut ebitmap_node,
}

pub type ebitmap_node_t = ebitmap_node;

#[repr(C)]
pub struct ebitmap {
    pub node: *mut ebitmap_node_t,
    pub highbit: u32,
}

pub type ebitmap_t = ebitmap;

// ---- MLS types ----

#[repr(C)]
pub struct mls_level {
    pub sens: u32,
    pub cat: ebitmap_t,
}

pub type mls_level_t = mls_level;

#[repr(C)]
pub struct mls_range {
    pub level: [mls_level_t; 2],
}

pub type mls_range_t = mls_range;

#[repr(C)]
pub struct mls_semantic_cat {
    pub low: u32,
    pub high: u32,
    pub next: *mut mls_semantic_cat,
}

pub type mls_semantic_cat_t = mls_semantic_cat;

#[repr(C)]
pub struct mls_semantic_level {
    pub sens: u32,
    pub cat: *mut mls_semantic_cat_t,
}

pub type mls_semantic_level_t = mls_semantic_level;

#[repr(C)]
pub struct mls_semantic_range {
    pub level: [mls_semantic_level_t; 2],
}

pub type mls_semantic_range_t = mls_semantic_range;

// ---- context_struct ----

#[repr(C)]
pub struct context_struct {
    pub user: u32,
    pub role: u32,
    pub type_: u32,
    pub range: mls_range_t,
}

pub type context_struct_t = context_struct;

// ---- hashtab ----

pub type hashtab_key_t = *mut c_char;
pub type const_hashtab_key_t = *const c_char;
pub type hashtab_datum_t = *mut c_void;

#[repr(C)]
pub struct hashtab_node {
    pub key: hashtab_key_t,
    pub datum: hashtab_datum_t,
    pub next: *mut hashtab_node,
}

pub type hashtab_node_t = hashtab_node;
pub type hashtab_ptr_t = *mut hashtab_node_t;

// Function pointer types for hashtab_val
pub type HashFn = unsafe extern "C" fn(h: hashtab_t, key: const_hashtab_key_t) -> c_uint;
pub type KeycmpFn =
    unsafe extern "C" fn(h: hashtab_t, key1: const_hashtab_key_t, key2: const_hashtab_key_t)
        -> c_int;

#[repr(C)]
pub struct hashtab_val {
    pub htable: *mut hashtab_ptr_t,
    pub size: c_uint,
    pub nel: u32,
    pub hash_value: Option<HashFn>,
    pub keycmp: Option<KeycmpFn>,
}

pub type hashtab_val_t = hashtab_val;
pub type hashtab_t = *mut hashtab_val_t;

// ---- symtab ----

#[repr(C)]
pub struct symtab_datum {
    pub value: u32,
}

pub type symtab_datum_t = symtab_datum;

#[repr(C)]
pub struct symtab {
    pub table: hashtab_t,
    pub nprim: u32,
}

pub type symtab_t = symtab;

// ---- avtab ----

#[repr(C)]
pub struct avtab_key {
    pub source_type: u16,
    pub target_type: u16,
    pub target_class: u16,
    pub specified: u16,
}

pub type avtab_key_t = avtab_key;

#[repr(C)]
pub struct avtab_extended_perms {
    pub specified: u8,
    pub driver: u8,
    pub perms: [u32; 8],
}

pub type avtab_extended_perms_t = avtab_extended_perms;

#[repr(C)]
pub struct avtab_datum {
    pub data: u32,
    pub xperms: *mut avtab_extended_perms_t,
}

pub type avtab_datum_t = avtab_datum;

pub type avtab_ptr_t = *mut avtab_node;

#[repr(C)]
pub struct avtab_node {
    pub key: avtab_key_t,
    pub datum: avtab_datum_t,
    pub next: avtab_ptr_t,
    pub parse_context: *mut c_void,
    pub merged: c_uint,
}

pub type avtab_node_t = avtab_node;

#[repr(C)]
pub struct avtab {
    pub htable: *mut avtab_ptr_t,
    pub nel: u32,
    pub nslot: u32,
    pub mask: u32,
}

pub type avtab_t = avtab;

// ---- type_datum ----

#[repr(C)]
pub struct type_datum {
    pub s: symtab_datum_t,
    pub primary: u32,
    pub flavor: u32,
    pub types: ebitmap_t,
    pub flags: u32,
    pub bounds: u32,
}

pub type type_datum_t = type_datum;

// ---- perm_datum ----

#[repr(C)]
pub struct perm_datum {
    pub s: symtab_datum_t,
}

pub type perm_datum_t = perm_datum;

// ---- common_datum ----

#[repr(C)]
pub struct common_datum {
    pub s: symtab_datum_t,
    pub permissions: symtab_t,
}

pub type common_datum_t = common_datum;

// ---- constraint_expr ----

#[repr(C)]
pub struct type_set {
    pub types: ebitmap_t,
    pub negset: ebitmap_t,
    pub flags: u32,
}

pub type type_set_t = type_set;

#[repr(C)]
pub struct constraint_expr {
    pub expr_type: u32,
    pub attr: u32,
    pub op: u32,
    pub names: ebitmap_t,
    pub type_names: *mut type_set_t,
    pub next: *mut constraint_expr,
}

pub type constraint_expr_t = constraint_expr;

#[repr(C)]
pub struct constraint_node {
    pub permissions: u32, // sepol_access_vector_t = uint32_t
    pub expr: *mut constraint_expr_t,
    pub next: *mut constraint_node,
}

pub type constraint_node_t = constraint_node;

// ---- class_datum ----

#[repr(C)]
pub struct class_datum {
    pub s: symtab_datum_t,
    pub comkey: *mut c_char,
    pub comdatum: *mut common_datum_t,
    pub permissions: symtab_t,
    pub constraints: *mut constraint_node_t,
    pub validatetrans: *mut constraint_node_t,
    pub default_user: c_char,
    pub default_role: c_char,
    pub default_type: c_char,
    pub default_range: c_char,
}

pub type class_datum_t = class_datum;

// ---- role_datum ----

#[repr(C)]
pub struct role_datum {
    pub s: symtab_datum_t,
    pub dominates: ebitmap_t,
    pub types: type_set_t,
    pub cache: ebitmap_t,
    pub bounds: u32,
    pub flavor: u32,
    pub roles: ebitmap_t,
}

pub type role_datum_t = role_datum;

// ---- user_datum ----

#[repr(C)]
pub struct user_datum {
    pub s: symtab_datum_t,
    pub roles: role_set_t,
    pub range: mls_semantic_range_t,
    pub dfltlevel: mls_semantic_level_t,
    pub cache: ebitmap_t,
    pub exp_range: mls_range_t,
    pub exp_dfltlevel: mls_level_t,
    pub bounds: u32,
}

pub type user_datum_t = user_datum;

#[repr(C)]
pub struct role_set {
    pub roles: ebitmap_t,
    pub flags: u32,
}

pub type role_set_t = role_set;

// ---- cond_bool_datum ----

#[repr(C)]
pub struct cond_bool_datum {
    pub s: symtab_datum_t,
    pub state: c_int,
    pub flags: u32,
}

pub type cond_bool_datum_t = cond_bool_datum;

// ---- filename_trans ----

#[repr(C)]
pub struct filename_trans_key {
    pub ttype: u32,
    pub tclass: u32,
    pub name: *mut c_char,
}

pub type filename_trans_key_t = filename_trans_key;

#[repr(C)]
pub struct filename_trans_datum {
    pub stypes: ebitmap_t,
    pub otype: u32,
    pub next: *mut filename_trans_datum,
}

pub type filename_trans_datum_t = filename_trans_datum;

// ---- ocontext ----

// The union u in ocontext has multiple variants; the largest is node6 with 4*4 + 4*4 = 32 bytes
// We use a byte array of sufficient size.
// ibendport is: char *dev_name (8 bytes on 64-bit) + uint8_t port (1 byte) + padding = 16 bytes
// ibpkey: uint64_t + uint16_t + uint16_t + padding = 16 bytes
// iomem: uint64_t + uint64_t = 16 bytes
// ioport: uint32_t + uint32_t = 8 bytes
// node6: uint32_t[4] + uint32_t[4] = 32 bytes  -- this is largest
// port: uint8_t + uint16_t + uint16_t + padding = 8 bytes
// The largest "u" variant is the ibendport: pointer (8 bytes) + uint8_t = 16 bytes, OR node6 = 32 bytes
// Actually name is just a *char pointer = 8 bytes
// So the largest is node6 = 32 bytes OR ibpkey = 8+2+2=12 => 16 bytes aligned
// Maximum = 32 bytes for node6
// We keep it as a union via byte array
#[repr(C)]
pub struct ocontext_u {
    pub _data: [u8; 32],
}

#[repr(C)]
pub struct ocontext_v {
    pub _data: u32,
}

#[repr(C)]
pub struct ocontext {
    pub u: ocontext_u,
    pub v: ocontext_v,
    pub context: [context_struct_t; 2],
    pub sid: [u32; 2],
    pub next: *mut ocontext,
}

pub type ocontext_t = ocontext;

// Helper: get u.name from ocontext (first field is a pointer)
impl ocontext {
    pub unsafe fn u_name(&self) -> *const c_char {
        let ptr = self.u._data.as_ptr() as *const *const c_char;
        *ptr
    }
    pub unsafe fn u_name_mut(&mut self) -> *mut *mut c_char {
        let ptr = self.u._data.as_mut_ptr() as *mut *mut c_char;
        ptr
    }
}

// ---- genfs ----

#[repr(C)]
pub struct genfs {
    pub fstype: *mut c_char,
    pub head: *mut ocontext_t,
    pub next: *mut genfs,
}

pub type genfs_t = genfs;

// ---- role_trans ----

#[repr(C)]
pub struct role_trans {
    pub role: u32,
    pub type_: u32,
    pub tclass: u32,
    pub new_role: u32,
    pub next: *mut role_trans,
}

pub type role_trans_t = role_trans;

// ---- role_allow ----

#[repr(C)]
pub struct role_allow {
    pub role: u32,
    pub new_role: u32,
    pub next: *mut role_allow,
}

pub type role_allow_t = role_allow;

// ---- scope_index ----

#[repr(C)]
pub struct scope_index {
    pub scope: [ebitmap_t; SYM_NUM],
    pub class_perms_map: *mut ebitmap_t,
    pub class_perms_len: u32,
}

pub type scope_index_t = scope_index;

// ---- avrule forward decls ----
// We need avrule_decl_t and avrule_block_t for policydb_t
// We don't need full layout since we only access them via pointers

#[repr(C)]
pub struct avrule_decl {
    _opaque: [u8; 0],
}

pub type avrule_decl_t = avrule_decl;

#[repr(C)]
pub struct avrule_block {
    pub branch_list: *mut avrule_decl_t,
    pub enabled: *mut avrule_decl_t,
    pub flags: u32,
    pub next: *mut avrule_block,
}

pub type avrule_block_t = avrule_block;

// ---- scope_datum ----

#[repr(C)]
pub struct scope_datum {
    pub scope: u32,
    pub decl_ids: *mut u32,
    pub decl_ids_len: u32,
}

pub type scope_datum_t = scope_datum;

// ---- cond_node (forward decl for policydb) ----

#[repr(C)]
pub struct cond_node {
    _opaque: [u8; 0],
}

pub type cond_node_t = cond_node;
pub type cond_list_t = cond_node_t;

// ---- policydb_t ----
// Complete #[repr(C)] layout matching libsepol's policydb_t

#[repr(C)]
pub struct policydb {
    pub policy_type: u32,
    pub name: *mut c_char,
    pub version: *mut c_char,
    pub target_platform: c_int,
    pub unsupported_format: c_int,
    pub mls: c_int,

    // symtab[SYM_NUM] -- 8 entries
    pub symtab: [symtab_t; SYM_NUM],

    // sym_val_to_name[SYM_NUM] -- 8 pointers to char**
    pub sym_val_to_name: [*mut *mut c_char; SYM_NUM],

    // class/role/user/type val-to-struct arrays
    pub class_val_to_struct: *mut *mut class_datum_t,
    pub role_val_to_struct: *mut *mut role_datum_t,
    pub user_val_to_struct: *mut *mut user_datum_t,
    pub type_val_to_struct: *mut *mut type_datum_t,

    // scope symtabs
    pub scope: [symtab_t; SYM_NUM],

    // module stuff
    pub global: *mut avrule_block_t,
    pub decl_val_to_struct: *mut *mut avrule_decl_t,

    // compiled storage
    pub te_avtab: avtab_t,

    // conditional
    pub bool_val_to_struct: *mut *mut cond_bool_datum_t,
    pub te_cond_avtab: avtab_t,
    pub cond_list: *mut cond_list_t,

    // role transitions and allows
    pub role_tr: *mut role_trans_t,
    pub role_allow: *mut role_allow_t,

    // object contexts
    pub ocontexts: [*mut ocontext_t; OCON_NUM],

    // genfs
    pub genfs: *mut genfs_t,

    // range transitions
    pub range_tr: hashtab_t,

    // filename transitions
    pub filename_trans: hashtab_t,
    pub filename_trans_count: u32,

    // type/attr maps
    pub type_attr_map: *mut ebitmap_t,
    pub attr_type_map: *mut ebitmap_t,

    // policy caps
    pub policycaps: ebitmap_t,
    pub permissive_map: ebitmap_t,

    pub policyvers: c_uint,
    pub handle_unknown: c_uint,
    pub android_extra: u32,

    // process class / access vector caching
    pub process_class: u16,  // sepol_security_class_t = uint16_t
    pub dir_class: u16,
    pub process_trans: u32,  // sepol_access_vector_t = uint32_t
    pub process_trans_dyntrans: u32,
}

// Provide short aliases used by sepol_impl.rs
pub use policydb as policydb_t;

// Policy file structure (matches libsepol's policy_file_t)
#[repr(C)]
pub struct policy_file {
    pub type_: c_uint,   // "type" is a keyword in Rust, use type_
    pub data: *mut c_char,
    pub len: usize,
    pub size: usize,
    pub fp: *mut libc::FILE,
    pub handle: *mut c_void, // sepol_handle *
}

// External functions from libsepol
extern "C" {
    // Policy functions
    pub fn policydb_init(p: *mut policydb) -> c_int;
    pub fn policydb_read(p: *mut policydb, pf: *mut policy_file, verbose: c_int) -> c_int;
    pub fn policydb_write(p: *const policydb, pf: *mut policy_file) -> c_int;
    pub fn policydb_destroy(p: *mut policydb);
    pub fn policydb_index_classes(p: *mut policydb) -> c_int;
    pub fn policydb_index_others(handle: *mut c_void, p: *mut policydb, verbose: c_int) -> c_int;
    pub fn policydb_index_decls(handle: *mut c_void, p: *mut policydb) -> c_int;
    pub fn policy_file_init(x: *mut policy_file);

    // Symbol table
    pub fn symtab_insert(
        db: *mut policydb,
        sym: u32,
        name: *mut c_char,
        datum: *mut c_void,
        scope: u32,
        avrule_decl_id: u32,
        value: *mut u32,
    ) -> c_int;

    // Hashtable functions
    pub fn hashtab_search(h: hashtab_t, k: const_hashtab_key_t) -> hashtab_datum_t;
    pub fn hashtab_insert(h: hashtab_t, k: hashtab_key_t, d: hashtab_datum_t) -> c_int;

    // avtab functions
    pub fn avtab_search_node(h: *mut avtab_t, key: *mut avtab_key_t) -> avtab_ptr_t;
    pub fn avtab_search_node_next(node: avtab_ptr_t, specified: c_int) -> avtab_ptr_t;
    pub fn avtab_insert_nonunique(
        h: *mut avtab_t,
        key: *mut avtab_key_t,
        datum: *mut avtab_datum_t,
    ) -> avtab_ptr_t;
    pub fn avtab_insert(
        h: *mut avtab_t,
        k: *mut avtab_key_t,
        d: *mut avtab_datum_t,
    ) -> c_int;
    pub fn avtab_hash(keyp: *mut avtab_key_t, mask: u32) -> c_int;

    // ebitmap functions
    pub fn ebitmap_get_bit(e: *const ebitmap_t, bit: c_uint) -> c_int;
    pub fn ebitmap_set_bit(e: *mut ebitmap_t, bit: c_uint, value: c_int) -> c_int;
    pub fn ebitmap_destroy(e: *mut ebitmap_t);
    pub fn mls_range_destroy(r: *mut mls_range_t);
    pub fn ebitmap_init(e: *mut ebitmap_t);

    // Type/scope functions
    pub fn type_datum_init(x: *mut type_datum_t);
    pub fn type_set_expand(
        set: *mut type_set_t,
        t: *mut ebitmap_t,
        p: *mut policydb,
        force_attribute: c_int,
    ) -> c_int;

    // Conditional functions
    pub fn cond_node_destroy(node: *mut cond_node_t);

    // Context functions
    pub fn context_to_string(
        handle: *mut c_void,
        policydb: *const policydb,
        context: *const context_struct_t,
        result: *mut *mut c_char,
        result_len: *mut usize,
    ) -> c_int;

    pub fn context_from_string(
        handle: *mut c_void,
        policydb: *const policydb,
        cptr: *mut *mut context_struct_t,
        con_str: *const c_char,
        con_str_len: usize,
    ) -> c_int;

    pub fn context_destroy(c: *mut context_struct_t);
}

// Wrapper functions — now implemented in sepol_impl.rs via #[no_mangle]
extern "C" {
    pub fn sepol_print_types(db: *mut policydb, attributes: c_int);
    pub fn sepol_print_avtab_rules(db: *mut policydb);
    pub fn sepol_print_filename_trans(db: *mut policydb);
    pub fn sepol_print_genfscon(db: *mut policydb);

    pub fn sepol_db_new() -> *mut policydb;
    pub fn sepol_db_free(db: *mut policydb);
    pub fn sepol_db_from_file(path: *const c_char) -> *mut policydb;
    pub fn sepol_db_from_data(data: *const u8, len: usize) -> *mut policydb;
    pub fn sepol_db_to_file(db: *mut policydb, path: *const c_char) -> c_int;

    pub fn sepol_add_rule(
        db: *mut policydb,
        s: *const c_char,
        t: *const c_char,
        c: *const c_char,
        p: *const c_char,
        effect: c_int,
        invert: c_int,
    ) -> c_int;

    pub fn sepol_add_xperm_rule(
        db: *mut policydb,
        s: *const c_char,
        t: *const c_char,
        c: *const c_char,
        low: u16,
        high: u16,
        reset: c_int,
        effect: c_int,
    ) -> c_int;

    pub fn sepol_add_type_rule(
        db: *mut policydb,
        s: *const c_char,
        t: *const c_char,
        c: *const c_char,
        d: *const c_char,
        effect: c_int,
    ) -> c_int;

    pub fn sepol_add_filename_trans(
        db: *mut policydb,
        s: *const c_char,
        t: *const c_char,
        c: *const c_char,
        d: *const c_char,
        o: *const c_char,
    ) -> c_int;

    pub fn sepol_add_genfscon(
        db: *mut policydb,
        fs: *const c_char,
        path: *const c_char,
        ctx: *const c_char,
    ) -> c_int;

    pub fn sepol_add_type(db: *mut policydb, name: *const c_char, flavor: u32) -> c_int;
    pub fn sepol_set_type_state(db: *mut policydb, name: *const c_char, permissive: c_int) -> c_int;
    pub fn sepol_add_typeattribute(
        db: *mut policydb,
        type_name: *const c_char,
        attr_name: *const c_char,
    ) -> c_int;

    pub fn sepol_disable_neverallow(db: *mut policydb);
    pub fn sepol_strip_conditional(db: *mut policydb);
    pub fn sepol_preserve_policycaps(dst: *mut policydb, src: *mut policydb);
    pub fn sepol_reindex_full(db: *mut policydb) -> c_int;
    pub fn sepol_get_android_flags(db: *mut policydb) -> u32;
    pub fn sepol_set_android_flags(db: *mut policydb, flags: u32);
}
