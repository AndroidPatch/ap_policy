//! FFI bindings to libsepol
//!
//! This module provides unsafe FFI bindings to the libsepol library.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use std::os::raw::{c_char, c_int, c_uint, c_void};

// Policy file types
pub const PF_USE_MEMORY: c_uint = 0;
pub const PF_USE_STDIO: c_uint = 1;

// AVTAB rule types
pub const AVTAB_ALLOWED: u16 = 0x0001;
pub const AVTAB_AUDITALLOW: u16 = 0x0002;
pub const AVTAB_AUDITDENY: u16 = 0x0004;
pub const AVTAB_TRANSITION: u16 = 0x0010;
pub const AVTAB_MEMBER: u16 = 0x0020;
pub const AVTAB_CHANGE: u16 = 0x0040;

pub const AVTAB_XPERMS_ALLOWED: u16 = 0x0100;
pub const AVTAB_XPERMS_AUDITALLOW: u16 = 0x0200;
pub const AVTAB_XPERMS_DONTAUDIT: u16 = 0x0400;

// Type flavors
pub const TYPE_TYPE: u32 = 0;
pub const TYPE_ATTRIB: u32 = 1;

// Scope declarations
pub const SCOPE_DECL: u32 = 1;
pub const SYM_TYPES: usize = 0;

// Opaque policydb type
#[repr(C)]
pub struct policydb {
    _opaque: [u8; 0],
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

    // Symbol table
    pub fn symtab_insert(
        db: *mut policydb,
        sym: usize,
        name: *mut c_char,
        datum: *mut c_void,
        scope: u32,
        avrule: c_int,
        value: *mut u32,
    ) -> c_int;
}

// Policy file structure
#[repr(C)]
pub struct policy_file {
    pub fp: *mut libc::FILE,
    pub data: *mut c_char,
    pub len: usize,
    pub type_: c_uint,
}

// Wrapper functions from our C library
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
    pub fn sepol_add_typeattribute(db: *mut policydb, type_name: *const c_char, attr_name: *const c_char) -> c_int;
}
