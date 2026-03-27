//! Pure Rust implementation of SELinux policy manipulation
//!
//! This module provides Rust implementations of all functions previously in
//! sepol_wrapper.c, directly calling libsepol FFI bindings.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::{mem, ptr, slice};

use crate::sepol::*;

// ---- xperm bit manipulation ----
// xperm_test(x, p): p is *const u32 array of 8 u32 = 256 bits
// Bit x: word p[x >> 5], bit (x & 0x1f)

#[inline]
unsafe fn xperm_test(x: usize, p: *const u32) -> bool {
    let word = *p.add(x >> 5);
    (word >> (x & 0x1f)) & 1 != 0
}

#[inline]
unsafe fn xperm_set(x: usize, p: *mut u32) {
    let word = p.add(x >> 5);
    *word |= 1u32 << (x & 0x1f);
}

#[inline]
unsafe fn xperm_clear(x: usize, p: *mut u32) {
    let word = p.add(x >> 5);
    *word &= !(1u32 << (x & 0x1f));
}

// ---- helpers ----

/// Duplicate a string (heap-allocated, caller must free)
unsafe fn dup_str(s: *const c_char) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }
    let cs = CStr::from_ptr(s);
    let bytes = cs.to_bytes_with_nul();
    let ptr = libc::malloc(bytes.len()) as *mut c_char;
    if !ptr.is_null() {
        ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, bytes.len());
    }
    ptr
}

/// Find type by name in policydb
unsafe fn find_type(db: *mut policydb, name: *const c_char) -> *mut type_datum_t {
    if name.is_null() || db.is_null() {
        return ptr::null_mut();
    }
    hashtab_search((*db).symtab[SYM_TYPES].table, name) as *mut type_datum_t
}

/// Find class by name in policydb
unsafe fn find_class(db: *mut policydb, name: *const c_char) -> *mut class_datum_t {
    if name.is_null() || db.is_null() {
        return ptr::null_mut();
    }
    hashtab_search((*db).symtab[SYM_CLASSES].table, name) as *mut class_datum_t
}

/// Find permission in class (checks comdatum too)
unsafe fn find_perm(cls: *mut class_datum_t, name: *const c_char) -> *mut perm_datum_t {
    if name.is_null() || cls.is_null() {
        return ptr::null_mut();
    }
    let perm = hashtab_search((*cls).permissions.table, name) as *mut perm_datum_t;
    if !perm.is_null() {
        return perm;
    }
    if !(*cls).comdatum.is_null() {
        return hashtab_search((*(*cls).comdatum).permissions.table, name) as *mut perm_datum_t;
    }
    ptr::null_mut()
}

/// Format a context_struct_t as a string (caller must free with libc::free)
unsafe fn context_to_str(db: *mut policydb, ctx: *mut context_struct_t) -> *mut c_char {
    if db.is_null() || ctx.is_null() {
        return ptr::null_mut();
    }
    let mut result: *mut c_char = ptr::null_mut();
    let mut result_len: usize = 0;
    if context_to_string(ptr::null_mut(), db, ctx, &mut result, &mut result_len) != 0 {
        return ptr::null_mut();
    }
    result
}

// ---- Remove node from avtab ----

unsafe fn xperm_remove_node(h: *mut avtab_t, node: avtab_ptr_t) -> c_int {
    if h.is_null() || (*h).htable.is_null() {
        return -1;
    }
    let hvalue = avtab_hash(&mut (*node).key as *mut avtab_key_t, (*h).mask);
    if hvalue < 0 {
        return -1;
    }
    let hvalue = hvalue as usize;
    let mut prev: avtab_ptr_t = ptr::null_mut();
    let mut cur = *(*h).htable.add(hvalue);
    while !cur.is_null() {
        if cur == node {
            break;
        }
        prev = cur;
        cur = (*cur).next;
    }
    if cur.is_null() {
        return -1;
    }
    if !prev.is_null() {
        (*prev).next = (*node).next;
    } else {
        *(*h).htable.add(hvalue) = (*node).next;
    }
    (*h).nel -= 1;
    if !(*node).datum.xperms.is_null() {
        libc::free((*node).datum.xperms as *mut c_void);
    }
    libc::free(node as *mut c_void);
    0
}

// ---- is_redundant ----

unsafe fn is_redundant(node: avtab_ptr_t) -> bool {
    match (*node).key.specified {
        x if x == AVTAB_AUDITDENY => (*node).datum.data == !0u32,
        _ => (*node).datum.data == 0u32,
    }
}

// ---- add_rule_impl ----

unsafe fn add_rule_impl(
    db: *mut policydb,
    src: *mut type_datum_t,
    tgt: *mut type_datum_t,
    cls: *mut class_datum_t,
    perm: *mut perm_datum_t,
    effect: c_int,
    invert: c_int,
) {
    let mut key = avtab_key_t {
        source_type: (*src).s.value as u16,
        target_type: (*tgt).s.value as u16,
        target_class: (*cls).s.value as u16,
        specified: effect as u16,
    };

    let mut node = avtab_search_node(&mut (*db).te_avtab, &mut key);
    if node.is_null() {
        let mut init = avtab_datum_t {
            data: if effect == AVTAB_AUDITDENY as c_int { !0u32 } else { 0u32 },
            xperms: ptr::null_mut(),
        };
        node = avtab_insert_nonunique(&mut (*db).te_avtab, &mut key, &mut init);
        if node.is_null() {
            return;
        }
    }

    if invert != 0 {
        if !perm.is_null() {
            (*node).datum.data &= !(1u32 << ((*perm).s.value - 1));
        } else {
            (*node).datum.data = 0u32;
        }
    } else {
        if !perm.is_null() {
            (*node).datum.data |= 1u32 << ((*perm).s.value - 1);
        } else {
            (*node).datum.data = !0u32;
        }
    }

    if is_redundant(node) {
        xperm_remove_node(&mut (*db).te_avtab, node);
    }
}

// ---- expand_rule ----

unsafe fn expand_rule(
    db: *mut policydb,
    src: *mut type_datum_t,
    tgt: *mut type_datum_t,
    cls: *mut class_datum_t,
    perm: *mut perm_datum_t,
    effect: c_int,
    invert: c_int,
) {
    // strip_av: for AUDITDENY, stripping means adding (invert=false),
    // for others stripping means removing (invert=true)
    let strip_av = (effect == AVTAB_AUDITDENY as c_int) == (invert == 0);

    if src.is_null() {
        let tab = (*db).symtab[SYM_TYPES].table;
        if tab.is_null() {
            return;
        }
        let sz = (*tab).size as usize;
        for i in 0..sz {
            let mut hp = *(*tab).htable.add(i);
            while !hp.is_null() {
                let t = (*hp).datum as *mut type_datum_t;
                if !t.is_null() {
                    if !strip_av && (*t).flavor != TYPE_ATTRIB {
                        hp = (*hp).next;
                        continue;
                    }
                    expand_rule(db, t, tgt, cls, perm, effect, invert);
                }
                hp = (*hp).next;
            }
        }
    } else if tgt.is_null() {
        let tab = (*db).symtab[SYM_TYPES].table;
        if tab.is_null() {
            return;
        }
        let sz = (*tab).size as usize;
        for i in 0..sz {
            let mut hp = *(*tab).htable.add(i);
            while !hp.is_null() {
                let t = (*hp).datum as *mut type_datum_t;
                if !t.is_null() {
                    if !strip_av && (*t).flavor != TYPE_ATTRIB {
                        hp = (*hp).next;
                        continue;
                    }
                    expand_rule(db, src, t, cls, perm, effect, invert);
                }
                hp = (*hp).next;
            }
        }
    } else if cls.is_null() {
        let tab = (*db).symtab[SYM_CLASSES].table;
        if tab.is_null() {
            return;
        }
        let sz = (*tab).size as usize;
        for i in 0..sz {
            let mut hp = *(*tab).htable.add(i);
            while !hp.is_null() {
                let c = (*hp).datum as *mut class_datum_t;
                if !c.is_null() {
                    expand_rule(db, src, tgt, c, perm, effect, invert);
                }
                hp = (*hp).next;
            }
        }
    } else {
        add_rule_impl(db, src, tgt, cls, perm, effect, invert);
    }
}

// ---- add_xperm_rule_impl ----

unsafe fn add_xperm_rule_impl(
    db: *mut policydb,
    src: *mut type_datum_t,
    tgt: *mut type_datum_t,
    cls: *mut class_datum_t,
    low: u16,
    high: u16,
    reset: c_int,
    effect: c_int,
) {
    let mut key = avtab_key_t {
        source_type: (*src).s.value as u16,
        target_type: (*tgt).s.value as u16,
        target_class: (*cls).s.value as u16,
        specified: effect as u16,
    };

    // Collect existing nodes
    let mut node_list: [avtab_ptr_t; 257] = [ptr::null_mut(); 257];
    let mut driver_node: avtab_ptr_t = ptr::null_mut();

    let mut node = avtab_search_node(&mut (*db).te_avtab, &mut key);
    while !node.is_null() {
        if !(*node).datum.xperms.is_null() {
            let xp = (*node).datum.xperms;
            if (*xp).specified == AVTAB_XPERMS_IOCTLDRIVER {
                driver_node = node;
                node_list[256] = node;
            } else if (*xp).specified == AVTAB_XPERMS_IOCTLFUNCTION {
                node_list[(*xp).driver as usize] = node;
            }
        }
        node = avtab_search_node_next(node, effect);
    }

    // Helper functions to avoid closure borrowing issues
    #[inline]
    unsafe fn create_driver_node(db: *mut policydb, key: &mut avtab_key_t) -> avtab_ptr_t {
        let mut avdatum = avtab_datum_t { data: 0, xperms: ptr::null_mut() };
        let n = avtab_insert_nonunique(&mut (*db).te_avtab, key, &mut avdatum);
        if !n.is_null() {
            let xp = libc::calloc(1, mem::size_of::<avtab_extended_perms_t>()) as *mut avtab_extended_perms_t;
            if !xp.is_null() {
                (*xp).specified = AVTAB_XPERMS_IOCTLDRIVER;
                (*xp).driver = 0;
            }
            (*n).datum.xperms = xp;
        }
        n
    }

    #[inline]
    unsafe fn create_func_node(db: *mut policydb, key: &mut avtab_key_t, drv: u8) -> avtab_ptr_t {
        let mut avdatum = avtab_datum_t { data: 0, xperms: ptr::null_mut() };
        let n = avtab_insert_nonunique(&mut (*db).te_avtab, key, &mut avdatum);
        if !n.is_null() {
            let xp = libc::calloc(1, mem::size_of::<avtab_extended_perms_t>()) as *mut avtab_extended_perms_t;
            if !xp.is_null() {
                (*xp).specified = AVTAB_XPERMS_IOCTLFUNCTION;
                (*xp).driver = drv;
            }
            (*n).datum.xperms = xp;
        }
        n
    }

    let ioctl_driver = |x: u16| -> u8 { ((x >> 8) & 0xFF) as u8 };
    let ioctl_func = |x: u16| -> u8 { (x & 0xFF) as u8 };

    if reset != 0 {
        // Remove all existing function nodes
        for i in 0..=0xFFusize {
            if !node_list[i].is_null() {
                xperm_remove_node(&mut (*db).te_avtab, node_list[i]);
                node_list[i] = ptr::null_mut();
            }
        }
        // Zero out driver node perms if exists
        if !driver_node.is_null() && !(*driver_node).datum.xperms.is_null() {
            let xp = (*driver_node).datum.xperms;
            ptr::write_bytes((*xp).perms.as_mut_ptr(), 0, 8);
        }

        // Create driver node if needed, fill all driver bits
        if driver_node.is_null() {
            driver_node = create_driver_node(db, &mut key);
        }
        if driver_node.is_null() || (*driver_node).datum.xperms.is_null() {
            return;
        }

        let xp = (*driver_node).datum.xperms;
        ptr::write_bytes((*xp).perms.as_mut_ptr(), 0xFF, 8);

        let drv_low = ioctl_driver(low) as usize;
        let drv_high = ioctl_driver(high) as usize;

        if drv_low != drv_high {
            // Cross-driver range: clear those driver bits
            for i in drv_low..=drv_high {
                xperm_clear(i, (*xp).perms.as_mut_ptr());
            }
        } else {
            // Same driver: clear that driver bit, create func node with all bits set,
            // then clear the specified function range
            let drv = drv_low;
            xperm_clear(drv, (*xp).perms.as_mut_ptr());

            let mut fnode = node_list[drv];
            if fnode.is_null() {
                fnode = create_func_node(db, &mut key, drv as u8);
                node_list[drv] = fnode;
            }
            if fnode.is_null() || (*fnode).datum.xperms.is_null() {
                return;
            }
            let fxp = (*fnode).datum.xperms;
            ptr::write_bytes((*fxp).perms.as_mut_ptr(), 0xFF, 8);
            let func_low = ioctl_func(low) as usize;
            let func_high = ioctl_func(high) as usize;
            for i in func_low..=func_high {
                xperm_clear(i, (*fxp).perms.as_mut_ptr());
            }
        }
    } else {
        let drv_low = ioctl_driver(low) as usize;
        let drv_high = ioctl_driver(high) as usize;

        if drv_low != drv_high {
            // Cross-driver range: set bits in driver node
            if driver_node.is_null() {
                driver_node = create_driver_node(db, &mut key);
            }
            if driver_node.is_null() || (*driver_node).datum.xperms.is_null() {
                return;
            }
            let xp = (*driver_node).datum.xperms;
            for i in drv_low..=drv_high {
                xperm_set(i, (*xp).perms.as_mut_ptr());
            }
        } else {
            let drv = drv_low;
            let mut fnode = node_list[drv];
            if fnode.is_null() {
                fnode = create_func_node(db, &mut key, drv as u8);
                node_list[drv] = fnode;
            }
            if fnode.is_null() || (*fnode).datum.xperms.is_null() {
                return;
            }
            let fxp = (*fnode).datum.xperms;
            let func_low = ioctl_func(low) as usize;
            let func_high = ioctl_func(high) as usize;
            for i in func_low..=func_high {
                xperm_set(i, (*fxp).perms.as_mut_ptr());
            }
        }
    }
}

// ---- expand_xperm_rule ----

unsafe fn expand_xperm_rule(
    db: *mut policydb,
    src: *mut type_datum_t,
    tgt: *mut type_datum_t,
    cls: *mut class_datum_t,
    low: u16,
    high: u16,
    reset: c_int,
    effect: c_int,
) {
    if src.is_null() {
        let tab = (*db).symtab[SYM_TYPES].table;
        if tab.is_null() {
            return;
        }
        let sz = (*tab).size as usize;
        for i in 0..sz {
            let mut hp = *(*tab).htable.add(i);
            while !hp.is_null() {
                let t = (*hp).datum as *mut type_datum_t;
                if !t.is_null() && (*t).flavor == TYPE_ATTRIB {
                    expand_xperm_rule(db, t, tgt, cls, low, high, reset, effect);
                }
                hp = (*hp).next;
            }
        }
    } else if tgt.is_null() {
        let tab = (*db).symtab[SYM_TYPES].table;
        if tab.is_null() {
            return;
        }
        let sz = (*tab).size as usize;
        for i in 0..sz {
            let mut hp = *(*tab).htable.add(i);
            while !hp.is_null() {
                let t = (*hp).datum as *mut type_datum_t;
                if !t.is_null() && (*t).flavor == TYPE_ATTRIB {
                    expand_xperm_rule(db, src, t, cls, low, high, reset, effect);
                }
                hp = (*hp).next;
            }
        }
    } else if cls.is_null() {
        let tab = (*db).symtab[SYM_CLASSES].table;
        if tab.is_null() {
            return;
        }
        let sz = (*tab).size as usize;
        for i in 0..sz {
            let mut hp = *(*tab).htable.add(i);
            while !hp.is_null() {
                let c = (*hp).datum as *mut class_datum_t;
                if !c.is_null() {
                    add_xperm_rule_impl(db, src, tgt, c, low, high, reset, effect);
                }
                hp = (*hp).next;
            }
        }
    } else {
        add_xperm_rule_impl(db, src, tgt, cls, low, high, reset, effect);
    }
}

// =============================================================================
// Public C-compatible functions (exported via #[no_mangle])
// =============================================================================

#[no_mangle]
pub unsafe extern "C" fn sepol_disable_neverallow(db: *mut policydb) {
    if db.is_null() {
        return;
    }
    let tab = (*db).symtab[SYM_CLASSES].table;
    if tab.is_null() {
        return;
    }
    let sz = (*tab).size as usize;
    for i in 0..sz {
        let mut hp = *(*tab).htable.add(i);
        while !hp.is_null() {
            let cls = (*hp).datum as *mut class_datum_t;
            if !cls.is_null() {
                (*cls).constraints = ptr::null_mut();
            }
            hp = (*hp).next;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sepol_strip_conditional(db: *mut policydb) {
    if db.is_null() || (*db).cond_list.is_null() {
        return;
    }

    let mut n = (*db).cond_list;
    (*db).cond_list = ptr::null_mut();

    while !n.is_null() {
        // cond_node_t is opaque in our binding; we must access its 'next' field
        // The cond_node struct starts with: int cur_state, *expr, *true_list, *false_list,
        // *avtrue_list, *avfalse_list, unsigned nbools, uint32_t bool_ids[5], uint32_t expr_pre_comp,
        // *next, uint32_t flags
        // We call cond_node_destroy which frees the node's internals but NOT the node itself
        // (Looking at libsepol source, cond_node_destroy frees internals and the node struct)
        // The C code calls cond_node_destroy(n) then n = next — so cond_node_destroy frees n
        // We need to get 'next' before calling destroy

        // Since cond_node_t is opaque, we need the offset of 'next'.
        // Layout of cond_node:
        //   int cur_state;                    4 bytes
        //   cond_expr_t *expr;                8 bytes
        //   cond_av_list_t *true_list;        8 bytes
        //   cond_av_list_t *false_list;       8 bytes
        //   avrule_t *avtrue_list;            8 bytes
        //   avrule_t *avfalse_list;           8 bytes
        //   unsigned int nbools;              4 bytes  (+4 padding after cur_state to align)
        //   Actually after int (4), pointer alignment => 4 bytes padding, then 8*5 pointers = 40 + 4+4 = 48
        // Let's compute: int(4)+pad(4)=8, ptr(8)=16, ptr(8)=24, ptr(8)=32, ptr(8)=40, ptr(8)=48
        //   unsigned nbools (4) = 52
        //   uint32_t bool_ids[5] (20) = 72
        //   uint32_t expr_pre_comp (4) = 76
        //   pad(4) = 80
        //   *next (8) = 88
        //   uint32_t flags (4) = 92
        // So next is at offset 80 on 64-bit systems
        let next_ptr = (n as *const u8).add(80) as *const *mut cond_node_t;
        let next = *next_ptr;
        cond_node_destroy(n);
        n = next;
    }
}

#[no_mangle]
pub unsafe extern "C" fn sepol_preserve_policycaps(dst: *mut policydb, src: *mut policydb) {
    if dst.is_null() || src.is_null() {
        return;
    }

    ebitmap_destroy(&mut (*dst).policycaps);
    // ebitmap_init is a static inline function in libsepol, just zero the struct
    ptr::write_bytes(&mut (*dst).policycaps, 0, 1);

    let highbit = (*src).policycaps.highbit;
    let mut i = 0u32;
    while i <= highbit {
        if ebitmap_get_bit(&(*src).policycaps, i) != 0 {
            ebitmap_set_bit(&mut (*dst).policycaps, i, 1);
        }
        i += 1;
    }
}

#[no_mangle]
pub unsafe extern "C" fn sepol_get_android_flags(db: *mut policydb) -> u32 {
    if db.is_null() {
        return 0;
    }
    (*db).android_extra
}

#[no_mangle]
pub unsafe extern "C" fn sepol_set_android_flags(db: *mut policydb, flags: u32) {
    if db.is_null() {
        return;
    }
    (*db).android_extra = flags;
}

#[no_mangle]
pub unsafe extern "C" fn sepol_reindex_full(db: *mut policydb) -> c_int {
    if db.is_null() {
        return -1;
    }
    if policydb_index_decls(ptr::null_mut(), db) != 0 {
        return -1;
    }
    if policydb_index_classes(db) != 0 {
        return -1;
    }
    if policydb_index_others(ptr::null_mut(), db, 0) != 0 {
        return -1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn sepol_db_new() -> *mut policydb {
    let db = libc::calloc(1, mem::size_of::<policydb>()) as *mut policydb;
    if db.is_null() {
        return ptr::null_mut();
    }
    if policydb_init(db) != 0 {
        libc::free(db as *mut c_void);
        return ptr::null_mut();
    }
    db
}

#[no_mangle]
pub unsafe extern "C" fn sepol_db_free(db: *mut policydb) {
    if !db.is_null() {
        policydb_destroy(db);
        libc::free(db as *mut c_void);
    }
}

#[no_mangle]
pub unsafe extern "C" fn sepol_db_from_file(path: *const c_char) -> *mut policydb {
    if path.is_null() {
        return ptr::null_mut();
    }

    let db = sepol_db_new();
    if db.is_null() {
        return ptr::null_mut();
    }

    let fp = libc::fopen(path, b"rb\0".as_ptr() as *const c_char);
    if fp.is_null() {
        sepol_db_free(db);
        return ptr::null_mut();
    }

    let mut pf: policy_file = mem::zeroed();
    policy_file_init(&mut pf);
    pf.fp = fp;
    pf.type_ = PF_USE_STDIO;

    if policydb_read(db, &mut pf, 0) != 0 {
        libc::fclose(fp);
        sepol_db_free(db);
        return ptr::null_mut();
    }
    libc::fclose(fp);
    db
}

#[no_mangle]
pub unsafe extern "C" fn sepol_db_from_data(data: *const u8, len: usize) -> *mut policydb {
    if data.is_null() || len == 0 {
        return ptr::null_mut();
    }

    let db = sepol_db_new();
    if db.is_null() {
        return ptr::null_mut();
    }

    let mut pf: policy_file = mem::zeroed();
    policy_file_init(&mut pf);
    pf.data = data as *mut c_char;
    pf.len = len;
    pf.type_ = PF_USE_MEMORY;

    if policydb_read(db, &mut pf, 0) != 0 {
        sepol_db_free(db);
        return ptr::null_mut();
    }
    db
}

#[no_mangle]
pub unsafe extern "C" fn sepol_db_to_file(db: *mut policydb, path: *const c_char) -> c_int {
    if db.is_null() || path.is_null() {
        return -1;
    }

    let mut data: *mut c_char = ptr::null_mut();
    let mut size: usize = 0;

    // Use open_memstream on Linux, funopen on Android/BSD
    #[cfg(any(target_os = "android", target_os = "freebsd", target_os = "openbsd"))]
    let (fp, buf_cookie) = {
        // funopen is not in libc crate for Android, declare it manually
        extern "C" {
            fn funopen(
                cookie: *mut c_void,
                readfn: Option<unsafe extern "C" fn(*mut c_void, *mut c_char, c_int) -> c_int>,
                writefn: Option<unsafe extern "C" fn(*mut c_void, *const c_char, c_int) -> c_int>,
                seekfn: Option<unsafe extern "C" fn(*mut c_void, i64, c_int) -> i64>,
                closefn: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
            ) -> *mut libc::FILE;
        }

        struct BufState {
            data: Vec<u8>,
        }
        unsafe extern "C" fn buf_write(
            cookie: *mut c_void,
            buf: *const c_char,
            len: c_int,
        ) -> c_int {
            let state = &mut *(cookie as *mut BufState);
            let slice = slice::from_raw_parts(buf as *const u8, len as usize);
            state.data.extend_from_slice(slice);
            len
        }
        let state = Box::new(BufState { data: Vec::new() });
        let cookie = Box::into_raw(state) as *mut c_void;
        let fp = funopen(cookie, None, Some(buf_write), None, None);
        (fp, Some(cookie))
    };

    #[cfg(not(any(target_os = "android", target_os = "freebsd", target_os = "openbsd")))]
    let (fp, buf_cookie) = {
        let fp = libc::open_memstream(&mut data, &mut size);
        (fp, None::<*mut c_void>)
    };

    if fp.is_null() {
        return -1;
    }

    libc::setbuf(fp, ptr::null_mut());

    let mut pf: policy_file = mem::zeroed();
    policy_file_init(&mut pf);
    pf.fp = fp;
    pf.type_ = PF_USE_STDIO;

    let ret = policydb_write(db, &mut pf);
    libc::fclose(fp);

    // Retrieve buffer
    #[cfg(any(target_os = "android", target_os = "freebsd", target_os = "openbsd"))]
    let (final_data, final_size) = {
        if let Some(cookie) = buf_cookie {
            struct BufState { data: Vec<u8> }
            let state = Box::from_raw(cookie as *mut BufState);
            let mut v = state.data;
            let ptr = v.as_mut_ptr() as *mut c_char;
            let len = v.len();
            std::mem::forget(v);
            (ptr, len)
        } else {
            (ptr::null_mut(), 0usize)
        }
    };

    #[cfg(not(any(target_os = "android", target_os = "freebsd", target_os = "openbsd")))]
    let (final_data, final_size) = (data, size);

    if ret != 0 {
        if !final_data.is_null() {
            libc::free(final_data as *mut c_void);
        }
        return -1;
    }

    // Open file for writing
    let fd = libc::open(
        path,
        libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC,
        0o644i32,
    );
    if fd < 0 {
        if !final_data.is_null() {
            libc::free(final_data as *mut c_void);
        }
        return -1;
    }

    // Truncate if file already has content
    let mut st: libc::stat = mem::zeroed();
    if libc::fstat(fd, &mut st) == 0 && st.st_size > 0 {
        libc::ftruncate(fd, 0);
    }

    // Write all at once (required for /sys/fs/selinux/load)
    let written = libc::write(fd, final_data as *const c_void, final_size);
    libc::close(fd);

    if !final_data.is_null() {
        libc::free(final_data as *mut c_void);
    }

    if written < 0 || written as usize != final_size {
        return -1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn sepol_print_types(db: *mut policydb, attributes: c_int) {
    if db.is_null() {
        return;
    }

    let nprim = (*db).symtab[SYM_TYPES].nprim as usize;
    for i in 0..nprim {
        let type_ptr = *(*db).type_val_to_struct.add(i);
        if type_ptr.is_null() {
            continue;
        }
        let name_ptr = *(*db).sym_val_to_name[SYM_TYPES].add(i);
        if name_ptr.is_null() {
            continue;
        }
        let name = CStr::from_ptr(name_ptr).to_string_lossy();

        if attributes != 0 && (*type_ptr).flavor == TYPE_ATTRIB {
            println!("attribute {}", name);
        } else if attributes == 0 && (*type_ptr).flavor == TYPE_TYPE {
            // Print type with attributes
            let bitmap = &(*db).type_attr_map.add(i);
            let highbit = (**bitmap).highbit;
            let mut first = true;
            let mut j = 0u32;
            while j <= highbit {
                if ebitmap_get_bit(*bitmap, j) != 0 {
                    let attr_type = *(*db).type_val_to_struct.add(j as usize);
                    if !attr_type.is_null() && (*attr_type).flavor == TYPE_ATTRIB {
                        let attr_name_ptr = *(*db).sym_val_to_name[SYM_TYPES].add(j as usize);
                        if !attr_name_ptr.is_null() {
                            let attr_name = CStr::from_ptr(attr_name_ptr).to_string_lossy();
                            if first {
                                print!("type {} {{", name);
                                first = false;
                            }
                            print!(" {}", attr_name);
                        }
                    }
                }
                j += 1;
            }
            if !first {
                println!(" }}");
            }
            // Print permissive
            if ebitmap_get_bit(&(*db).permissive_map, (*type_ptr).s.value) != 0 {
                println!("permissive {}", name);
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sepol_print_avtab_rules(db: *mut policydb) {
    if db.is_null() {
        return;
    }

    let nslot = (*db).te_avtab.nslot as usize;
    for i in 0..nslot {
        let mut node = *(*db).te_avtab.htable.add(i);
        while !node.is_null() {
            let src_idx = (*node).key.source_type as usize;
            let tgt_idx = (*node).key.target_type as usize;
            let cls_idx = (*node).key.target_class as usize;

            if src_idx == 0 || tgt_idx == 0 || cls_idx == 0 {
                node = (*node).next;
                continue;
            }

            let src_ptr = *(*db).sym_val_to_name[SYM_TYPES].add(src_idx - 1);
            let tgt_ptr = *(*db).sym_val_to_name[SYM_TYPES].add(tgt_idx - 1);
            let cls_ptr = *(*db).sym_val_to_name[SYM_CLASSES].add(cls_idx - 1);

            if src_ptr.is_null() || tgt_ptr.is_null() || cls_ptr.is_null() {
                node = (*node).next;
                continue;
            }

            let src = CStr::from_ptr(src_ptr).to_string_lossy();
            let tgt = CStr::from_ptr(tgt_ptr).to_string_lossy();
            let cls = CStr::from_ptr(cls_ptr).to_string_lossy();

            let specified = (*node).key.specified;

            if (specified & AVTAB_AV) != 0 {
                let mut data = (*node).datum.data;
                let rule_name = match specified {
                    x if x == AVTAB_ALLOWED => "allow",
                    x if x == AVTAB_AUDITALLOW => "auditallow",
                    x if x == AVTAB_AUDITDENY => {
                        data = !data;
                        "dontaudit"
                    }
                    _ => {
                        node = (*node).next;
                        continue;
                    }
                };

                let clz = *(*db).class_val_to_struct.add(cls_idx - 1);
                if clz.is_null() {
                    node = (*node).next;
                    continue;
                }

                // Build value->name lookup for permissions
                let mut perm_names: [*const c_char; 32] = [ptr::null(); 32];

                // Class-specific permissions
                let ctab = (*clz).permissions.table;
                if !ctab.is_null() {
                    let csz = (*ctab).size as usize;
                    for b in 0..csz {
                        let mut hp = *(*ctab).htable.add(b);
                        while !hp.is_null() {
                            let pd = (*hp).datum as *mut perm_datum_t;
                            if !pd.is_null() {
                                let v = (*pd).s.value as usize;
                                if v >= 1 && v <= 32 {
                                    perm_names[v - 1] = (*hp).key;
                                }
                            }
                            hp = (*hp).next;
                        }
                    }
                }

                // Common permissions
                let comdatum = (*clz).comdatum;
                if !comdatum.is_null() {
                    let comtab = (*comdatum).permissions.table;
                    if !comtab.is_null() {
                        let csz = (*comtab).size as usize;
                        for b in 0..csz {
                            let mut hp = *(*comtab).htable.add(b);
                            while !hp.is_null() {
                                let pd = (*hp).datum as *mut perm_datum_t;
                                if !pd.is_null() {
                                    let v = (*pd).s.value as usize;
                                    if v >= 1 && v <= 32 && perm_names[v - 1].is_null() {
                                        perm_names[v - 1] = (*hp).key;
                                    }
                                }
                                hp = (*hp).next;
                            }
                        }
                    }
                }

                let mut first = true;
                for bit in 0..32usize {
                    if (data & (1u32 << bit)) != 0 && !perm_names[bit].is_null() {
                        let pname = CStr::from_ptr(perm_names[bit]).to_string_lossy();
                        if first {
                            print!("{} {} {} {} {{", rule_name, src, tgt, cls);
                            first = false;
                        }
                        print!(" {}", pname);
                    }
                }
                if !first {
                    println!(" }}");
                }
            } else if (specified & AVTAB_TYPE) != 0 {
                let rule_name = match specified {
                    x if x == AVTAB_TRANSITION => "type_transition",
                    x if x == AVTAB_MEMBER => "type_member",
                    x if x == AVTAB_CHANGE => "type_change",
                    _ => {
                        node = (*node).next;
                        continue;
                    }
                };
                let def_idx = (*node).datum.data as usize;
                if def_idx == 0 {
                    node = (*node).next;
                    continue;
                }
                let def_ptr = *(*db).sym_val_to_name[SYM_TYPES].add(def_idx - 1);
                if !def_ptr.is_null() {
                    let def = CStr::from_ptr(def_ptr).to_string_lossy();
                    println!("{} {} {} {} {}", rule_name, src, tgt, cls, def);
                }
            } else if (specified & AVTAB_XPERMS) != 0 {
                let rule_name = match specified {
                    x if x == AVTAB_XPERMS_ALLOWED => "allowxperm",
                    x if x == AVTAB_XPERMS_AUDITALLOW => "auditallowxperm",
                    x if x == AVTAB_XPERMS_DONTAUDIT => "dontauditxperm",
                    _ => {
                        node = (*node).next;
                        continue;
                    }
                };

                let xperms = (*node).datum.xperms;
                if xperms.is_null() {
                    node = (*node).next;
                    continue;
                }

                print!("{} {} {} {} ioctl {{", rule_name, src, tgt, cls);

                let mut low: i32 = -1;
                for xi in 0..256usize {
                    if xperm_test(xi, (*xperms).perms.as_ptr()) {
                        if low < 0 {
                            low = xi as i32;
                        }
                        if xi == 255 {
                            let v = if (*xperms).specified == AVTAB_XPERMS_IOCTLFUNCTION {
                                ((((*xperms).driver as u16) << 8) | xi as u16)
                            } else {
                                (xi as u16) << 8
                            };
                            if low as usize == 255 {
                                print!(" 0x{:04X}", v);
                            } else {
                                let vlow = if (*xperms).specified == AVTAB_XPERMS_IOCTLFUNCTION {
                                    ((((*xperms).driver as u16) << 8) | low as u16)
                                } else {
                                    (low as u16) << 8
                                };
                                print!(" 0x{:04X}-0x{:04X}", vlow, v);
                            }
                        }
                    } else if low >= 0 {
                        let vlow = if (*xperms).specified == AVTAB_XPERMS_IOCTLFUNCTION {
                            ((((*xperms).driver as u16) << 8) | low as u16)
                        } else {
                            (low as u16) << 8
                        };
                        let vhigh = if (*xperms).specified == AVTAB_XPERMS_IOCTLFUNCTION {
                            ((((*xperms).driver as u16) << 8) | (xi as u16 - 1))
                        } else {
                            ((xi as u16) - 1) << 8
                        };
                        if low as usize == xi - 1 {
                            print!(" 0x{:04X}", vlow);
                        } else {
                            print!(" 0x{:04X}-0x{:04X}", vlow, vhigh);
                        }
                        low = -1;
                    }
                }
                println!(" }}");
            }

            node = (*node).next;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sepol_print_filename_trans(db: *mut policydb) {
    if db.is_null() || (*db).filename_trans.is_null() {
        return;
    }

    let tab = (*db).filename_trans;
    let sz = (*tab).size as usize;
    for i in 0..sz {
        let mut node = *(*tab).htable.add(i);
        while !node.is_null() {
            let key = (*node).key as *mut filename_trans_key_t;
            let mut trans = (*node).datum as *mut filename_trans_datum_t;

            if key.is_null() || trans.is_null() {
                node = (*node).next;
                continue;
            }

            let ttype = (*key).ttype as usize;
            let tclass = (*key).tclass as usize;

            if ttype == 0 || tclass == 0 {
                node = (*node).next;
                continue;
            }

            let tgt_ptr = *(*db).sym_val_to_name[SYM_TYPES].add(ttype - 1);
            let cls_ptr = *(*db).sym_val_to_name[SYM_CLASSES].add(tclass - 1);
            let name_cstr = (*key).name;

            if tgt_ptr.is_null() || cls_ptr.is_null() || name_cstr.is_null() {
                node = (*node).next;
                continue;
            }

            let tgt = CStr::from_ptr(tgt_ptr).to_string_lossy();
            let cls = CStr::from_ptr(cls_ptr).to_string_lossy();
            let oname = CStr::from_ptr(name_cstr).to_string_lossy();

            while !trans.is_null() {
                let otype = (*trans).otype as usize;
                if otype == 0 {
                    trans = (*trans).next;
                    continue;
                }
                let def_ptr = *(*db).sym_val_to_name[SYM_TYPES].add(otype - 1);
                if def_ptr.is_null() {
                    trans = (*trans).next;
                    continue;
                }
                let def = CStr::from_ptr(def_ptr).to_string_lossy();

                let highbit = (*trans).stypes.highbit;
                let mut k = 0u32;
                while k <= highbit {
                    if ebitmap_get_bit(&(*trans).stypes, k) != 0 {
                        let src_ptr = *(*db).sym_val_to_name[SYM_TYPES].add(k as usize);
                        if !src_ptr.is_null() {
                            let src = CStr::from_ptr(src_ptr).to_string_lossy();
                            println!(
                                "type_transition {} {} {} {} {}",
                                src, tgt, cls, def, oname
                            );
                        }
                    }
                    k += 1;
                }
                trans = (*trans).next;
            }

            node = (*node).next;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sepol_print_genfscon(db: *mut policydb) {
    if db.is_null() {
        return;
    }

    let mut genfs = (*db).genfs;
    while !genfs.is_null() {
        let fstype_cstr = (*genfs).fstype;
        let fstype = if !fstype_cstr.is_null() {
            CStr::from_ptr(fstype_cstr).to_string_lossy().into_owned()
        } else {
            genfs = (*genfs).next;
            continue;
        };

        let mut ocon = (*genfs).head;
        while !ocon.is_null() {
            // u.name is the first field of the union, so it's the pointer itself
            let name_ptr = (*ocon).u_name();
            if !name_ptr.is_null() {
                let path = CStr::from_ptr(name_ptr).to_string_lossy();
                let ctx_str = context_to_str(db, &mut (*ocon).context[0]);
                if !ctx_str.is_null() {
                    let ctx = CStr::from_ptr(ctx_str).to_string_lossy();
                    println!("genfscon {} {} {}", fstype, path, ctx);
                    libc::free(ctx_str as *mut c_void);
                }
            }
            ocon = (*ocon).next;
        }
        genfs = (*genfs).next;
    }
}

#[no_mangle]
pub unsafe extern "C" fn sepol_add_rule(
    db: *mut policydb,
    s: *const c_char,
    t: *const c_char,
    c: *const c_char,
    p: *const c_char,
    effect: c_int,
    invert: c_int,
) -> c_int {
    if db.is_null() {
        return -1;
    }

    let src = if !s.is_null() && *s != 0 { find_type(db, s) } else { ptr::null_mut() };
    let tgt = if !t.is_null() && *t != 0 { find_type(db, t) } else { ptr::null_mut() };
    let cls = if !c.is_null() && *c != 0 { find_class(db, c) } else { ptr::null_mut() };
    let perm = if !p.is_null() && *p != 0 && !cls.is_null() {
        find_perm(cls, p)
    } else {
        ptr::null_mut()
    };

    // Validate: if name provided but not found, error
    if (!s.is_null() && *s != 0 && src.is_null())
        || (!t.is_null() && *t != 0 && tgt.is_null())
        || (!c.is_null() && *c != 0 && cls.is_null())
        || (!p.is_null() && *p != 0 && perm.is_null())
    {
        return -1;
    }

    expand_rule(db, src, tgt, cls, perm, effect, invert);
    0
}

#[no_mangle]
pub unsafe extern "C" fn sepol_add_xperm_rule(
    db: *mut policydb,
    s: *const c_char,
    t: *const c_char,
    c: *const c_char,
    low: u16,
    high: u16,
    reset: c_int,
    effect: c_int,
) -> c_int {
    if db.is_null() {
        return -1;
    }

    if (*db).policyvers < POLICYDB_VERSION_XPERMS_IOCTL {
        eprintln!(
            "policy version {} does not support ioctl xperms rules",
            (*db).policyvers
        );
        return -1;
    }

    let src = if !s.is_null() && *s != 0 { find_type(db, s) } else { ptr::null_mut() };
    let tgt = if !t.is_null() && *t != 0 { find_type(db, t) } else { ptr::null_mut() };
    let cls = if !c.is_null() && *c != 0 { find_class(db, c) } else { ptr::null_mut() };

    if (!s.is_null() && *s != 0 && src.is_null())
        || (!t.is_null() && *t != 0 && tgt.is_null())
        || (!c.is_null() && *c != 0 && cls.is_null())
    {
        return -1;
    }

    expand_xperm_rule(db, src, tgt, cls, low, high, reset, effect);
    0
}

#[no_mangle]
pub unsafe extern "C" fn sepol_add_type_rule(
    db: *mut policydb,
    s: *const c_char,
    t: *const c_char,
    c: *const c_char,
    d: *const c_char,
    effect: c_int,
) -> c_int {
    if db.is_null() || s.is_null() || t.is_null() || c.is_null() || d.is_null() {
        return -1;
    }

    let src = find_type(db, s);
    let tgt = find_type(db, t);
    let cls = find_class(db, c);
    let def = find_type(db, d);

    if src.is_null() || tgt.is_null() || cls.is_null() || def.is_null() {
        return -1;
    }

    let mut key = avtab_key_t {
        source_type: (*src).s.value as u16,
        target_type: (*tgt).s.value as u16,
        target_class: (*cls).s.value as u16,
        specified: effect as u16,
    };

    let mut datum = avtab_datum_t {
        data: (*def).s.value,
        xperms: ptr::null_mut(),
    };

    avtab_insert(&mut (*db).te_avtab, &mut key, &mut datum)
}

#[no_mangle]
pub unsafe extern "C" fn sepol_add_filename_trans(
    db: *mut policydb,
    s: *const c_char,
    t: *const c_char,
    c: *const c_char,
    d: *const c_char,
    o: *const c_char,
) -> c_int {
    if db.is_null() || s.is_null() || t.is_null() || c.is_null() || d.is_null() || o.is_null() {
        return -1;
    }

    let src = find_type(db, s);
    if src.is_null() {
        eprintln!(
            "filename_trans: source type {} does not exist",
            CStr::from_ptr(s).to_string_lossy()
        );
        return -1;
    }
    let tgt = find_type(db, t);
    if tgt.is_null() {
        eprintln!(
            "filename_trans: target type {} does not exist",
            CStr::from_ptr(t).to_string_lossy()
        );
        return -1;
    }
    let cls = find_class(db, c);
    if cls.is_null() {
        eprintln!(
            "filename_trans: class {} does not exist",
            CStr::from_ptr(c).to_string_lossy()
        );
        return -1;
    }
    let def = find_type(db, d);
    if def.is_null() {
        eprintln!(
            "filename_trans: default type {} does not exist",
            CStr::from_ptr(d).to_string_lossy()
        );
        return -1;
    }

    // Build stack key for lookup
    let mut key = filename_trans_key_t {
        ttype: (*tgt).s.value,
        tclass: (*cls).s.value,
        name: o as *mut c_char,
    };

    // Walk existing chain for this key
    let mut trans =
        hashtab_search((*db).filename_trans, &mut key as *mut _ as *const c_char)
            as *mut filename_trans_datum_t;
    let mut last: *mut filename_trans_datum_t = ptr::null_mut();

    while !trans.is_null() {
        if ebitmap_get_bit(&(*trans).stypes, (*src).s.value - 1) != 0 {
            // Duplicate — just update otype
            (*trans).otype = (*def).s.value;
            return 0;
        }
        if (*trans).otype == (*def).s.value {
            break; // reuse this node
        }
        last = trans;
        trans = (*trans).next;
    }

    if trans.is_null() {
        // New datum
        trans = libc::calloc(1, mem::size_of::<filename_trans_datum_t>())
            as *mut filename_trans_datum_t;
        if trans.is_null() {
            return -1;
        }
        // ebitmap_init is a static inline function in libsepol, just zero the struct
        ptr::write_bytes(&mut (*trans).stypes, 0, 1);
        (*trans).otype = (*def).s.value;
    }

    if !last.is_null() {
        // Append to existing chain
        (*last).next = trans;
    } else {
        // First entry for this key — allocate permanent key and insert
        let new_key =
            libc::malloc(mem::size_of::<filename_trans_key_t>()) as *mut filename_trans_key_t;
        if new_key.is_null() {
            libc::free(trans as *mut c_void);
            return -1;
        }
        (*new_key).ttype = key.ttype;
        (*new_key).tclass = key.tclass;
        (*new_key).name = dup_str(o);
        if (*new_key).name.is_null() {
            libc::free(new_key as *mut c_void);
            libc::free(trans as *mut c_void);
            return -1;
        }
        if hashtab_insert(
            (*db).filename_trans,
            new_key as *mut _ as *mut c_char,
            trans as *mut c_void,
        ) != 0
        {
            libc::free((*new_key).name as *mut c_void);
            libc::free(new_key as *mut c_void);
            libc::free(trans as *mut c_void);
            return -1;
        }
    }

    (*db).filename_trans_count += 1;
    if ebitmap_set_bit(&mut (*trans).stypes, (*src).s.value - 1, 1) == 0 {
        0
    } else {
        -1
    }
}

#[no_mangle]
pub unsafe extern "C" fn sepol_add_genfscon(
    db: *mut policydb,
    fs: *const c_char,
    path: *const c_char,
    ctx: *const c_char,
) -> c_int {
    if db.is_null() || fs.is_null() || path.is_null() || ctx.is_null() {
        return -1;
    }

    // Parse context string
    let ctx_len = libc::strlen(ctx);
    let mut new_ctx: *mut context_struct_t = ptr::null_mut();
    if context_from_string(ptr::null_mut(), db, &mut new_ctx, ctx, ctx_len) != 0 {
        eprintln!(
            "genfscon: failed to parse context '{}'",
            CStr::from_ptr(ctx).to_string_lossy()
        );
        return -1;
    }

    // Find or create genfs node
    let mut genfs = (*db).genfs;
    while !genfs.is_null() {
        if libc::strcmp((*genfs).fstype, fs) == 0 {
            break;
        }
        genfs = (*genfs).next;
    }
    if genfs.is_null() {
        genfs = libc::calloc(1, mem::size_of::<genfs_t>()) as *mut genfs_t;
        if genfs.is_null() {
            libc::free(new_ctx as *mut c_void);
            return -1;
        }
        (*genfs).fstype = dup_str(fs);
        if (*genfs).fstype.is_null() {
            libc::free(genfs as *mut c_void);
            libc::free(new_ctx as *mut c_void);
            return -1;
        }
        (*genfs).next = (*db).genfs;
        (*db).genfs = genfs;
    }

    // Find or create ocontext node
    let mut ocon = (*genfs).head;
    while !ocon.is_null() {
        let n = (*ocon).u_name();
        if !n.is_null() && libc::strcmp(n, path) == 0 {
            break;
        }
        ocon = (*ocon).next;
    }
    if ocon.is_null() {
        ocon = libc::calloc(1, mem::size_of::<ocontext_t>()) as *mut ocontext_t;
        if ocon.is_null() {
            libc::free(new_ctx as *mut c_void);
            return -1;
        }
        let name_slot = (*ocon).u_name_mut();
        *name_slot = dup_str(path);
        if (*name_slot).is_null() {
            libc::free(ocon as *mut c_void);
            libc::free(new_ctx as *mut c_void);
            return -1;
        }
        (*ocon).next = (*genfs).head;
        (*genfs).head = ocon;
    }

    if (*ocon).context[0].user != 0 {
        // context_destroy is a static inline function: zero user/role/type and destroy MLS range
        // mls_range_destroy calls mls_level_destroy on both levels
        // mls_level_destroy calls ebitmap_destroy and zeros the level
        (*ocon).context[0].user = 0;
        (*ocon).context[0].role = 0;
        (*ocon).context[0].type_ = 0;
        ebitmap_destroy(&mut (*ocon).context[0].range.level[0].cat);
        ptr::write_bytes(&mut (*ocon).context[0].range.level[0], 0, 1);
        ebitmap_destroy(&mut (*ocon).context[0].range.level[1].cat);
        ptr::write_bytes(&mut (*ocon).context[0].range.level[1], 0, 1);
    }
    ptr::copy_nonoverlapping(new_ctx, &mut (*ocon).context[0], 1);
    libc::free(new_ctx as *mut c_void);
    0
}

#[no_mangle]
pub unsafe extern "C" fn sepol_add_type(
    db: *mut policydb,
    name: *const c_char,
    flavor: u32,
) -> c_int {
    if db.is_null() || name.is_null() {
        return -1;
    }

    // Check if already exists
    let existing = hashtab_search((*db).symtab[SYM_TYPES].table, name) as *mut type_datum_t;
    if !existing.is_null() {
        return 0; // already exists — not an error
    }

    let type_datum =
        libc::calloc(1, mem::size_of::<type_datum_t>()) as *mut type_datum_t;
    if type_datum.is_null() {
        return -1;
    }

    type_datum_init(type_datum);
    (*type_datum).primary = 1;
    (*type_datum).flavor = flavor;

    let name_copy = dup_str(name);
    if name_copy.is_null() {
        libc::free(type_datum as *mut c_void);
        return -1;
    }

    let mut value: u32 = 0;
    if symtab_insert(
        db,
        SYM_TYPES as u32,
        name_copy,
        type_datum as *mut c_void,
        SCOPE_DECL,
        1,
        &mut value,
    ) != 0
    {
        libc::free(name_copy as *mut c_void);
        libc::free(type_datum as *mut c_void);
        return -1;
    }
    (*type_datum).s.value = value;

    // For modular policies, set scope in declared.p_types_scope
    // avrule_decl_t layout (64-bit):
    //   offset 0:   uint32_t decl_id
    //   offset 4:   uint32_t enabled
    //   offset 8:   *cond_list
    //   offset 16:  *avrules
    //   offset 24:  *role_tr_rules
    //   offset 32:  *role_allow_rules
    //   offset 40:  *range_tr_rules
    //   offset 48:  scope_index_t required
    //               = [ebitmap_t;8](128) + *ebitmap_t(8) + u32(4) + pad(4) = 144 bytes
    //   offset 192: scope_index_t declared
    //               declared.scope[SYM_TYPES=3] = offset 192 + 3*16 = 240
    if !(*db).global.is_null() && !(*(*db).global).branch_list.is_null() {
        let branch = (*(*db).global).branch_list as *mut u8;
        // ebitmap_t size = pointer(8) + u32(4) + pad(4) = 16 bytes on 64-bit
        const EBITMAP_SIZE: usize = 16;
        const SCOPE_INDEX_SIZE: usize = SYM_NUM * EBITMAP_SIZE + 8 + 4 + 4; // 144
        // avrule_decl fields before required:
        // 2*u32 + 5 pointers = 8 + 40 = 48
        const REQUIRED_OFFSET: usize = 8 + 5 * 8; // 48
        const DECLARED_OFFSET: usize = REQUIRED_OFFSET + SCOPE_INDEX_SIZE; // 192
        const P_TYPES_SCOPE_OFFSET: usize = DECLARED_OFFSET + SYM_TYPES * EBITMAP_SIZE; // 240
        let scope_bitmap = branch.add(P_TYPES_SCOPE_OFFSET) as *mut ebitmap_t;
        ebitmap_set_bit(scope_bitmap, value - 1, 1);
    }

    // Resize type_attr_map and attr_type_map
    let new_size = mem::size_of::<ebitmap_t>() * (*db).symtab[SYM_TYPES].nprim as usize;
    let new_type_attr_map =
        libc::realloc((*db).type_attr_map as *mut c_void, new_size) as *mut ebitmap_t;
    let new_attr_type_map =
        libc::realloc((*db).attr_type_map as *mut c_void, new_size) as *mut ebitmap_t;

    if new_type_attr_map.is_null() || new_attr_type_map.is_null() {
        return -1;
    }
    (*db).type_attr_map = new_type_attr_map;
    (*db).attr_type_map = new_attr_type_map;

    // ebitmap_init is a static inline function in libsepol, just zero the struct
    ptr::write_bytes(&mut *(*db).type_attr_map.add(value as usize - 1), 0, 1);
    ptr::write_bytes(&mut *(*db).attr_type_map.add(value as usize - 1), 0, 1);
    ebitmap_set_bit(
        &mut *(*db).type_attr_map.add(value as usize - 1),
        value - 1,
        1,
    );

    // Re-index
    if policydb_index_decls(ptr::null_mut(), db) != 0
        || policydb_index_classes(db) != 0
        || policydb_index_others(ptr::null_mut(), db, 0) != 0
    {
        return -1;
    }

    // Add type to all roles
    let nroles = (*db).symtab[SYM_ROLES].nprim as usize;
    for i in 0..nroles {
        let role = *(*db).role_val_to_struct.add(i);
        if role.is_null() {
            continue;
        }
        ebitmap_set_bit(&mut (*role).types.negset, value - 1, 0);
        ebitmap_set_bit(&mut (*role).types.types, value - 1, 1);
        type_set_expand(&mut (*role).types, &mut (*role).cache, db, 0);
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn sepol_set_type_state(
    db: *mut policydb,
    name: *const c_char,
    permissive: c_int,
) -> c_int {
    if db.is_null() {
        return -1;
    }

    if !name.is_null() && *name != 0 {
        let type_datum = find_type(db, name);
        if type_datum.is_null() {
            return -1;
        }
        ebitmap_set_bit(&mut (*db).permissive_map, (*type_datum).s.value, permissive)
    } else {
        // Set all types
        let nprim = (*db).symtab[SYM_TYPES].nprim;
        let mut i = 0u32;
        while i < nprim {
            ebitmap_set_bit(&mut (*db).permissive_map, i + 1, permissive);
            i += 1;
        }
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn sepol_add_typeattribute(
    db: *mut policydb,
    type_name: *const c_char,
    attr_name: *const c_char,
) -> c_int {
    if db.is_null() || type_name.is_null() || attr_name.is_null() {
        return -1;
    }

    let type_datum = find_type(db, type_name);
    if type_datum.is_null() || (*type_datum).flavor == TYPE_ATTRIB {
        return -1;
    }

    let attr_datum = find_type(db, attr_name);
    if attr_datum.is_null() || (*attr_datum).flavor != TYPE_ATTRIB {
        return -1;
    }

    let type_val = (*type_datum).s.value as usize;
    let attr_val = (*attr_datum).s.value as usize;

    ebitmap_set_bit(
        &mut *(*db).type_attr_map.add(type_val - 1),
        attr_val as u32 - 1,
        1,
    );
    ebitmap_set_bit(
        &mut *(*db).attr_type_map.add(attr_val - 1),
        type_val as u32 - 1,
        1,
    );

    // Expand constraint expressions
    let tab = (*db).symtab[SYM_CLASSES].table;
    if !tab.is_null() {
        let sz = (*tab).size as usize;
        for i in 0..sz {
            let mut hp = *(*tab).htable.add(i);
            while !hp.is_null() {
                let cls = (*hp).datum as *mut class_datum_t;
                if !cls.is_null() {
                    let mut cn = (*cls).constraints;
                    while !cn.is_null() {
                        let mut e = (*cn).expr;
                        while !e.is_null() {
                            if (*e).expr_type == CEXPR_NAMES
                                && !(*e).type_names.is_null()
                                && ebitmap_get_bit(
                                    &(*(*e).type_names).types,
                                    attr_val as u32 - 1,
                                ) != 0
                            {
                                ebitmap_set_bit(
                                    &mut (*e).names,
                                    type_val as u32 - 1,
                                    1,
                                );
                            }
                            e = (*e).next;
                        }
                        cn = (*cn).next;
                    }
                }
                hp = (*hp).next;
            }
        }
    }

    0
}
