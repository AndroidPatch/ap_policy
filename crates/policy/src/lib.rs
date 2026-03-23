//! SELinux Policy Manipulation Library
//!
//! This library provides functionality to parse, modify, and apply SELinux policies.
//! It can use libsepol for full policy binary format support when available.

use std::ffi::CString;
use std::fmt;
use std::io;
use std::path::Path;

#[cfg(feature = "sepol_linked")]
mod sepol;
pub mod rules;
pub mod statement;

#[cfg(feature = "sepol_stub")]
mod stub;

pub use statement::format_statement_help;
pub use rules::{SEPOL_FILE_TYPE, SEPOL_LOG_TYPE, SEPOL_PROC_DOMAIN};

#[cfg(feature = "sepol_linked")]
use sepol::*;

#[cfg(feature = "sepol_stub")]
use stub::*;

/// Extended permission range for ioctl operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Xperm {
    /// Low value of the range
    pub low: u16,
    /// High value of the range
    pub high: u16,
    /// Whether this is a complement (exclude) range
    pub reset: bool,
}

impl Xperm {
    /// Create a new Xperm
    pub fn new(low: u16, high: u16, reset: bool) -> Self {
        Self { low, high, reset }
    }

    /// Create a single-value Xperm
    pub fn single(value: u16) -> Self {
        Self { low: value, high: value, reset: false }
    }

    /// Create a range Xperm
    pub fn range(low: u16, high: u16) -> Self {
        Self { low, high, reset: false }
    }

    /// Create a complement Xperm (exclude range)
    pub fn complement(low: u16, high: u16) -> Self {
        Self { low, high, reset: true }
    }

    /// Create an all-permissions Xperm
    pub fn all() -> Self {
        Self { low: 0x0000, high: 0xFFFF, reset: false }
    }

    /// Check if a value is in the range
    pub fn contains(&self, value: u16) -> bool {
        value >= self.low && value <= self.high
    }
}

impl fmt::Display for Xperm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.reset {
            write!(f, "~")?;
        }
        if self.low == self.high {
            write!(f, "{{ {:#06X} }}", self.low)
        } else {
            write!(f, "{{ {:#06X}-{:#06X} }}", self.low, self.high)
        }
    }
}

/// Main SELinux policy structure
pub struct SePolicy {
    #[cfg(feature = "sepol_linked")]
    db: *mut policydb,
    #[cfg(feature = "sepol_stub")]
    inner: SePolicyInner,
}

#[cfg(feature = "sepol_linked")]
impl Drop for SePolicy {
    fn drop(&mut self) {
        unsafe {
            if !self.db.is_null() {
                sepol_db_free(self.db);
            }
        }
    }
}

// Safety: policydb is not thread-safe but can be sent between threads
unsafe impl Send for SePolicy {}
unsafe impl Sync for SePolicy {}

#[cfg(feature = "sepol_stub")]
impl Default for SePolicy {
    fn default() -> Self {
        Self { inner: SePolicyInner::default() }
    }
}

impl SePolicy {
    /// Load policy from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path_str = CString::new(path.as_ref().to_string_lossy().into_owned())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        #[cfg(feature = "sepol_linked")]
        {
            unsafe {
                let db = sepol_db_from_file(path_str.as_ptr());
                if db.is_null() {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "Failed to load policy"));
                }
                Ok(Self { db })
            }
        }

        #[cfg(feature = "sepol_stub")]
        {
            let data = std::fs::read(path)?;
            Self::from_data(&data)
        }
    }

    /// Load policy from binary data
    pub fn from_data(data: &[u8]) -> io::Result<Self> {
        #[cfg(feature = "sepol_linked")]
        {
            unsafe {
                let db = sepol_db_from_data(data.as_ptr(), data.len());
                if db.is_null() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Failed to parse policy"));
                }
                Ok(Self { db })
            }
        }

        #[cfg(feature = "sepol_stub")]
        {
            let mut policy = Self::default();
            policy.inner.policy_data = data.to_vec();
            policy.inner.initialize_common_types();
            Ok(policy)
        }
    }

    /// Load policy from split CIL policies
    pub fn from_split() -> io::Result<Self> {
        // TODO: Implement CIL compilation
        #[cfg(feature = "sepol_linked")]
        {
            Err(io::Error::new(io::ErrorKind::Unsupported, "CIL compilation not implemented"))
        }

        #[cfg(feature = "sepol_stub")]
        {
            let mut policy = Self::default();
            policy.inner.initialize_common_types();
            Ok(policy)
        }
    }

    /// Compile split CIL policies
    pub fn compile_split() -> io::Result<Self> {
        #[cfg(feature = "sepol_linked")]
        {
            Err(io::Error::new(io::ErrorKind::Unsupported, "CIL compilation not implemented"))
        }

        #[cfg(feature = "sepol_stub")]
        {
            let mut policy = Self::default();
            policy.inner.initialize_common_types();
            Ok(policy)
        }
    }

    /// Save policy to a file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let path_str = CString::new(path.as_ref().to_string_lossy().into_owned())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        #[cfg(feature = "sepol_linked")]
        {
            unsafe {
                if sepol_db_to_file(self.db, path_str.as_ptr()) != 0 {
                    return Err(io::Error::new(io::ErrorKind::Other, "Failed to write policy"));
                }
            }
        }

        #[cfg(feature = "sepol_stub")]
        {
            if self.inner.policy_data.is_empty() {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                    "Cannot save empty policy - no binary data available"));
            }
            std::fs::write(path, &self.inner.policy_data)?;
        }

        Ok(())
    }

    /// Add an allow rule
    pub fn allow(&mut self, s: &[&str], t: &[&str], c: &[&str], p: &[&str]) {
        for &src in s {
            for &tgt in t {
                for &cls in c {
                    for &perm in p {
                        self.add_rule(src, tgt, cls, perm, AVTAB_ALLOWED as i32, 0);
                    }
                }
            }
        }
        if s.is_empty() || t.is_empty() || c.is_empty() || p.is_empty() {
            self.add_rule(
                if s.is_empty() { "" } else { s[0] },
                if t.is_empty() { "" } else { t[0] },
                if c.is_empty() { "" } else { c[0] },
                "",
                AVTAB_ALLOWED as i32,
                if p.is_empty() { 0 } else { 1 },
            );
        }
    }

    /// Add a deny rule
    pub fn deny(&mut self, s: &[&str], t: &[&str], c: &[&str], p: &[&str]) {
        for &src in s {
            for &tgt in t {
                for &cls in c {
                    for &perm in p {
                        self.add_rule(src, tgt, cls, perm, AVTAB_ALLOWED as i32, 1);
                    }
                }
            }
        }
    }

    /// Add an auditallow rule
    pub fn auditallow(&mut self, s: &[&str], t: &[&str], c: &[&str], p: &[&str]) {
        for &src in s {
            for &tgt in t {
                for &cls in c {
                    for &perm in p {
                        self.add_rule(src, tgt, cls, perm, AVTAB_AUDITALLOW as i32, 0);
                    }
                }
            }
        }
    }

    /// Add a dontaudit rule
    pub fn dontaudit(&mut self, s: &[&str], t: &[&str], c: &[&str], p: &[&str]) {
        for &src in s {
            for &tgt in t {
                for &cls in c {
                    for &perm in p {
                        self.add_rule(src, tgt, cls, perm, AVTAB_AUDITDENY as i32, 1);
                    }
                }
            }
        }
    }

    /// Add an allowxperm rule
    pub fn allowxperm(&mut self, s: &[&str], t: &[&str], c: &[&str], p: &[Xperm]) {
        for &src in s {
            for &tgt in t {
                for &cls in c {
                    for perm in p {
                        self.add_xperm_rule(src, tgt, cls, perm, AVTAB_XPERMS_ALLOWED as i32);
                    }
                }
            }
        }
    }

    /// Add an auditallowxperm rule
    pub fn auditallowxperm(&mut self, s: &[&str], t: &[&str], c: &[&str], p: &[Xperm]) {
        for &src in s {
            for &tgt in t {
                for &cls in c {
                    for perm in p {
                        self.add_xperm_rule(src, tgt, cls, perm, AVTAB_XPERMS_AUDITALLOW as i32);
                    }
                }
            }
        }
    }

    /// Add a dontauditxperm rule
    pub fn dontauditxperm(&mut self, s: &[&str], t: &[&str], c: &[&str], p: &[Xperm]) {
        for &src in s {
            for &tgt in t {
                for &cls in c {
                    for perm in p {
                        self.add_xperm_rule(src, tgt, cls, perm, AVTAB_XPERMS_DONTAUDIT as i32);
                    }
                }
            }
        }
    }

    /// Make types permissive
    pub fn permissive(&mut self, types: &[&str]) {
        for &t in types {
            self.set_type_state(t, true);
        }
    }

    /// Make types enforcing
    pub fn enforce(&mut self, types: &[&str]) {
        for &t in types {
            self.set_type_state(t, false);
        }
    }

    /// Add typeattribute
    pub fn typeattribute(&mut self, types: &[&str], attrs: &[&str]) {
        for &t in types {
            for &a in attrs {
                self.add_typeattribute(t, a);
            }
        }
    }

    /// Create a new type
    pub fn type_(&mut self, name: &str, attrs: &[&str]) {
        self.add_type(name, TYPE_TYPE);
        for &a in attrs {
            self.add_typeattribute(name, a);
        }
    }

    /// Create a new attribute
    pub fn attribute(&mut self, name: &str) {
        self.add_type(name, TYPE_ATTRIB);
    }

    /// Add a type_transition rule
    pub fn type_transition(&mut self, s: &str, t: &str, c: &str, d: &str, o: &str) {
        if o.is_empty() {
            self.add_type_rule(s, t, c, d, AVTAB_TRANSITION as i32);
        } else {
            self.add_filename_trans(s, t, c, d, o);
        }
    }

    /// Add a type_change rule
    pub fn type_change(&mut self, s: &str, t: &str, c: &str, d: &str) {
        self.add_type_rule(s, t, c, d, AVTAB_CHANGE as i32);
    }

    /// Add a type_member rule
    pub fn type_member(&mut self, s: &str, t: &str, c: &str, d: &str) {
        self.add_type_rule(s, t, c, d, AVTAB_MEMBER as i32);
    }

    /// Add a genfscon rule
    pub fn genfscon(&mut self, fs: &str, path: &str, ctx: &str) {
        self.add_genfscon_rule(fs, path, ctx);
    }

    /// Load and parse rules from a string
    pub fn load_rules(&mut self, rules: &str) {
        statement::parse_rules(self, rules);
    }

    /// Load rules from a file
    pub fn load_rule_file<P: AsRef<Path>>(&mut self, filename: P) -> io::Result<()> {
        let content = std::fs::read_to_string(filename)?;
        self.load_rules(&content);
        Ok(())
    }

    /// Print all rules in the policy
    pub fn print_rules(&self) {
        #[cfg(feature = "sepol_linked")]
        unsafe {
            sepol_print_types(self.db, 1);  // Print attributes
            sepol_print_types(self.db, 0);  // Print types
            sepol_print_avtab_rules(self.db);
            sepol_print_filename_trans(self.db);
            sepol_print_genfscon(self.db);
        }

        #[cfg(feature = "sepol_stub")]
        self.inner.print_rules();
    }

    // Internal helper methods

    fn add_rule(&mut self, s: &str, t: &str, c: &str, p: &str, effect: i32, invert: i32) {
        #[cfg(feature = "sepol_linked")]
        unsafe {
            let s_c = if s.is_empty() { None } else { Some(CString::new(s).unwrap()) };
            let t_c = if t.is_empty() { None } else { Some(CString::new(t).unwrap()) };
            let c_c = if c.is_empty() { None } else { Some(CString::new(c).unwrap()) };
            let p_c = if p.is_empty() { None } else { Some(CString::new(p).unwrap()) };
            sepol_add_rule(
                self.db,
                s_c.as_ref().map_or(std::ptr::null(), |x| x.as_ptr()),
                t_c.as_ref().map_or(std::ptr::null(), |x| x.as_ptr()),
                c_c.as_ref().map_or(std::ptr::null(), |x| x.as_ptr()),
                p_c.as_ref().map_or(std::ptr::null(), |x| x.as_ptr()),
                effect,
                invert,
            );
        }

        #[cfg(feature = "sepol_stub")]
        self.inner.add_rule(s, t, c, p, effect, invert);
    }

    fn add_xperm_rule(&mut self, s: &str, t: &str, c: &str, p: &Xperm, effect: i32) {
        #[cfg(feature = "sepol_linked")]
        unsafe {
            let s_c = if s.is_empty() { None } else { Some(CString::new(s).unwrap()) };
            let t_c = if t.is_empty() { None } else { Some(CString::new(t).unwrap()) };
            let c_c = if c.is_empty() { None } else { Some(CString::new(c).unwrap()) };
            sepol_add_xperm_rule(
                self.db,
                s_c.as_ref().map_or(std::ptr::null(), |x| x.as_ptr()),
                t_c.as_ref().map_or(std::ptr::null(), |x| x.as_ptr()),
                c_c.as_ref().map_or(std::ptr::null(), |x| x.as_ptr()),
                p.low,
                p.high,
                if p.reset { 1 } else { 0 },
                effect,
            );
        }

        #[cfg(feature = "sepol_stub")]
        self.inner.add_xperm_rule(s, t, c, p, effect);
    }

    fn add_type_rule(&mut self, s: &str, t: &str, c: &str, d: &str, effect: i32) {
        #[cfg(feature = "sepol_linked")]
        unsafe {
            let s_c = CString::new(s).unwrap();
            let t_c = CString::new(t).unwrap();
            let c_c = CString::new(c).unwrap();
            let d_c = CString::new(d).unwrap();
            sepol_add_type_rule(self.db, s_c.as_ptr(), t_c.as_ptr(), c_c.as_ptr(), d_c.as_ptr(), effect);
        }

        #[cfg(feature = "sepol_stub")]
        self.inner.add_type_rule(s, t, c, d, effect);
    }

    fn add_filename_trans(&mut self, s: &str, t: &str, c: &str, d: &str, o: &str) {
        #[cfg(feature = "sepol_linked")]
        unsafe {
            let s_c = CString::new(s).unwrap();
            let t_c = CString::new(t).unwrap();
            let c_c = CString::new(c).unwrap();
            let d_c = CString::new(d).unwrap();
            let o_c = CString::new(o).unwrap();
            sepol_add_filename_trans(self.db, s_c.as_ptr(), t_c.as_ptr(), c_c.as_ptr(), d_c.as_ptr(), o_c.as_ptr());
        }

        #[cfg(feature = "sepol_stub")]
        self.inner.add_filename_trans(s, t, c, d, o);
    }

    fn add_genfscon_rule(&mut self, fs: &str, path: &str, ctx: &str) {
        #[cfg(feature = "sepol_linked")]
        unsafe {
            let fs_c = CString::new(fs).unwrap();
            let path_c = CString::new(path).unwrap();
            let ctx_c = CString::new(ctx).unwrap();
            sepol_add_genfscon(self.db, fs_c.as_ptr(), path_c.as_ptr(), ctx_c.as_ptr());
        }

        #[cfg(feature = "sepol_stub")]
        self.inner.add_genfscon_rule(fs, path, ctx);
    }

    fn add_type(&mut self, name: &str, flavor: u32) {
        #[cfg(feature = "sepol_linked")]
        unsafe {
            let name_c = CString::new(name).unwrap();
            sepol_add_type(self.db, name_c.as_ptr(), flavor);
        }

        #[cfg(feature = "sepol_stub")]
        self.inner.add_type(name, flavor);
    }

    fn set_type_state(&mut self, name: &str, permissive: bool) {
        #[cfg(feature = "sepol_linked")]
        unsafe {
            let name_c = CString::new(name).unwrap();
            sepol_set_type_state(self.db, name_c.as_ptr(), if permissive { 1 } else { 0 });
        }

        #[cfg(feature = "sepol_stub")]
        self.inner.set_type_state(name, permissive);
    }

    fn add_typeattribute(&mut self, type_name: &str, attr_name: &str) {
        #[cfg(feature = "sepol_linked")]
        unsafe {
            let type_c = CString::new(type_name).unwrap();
            let attr_c = CString::new(attr_name).unwrap();
            sepol_add_typeattribute(self.db, type_c.as_ptr(), attr_c.as_ptr());
        }

        #[cfg(feature = "sepol_stub")]
        self.inner.add_typeattribute(type_name, attr_name);
    }
}
