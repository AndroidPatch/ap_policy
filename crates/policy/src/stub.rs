//! Stub implementation when libsepol is not available
//!
//! This module provides a pure Rust fallback that can add rules but cannot
//! parse existing policy binary files.

use std::collections::{HashMap, HashSet};
use std::fmt;

/// SELinux type definition
#[derive(Debug, Clone)]
pub struct Type {
    /// Type name
    pub name: String,
    /// Whether this is an attribute
    pub is_attribute: bool,
    /// Attributes associated with this type
    pub attributes: HashSet<String>,
    /// Whether this type is permissive
    pub is_permissive: bool,
    /// Type value/index
    pub value: u32,
}

/// SELinux class definition
#[derive(Debug, Clone)]
pub struct Class {
    /// Class name
    pub name: String,
    /// Class value/index
    pub value: u32,
    /// Permissions defined for this class
    pub permissions: HashMap<String, u32>,
    /// Common permissions inherited
    pub common_permissions: HashMap<String, u32>,
}

/// Rule type for access vector table rules
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleType {
    Allow,
    Deny,
    AuditAllow,
    DontAudit,
}

/// Extended permission rule type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XpermRuleType {
    Allow,
    AuditAllow,
    DontAudit,
}

/// Type rule type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeRuleType {
    Transition,
    Change,
    Member,
}

/// Access vector table rule
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AvtabRule {
    /// Source type
    pub source_type: String,
    /// Target type
    pub target_type: String,
    /// Target class
    pub target_class: String,
    /// Permissions (as bit vector)
    pub permissions: u32,
    /// Rule type
    pub rule_type: RuleType,
}

/// Type transition/change/member rule
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypeRule {
    /// Source type
    pub source_type: String,
    /// Target type
    pub target_type: String,
    /// Target class
    pub target_class: String,
    /// Default type
    pub default_type: String,
    /// Object name (for filename transitions)
    pub object_name: Option<String>,
    /// Rule type
    pub rule_type: TypeRuleType,
}

/// genfscon rule
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GenfsCon {
    /// Filesystem name
    pub fs_name: String,
    /// Path
    pub path: String,
    /// Security context
    pub context: String,
}

/// Extended permission rule
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct XpermRule {
    /// Source type
    pub source_type: String,
    /// Target type
    pub target_type: String,
    /// Target class
    pub target_class: String,
    /// Extended permissions
    pub xperms: Vec<crate::Xperm>,
    /// Rule type
    pub rule_type: XpermRuleType,
}

/// AVTAB constants (matches libsepol)
pub const AVTAB_ALLOWED: u16 = 0x0001;
pub const AVTAB_AUDITALLOW: u16 = 0x0002;
pub const AVTAB_AUDITDENY: u16 = 0x0004;
pub const AVTAB_TRANSITION: u16 = 0x0010;
pub const AVTAB_MEMBER: u16 = 0x0020;
pub const AVTAB_CHANGE: u16 = 0x0040;

pub const AVTAB_XPERMS_ALLOWED: u16 = 0x0100;
pub const AVTAB_XPERMS_AUDITALLOW: u16 = 0x0200;
pub const AVTAB_XPERMS_DONTAUDIT: u16 = 0x0400;

pub const TYPE_TYPE: u32 = 0;
pub const TYPE_ATTRIB: u32 = 1;

/// Inner policy representation for stub implementation
pub struct SePolicyInner {
    pub types: HashMap<String, Type>,
    pub classes: HashMap<String, Class>,
    pub avtab_rules: Vec<AvtabRule>,
    pub xperm_rules: Vec<XpermRule>,
    pub type_rules: Vec<TypeRule>,
    pub genfscon_rules: Vec<GenfsCon>,
    pub policy_data: Vec<u8>,
    pub policy_version: u32,
    next_type_value: u32,
    next_class_value: u32,
}

impl Default for SePolicyInner {
    fn default() -> Self {
        Self {
            types: HashMap::new(),
            classes: HashMap::new(),
            avtab_rules: Vec::new(),
            xperm_rules: Vec::new(),
            type_rules: Vec::new(),
            genfscon_rules: Vec::new(),
            policy_data: Vec::new(),
            policy_version: 32,
            next_type_value: 1,
            next_class_value: 1,
        }
    }
}

impl SePolicyInner {
    pub fn initialize_common_types(&mut self) {
        // Add common attributes
        self.add_attribute("domain");
        self.add_attribute("file_type");
        self.add_attribute("dev_type");
        self.add_attribute("fs_type");
        self.add_attribute("mlstrustedsubject");
        self.add_attribute("mlstrustedobject");
        self.add_attribute("netdomain");
        self.add_attribute("appdomain");

        // Add common types
        self.add_type("kernel", &["domain"]);

        // Add common classes with permissions
        self.add_class("file", &[
            "read", "write", "execute", "entrypoint", "open", "create",
            "getattr", "setattr", "unlink", "rename", "map", "append"
        ]);
        self.add_class("dir", &[
            "read", "write", "search", "add_name", "remove_name",
            "create", "getattr", "setattr", "rmdir", "open", "map"
        ]);
        self.add_class("process", &[
            "transition", "sigchld", "fork", "execmem", "getattr",
            "setcurrent", "dyntransition"
        ]);
        self.add_class("binder", &["call", "transfer", "impersonate"]);
        self.add_class("chr_file", &[
            "read", "write", "open", "ioctl", "getattr", "setattr"
        ]);
        self.add_class("blk_file", &[
            "read", "write", "open", "ioctl", "getattr", "setattr"
        ]);
        self.add_class("fifo_file", &[
            "read", "write", "open", "getattr", "setattr"
        ]);
        self.add_class("sock_file", &[
            "read", "write", "open", "getattr", "setattr"
        ]);
        self.add_class("lnk_file", &[
            "read", "write", "open", "getattr", "setattr"
        ]);
        self.add_class("unix_stream_socket", &[
            "connectto", "read", "write", "create", "bind"
        ]);
        self.add_class("tcp_socket", &["ioctl"]);
        self.add_class("udp_socket", &["ioctl"]);
        self.add_class("rawip_socket", &["ioctl"]);
        self.add_class("security", &["load_policy"]);
        self.add_class("filesystem", &["associate", "unmount"]);
        self.add_class("fd", &["use"]);
    }

    fn add_type(&mut self, name: &str, attributes: &[&str]) {
        if self.types.contains_key(name) {
            return;
        }
        let type_entry = Type {
            name: name.to_string(),
            is_attribute: false,
            attributes: attributes.iter().map(|s| s.to_string()).collect(),
            is_permissive: false,
            value: self.next_type_value,
        };
        self.next_type_value += 1;
        self.types.insert(name.to_string(), type_entry);
    }

    fn add_attribute(&mut self, name: &str) {
        if self.types.contains_key(name) {
            return;
        }
        let type_entry = Type {
            name: name.to_string(),
            is_attribute: true,
            attributes: HashSet::new(),
            is_permissive: false,
            value: self.next_type_value,
        };
        self.next_type_value += 1;
        self.types.insert(name.to_string(), type_entry);
    }

    fn add_class(&mut self, name: &str, permissions: &[&str]) {
        if self.classes.contains_key(name) {
            return;
        }
        let mut perms = HashMap::new();
        for (i, perm) in permissions.iter().enumerate() {
            perms.insert(perm.to_string(), i as u32 + 1);
        }
        let class = Class {
            name: name.to_string(),
            value: self.next_class_value,
            permissions: perms,
            common_permissions: HashMap::new(),
        };
        self.next_class_value += 1;
        self.classes.insert(name.to_string(), class);
    }

    fn get_or_create_type(&mut self, name: &str) -> &mut Type {
        if !self.types.contains_key(name) {
            let type_entry = Type {
                name: name.to_string(),
                is_attribute: false,
                attributes: HashSet::new(),
                is_permissive: false,
                value: self.next_type_value,
            };
            self.next_type_value += 1;
            self.types.insert(name.to_string(), type_entry);
        }
        self.types.get_mut(name).unwrap()
    }

    fn expand_types(&self, types: &[&str]) -> Vec<String> {
        let mut result = Vec::new();
        for type_name in types {
            if type_name.is_empty() {
                // Wildcard - expand to all types
                for (name, t) in &self.types {
                    if !t.is_attribute {
                        result.push(name.clone());
                    }
                }
                continue;
            }
            if let Some(type_entry) = self.types.get(*type_name) {
                if type_entry.is_attribute {
                    // Expand attribute to all types with this attribute
                    for (name, t) in &self.types {
                        if !t.is_attribute && t.attributes.contains(*type_name) {
                            result.push(name.clone());
                        }
                    }
                } else {
                    result.push(type_name.to_string());
                }
            } else {
                // Type doesn't exist, add it anyway
                result.push(type_name.to_string());
            }
        }
        result.sort();
        result.dedup();
        result
    }

    fn perms_to_bits(&self, class_name: &str, perms: &[&str]) -> u32 {
        if perms.is_empty() {
            return !0u32; // All permissions
        }
        let mut bits = 0u32;
        if let Some(class) = self.classes.get(class_name) {
            for perm in perms {
                if let Some(&bit) = class.permissions.get(*perm) {
                    bits |= 1u32 << (bit - 1);
                } else if let Some(&bit) = class.common_permissions.get(*perm) {
                    bits |= 1u32 << (bit - 1);
                }
            }
        }
        bits
    }

    pub fn print_rules(&self) {
        // Print attributes first
        for (name, type_entry) in &self.types {
            if type_entry.is_attribute {
                println!("attribute {}", name);
            }
        }

        // Print types
        for (name, type_entry) in &self.types {
            if !type_entry.is_attribute {
                if type_entry.attributes.is_empty() {
                    println!("type {}", name);
                } else {
                    let attrs: Vec<_> = type_entry.attributes.iter().cloned().collect();
                    println!("type {} {{ {} }}", name, attrs.join(" "));
                }
            }
            if type_entry.is_permissive {
                println!("permissive {}", name);
            }
        }

        // Print avtab rules
        for rule in &self.avtab_rules {
            let rule_type = match rule.rule_type {
                RuleType::Allow => "allow",
                RuleType::Deny => "deny",
                RuleType::AuditAllow => "auditallow",
                RuleType::DontAudit => "dontaudit",
            };
            let perms = self.bits_to_perms(&rule.target_class, rule.permissions);
            println!("{} {} {} {} {{ {} }}",
                rule_type, rule.source_type, rule.target_type,
                rule.target_class, perms.join(" "));
        }

        // Print xperm rules
        for rule in &self.xperm_rules {
            let rule_type = match rule.rule_type {
                XpermRuleType::Allow => "allowxperm",
                XpermRuleType::AuditAllow => "auditallowxperm",
                XpermRuleType::DontAudit => "dontauditxperm",
            };
            let xperms: Vec<String> = rule.xperms.iter().map(|x| format!("{}", x)).collect();
            println!("{} {} {} {} ioctl {{ {} }}",
                rule_type, rule.source_type, rule.target_type, rule.target_class, xperms.join(" "));
        }

        // Print type rules
        for rule in &self.type_rules {
            let rule_type = match rule.rule_type {
                TypeRuleType::Transition => "type_transition",
                TypeRuleType::Change => "type_change",
                TypeRuleType::Member => "type_member",
            };
            if let Some(ref obj) = rule.object_name {
                println!("{} {} {} {} {} {}",
                    rule_type, rule.source_type, rule.target_type,
                    rule.target_class, rule.default_type, obj);
            } else {
                println!("{} {} {} {} {}",
                    rule_type, rule.source_type, rule.target_type,
                    rule.target_class, rule.default_type);
            }
        }

        // Print genfscon rules
        for genfs in &self.genfscon_rules {
            println!("genfscon {} {} {}", genfs.fs_name, genfs.path, genfs.context);
        }
    }

    fn bits_to_perms(&self, class_name: &str, bits: u32) -> Vec<String> {
        let mut perms = Vec::new();
        if let Some(class) = self.classes.get(class_name) {
            for (name, &bit) in &class.permissions {
                if bits & (1u32 << (bit - 1)) != 0 {
                    perms.push(name.clone());
                }
            }
            for (name, &bit) in &class.common_permissions {
                if bits & (1u32 << (bit - 1)) != 0 {
                    perms.push(name.clone());
                }
            }
        }
        perms.sort();
        perms
    }

    pub fn add_rule(&mut self, s: &str, t: &str, c: &str, p: &str, effect: i32, _invert: i32) {
        let sources = self.expand_types(if s.is_empty() { &[] } else { &[s] });
        let targets = self.expand_types(if t.is_empty() { &[] } else { &[t] });

        for src in &sources {
            for tgt in &targets {
                let rule = AvtabRule {
                    source_type: src.clone(),
                    target_type: tgt.clone(),
                    target_class: c.to_string(),
                    permissions: self.perms_to_bits(c, if p.is_empty() { &[] } else { &[p] }),
                    rule_type: match effect as u16 {
                        AVTAB_ALLOWED => RuleType::Allow,
                        AVTAB_AUDITALLOW => RuleType::AuditAllow,
                        AVTAB_AUDITDENY => RuleType::DontAudit,
                        _ => RuleType::Allow,
                    },
                };
                self.avtab_rules.push(rule);
            }
        }
    }

    pub fn add_xperm_rule(&mut self, s: &str, t: &str, c: &str, p: &crate::Xperm, effect: i32) {
        let sources = self.expand_types(if s.is_empty() { &[] } else { &[s] });
        let targets = self.expand_types(if t.is_empty() { &[] } else { &[t] });

        for src in &sources {
            for tgt in &targets {
                let rule = XpermRule {
                    source_type: src.clone(),
                    target_type: tgt.clone(),
                    target_class: c.to_string(),
                    xperms: vec![*p],
                    rule_type: match effect as u16 {
                        AVTAB_XPERMS_ALLOWED => XpermRuleType::Allow,
                        AVTAB_XPERMS_AUDITALLOW => XpermRuleType::AuditAllow,
                        AVTAB_XPERMS_DONTAUDIT => XpermRuleType::DontAudit,
                        _ => XpermRuleType::Allow,
                    },
                };
                self.xperm_rules.push(rule);
            }
        }
    }

    pub fn add_type_rule(&mut self, s: &str, t: &str, c: &str, d: &str, effect: i32) {
        let rule = TypeRule {
            source_type: s.to_string(),
            target_type: t.to_string(),
            target_class: c.to_string(),
            default_type: d.to_string(),
            object_name: None,
            rule_type: match effect as u16 {
                AVTAB_TRANSITION => TypeRuleType::Transition,
                AVTAB_MEMBER => TypeRuleType::Member,
                AVTAB_CHANGE => TypeRuleType::Change,
                _ => TypeRuleType::Transition,
            },
        };
        self.type_rules.push(rule);
    }

    pub fn add_filename_trans(&mut self, s: &str, t: &str, c: &str, d: &str, o: &str) {
        let rule = TypeRule {
            source_type: s.to_string(),
            target_type: t.to_string(),
            target_class: c.to_string(),
            default_type: d.to_string(),
            object_name: Some(o.to_string()),
            rule_type: TypeRuleType::Transition,
        };
        self.type_rules.push(rule);
    }

    pub fn add_genfscon_rule(&mut self, fs: &str, path: &str, ctx: &str) {
        let rule = GenfsCon {
            fs_name: fs.to_string(),
            path: path.to_string(),
            context: ctx.to_string(),
        };
        self.genfscon_rules.push(rule);
    }

    pub fn add_type(&mut self, name: &str, flavor: u32) {
        if self.types.contains_key(name) {
            return;
        }
        let type_entry = Type {
            name: name.to_string(),
            is_attribute: flavor == TYPE_ATTRIB,
            attributes: HashSet::new(),
            is_permissive: false,
            value: self.next_type_value,
        };
        self.next_type_value += 1;
        self.types.insert(name.to_string(), type_entry);
    }

    pub fn set_type_state(&mut self, name: &str, permissive: bool) {
        let type_entry = self.get_or_create_type(name);
        type_entry.is_permissive = permissive;
    }

    pub fn add_typeattribute(&mut self, type_name: &str, attr_name: &str) {
        // Ensure the type exists
        if !self.types.contains_key(type_name) {
            self.add_type(type_name, TYPE_TYPE);
        }

        // Ensure the attribute exists
        if !self.types.contains_key(attr_name) {
            self.add_type(attr_name, TYPE_ATTRIB);
        }

        // Add attribute to type
        if let Some(type_entry) = self.types.get_mut(type_name) {
            type_entry.attributes.insert(attr_name.to_string());
        }

        // Mark the attribute
        if let Some(attr_entry) = self.types.get_mut(attr_name) {
            attr_entry.is_attribute = true;
        }
    }
}
