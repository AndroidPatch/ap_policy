//! Magisk-specific SELinux rules
//!
//! This module provides the `magisk_rules()` function to apply Magisk's
//! built-in SELinux policy rules.

use crate::{SePolicy, Xperm};

/// Default process domain for Magisk
pub const SEPOL_PROC_DOMAIN: &str = "magisk";
/// Default file type for Magisk
pub const SEPOL_FILE_TYPE: &str = "magisk_file";
/// Default log type for Magisk
pub const SEPOL_LOG_TYPE: &str = "magisk_log";

impl SePolicy {
    /// Apply built-in Magisk rules to the policy
    pub fn magisk_rules(&mut self) {
        // Create new types
        self.type_(SEPOL_PROC_DOMAIN, &["domain"]);
        self.typeattribute(&[SEPOL_PROC_DOMAIN], &["mlstrustedsubject", "netdomain", "appdomain"]);
        self.type_(SEPOL_FILE_TYPE, &["file_type"]);
        self.typeattribute(&[SEPOL_FILE_TYPE], &["mlstrustedobject"]);




        // Make our root domain unconstrained
        self.allow(
            &[SEPOL_PROC_DOMAIN],
            &[
                "fs_type", "dev_type", "file_type", "domain",
                "service_manager_type", "hwservice_manager_type", "vndservice_manager_type",
                "port_type", "node_type", "property_type"
            ],
            &[],
            &[],
        );

        // Just in case, make the domain permissive
        self.permissive(&[SEPOL_PROC_DOMAIN]);

        // Allow us to do any ioctl
        self.allowxperm(
            &[SEPOL_PROC_DOMAIN],
            &["fs_type", "dev_type", "file_type", "domain"],
            &["blk_file", "fifo_file","chr_file", "chr_file"],
            &[Xperm::all()],
        );
        self.allowxperm(
            &[SEPOL_PROC_DOMAIN],
            &[SEPOL_PROC_DOMAIN],
            &["tcp_socket", "udp_socket", "rawip_socket"],
            &[Xperm::all()],
        );

        // Let binder work with our processes
        let service_managers = ["servicemanager", "vndservicemanager", "hwservicemanager"];
        self.allow(&service_managers, &[SEPOL_PROC_DOMAIN], &["dir"], &["search"]);
        self.allow(&service_managers, &[SEPOL_PROC_DOMAIN], &["file"], &["open", "read", "map"]);
        self.allow(&service_managers, &[SEPOL_PROC_DOMAIN], &["process"], &["getattr"]);
        self.allow(&["domain"], &[SEPOL_PROC_DOMAIN], &["binder"], &["call", "transfer"]);

        // Other common IPC
        self.allow(&["domain"], &[SEPOL_PROC_DOMAIN], &["process"], &["sigchld"]);
        self.allow(&["domain"], &[SEPOL_PROC_DOMAIN], &["fd"], &["use"]);
        self.allow(&["domain"], &[SEPOL_PROC_DOMAIN], &["fifo_file"], &["write", "read", "open", "getattr"]);

        self.allow(&["kernel"], &["adb_data_file"], &["file"], &[]);
        self.allow(&["kernel"], &["fs_type","dev_type","file_type"], &["file"], &["read","write"]);

    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert!(!SEPOL_PROC_DOMAIN.is_empty());
        assert!(!SEPOL_FILE_TYPE.is_empty());
        assert!(!SEPOL_LOG_TYPE.is_empty());
    }

    #[test]
    fn test_magisk_rules() {
        let mut policy = SePolicy::default();
        policy.magisk_rules();

        // Check that types were created
        assert!(policy.types.contains_key(SEPOL_PROC_DOMAIN));
        assert!(policy.types.contains_key(SEPOL_FILE_TYPE));
        assert!(policy.types.contains_key(SEPOL_LOG_TYPE));

        // Check that some rules were added
        assert!(!policy.avtab_rules.is_empty());
        assert!(!policy.xperm_rules.is_empty());
    }
}
