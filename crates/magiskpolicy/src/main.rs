//! MagiskPolicy - SELinux Policy Patch Tool
//!
//! A command-line tool for manipulating SELinux policies.

use std::env;
use std::io;

use policy::{format_statement_help, SePolicy};

/// Adapter to convert io::Write to fmt::Write
struct WriteAdapter<T>(T);

impl<T: std::io::Write> std::fmt::Write for WriteAdapter<T> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.write_all(s.as_bytes()).map_err(|_| std::fmt::Error)
    }
}

/// Print usage information
fn print_usage(cmd: &str) {
    eprintln!(
        r#"MagiskPolicy - SELinux Policy Patch Tool

Usage: {cmd} [--options...] [policy statements...]

Options:
   --help            show help message for policy statements
   --load FILE       load monolithic sepolicy from FILE
   --load-split      load from precompiled sepolicy or compile
                     split cil policies
   --compile-split   compile split cil policies
   --save FILE       dump monolithic sepolicy to FILE
   --live            immediately load sepolicy into the kernel
   --magisk          apply built-in Magisk sepolicy rules
   --apply FILE      apply rules from FILE, read and parsed
                     line by line as policy statements
                     (multiple --apply are allowed)
   --print-rules     print all rules in the loaded sepolicy

If neither --load, --load-split, nor --compile-split is specified,
it will load from current live policies (/sys/fs/selinux/policy)
"#
    );

    let _ = format_statement_help(&mut WriteAdapter(io::stderr()));
    eprintln!();
}

/// CLI configuration
#[derive(Debug, Default)]
struct CliConfig {
    live: bool,
    magisk: bool,
    compile_split: bool,
    load_split: bool,
    print_rules: bool,
    load: Option<String>,
    save: Option<String>,
    apply: Vec<String>,
    policies: Vec<String>,
}

/// Parse command-line arguments
fn parse_args(args: &[String]) -> Result<CliConfig, String> {
    let mut config = CliConfig::default();
    let mut i = 1; // Skip program name

    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_usage(args.first().map(|s| s.as_str()).unwrap_or("magiskpolicy"));
                std::process::exit(0);
            }
            "--live" => config.live = true,
            "--magisk" => config.magisk = true,
            "--compile-split" => config.compile_split = true,
            "--load-split" => config.load_split = true,
            "--print-rules" => config.print_rules = true,
            "--load" => {
                i += 1;
                if i >= args.len() {
                    return Err("--load requires a file path".to_string());
                }
                config.load = Some(args[i].clone());
            }
            "--save" => {
                i += 1;
                if i >= args.len() {
                    return Err("--save requires a file path".to_string());
                }
                config.save = Some(args[i].clone());
            }
            "--apply" => {
                i += 1;
                if i >= args.len() {
                    return Err("--apply requires a file path".to_string());
                }
                config.apply.push(args[i].clone());
            }
            arg if arg.starts_with('-') => {
                return Err(format!("Unknown option: {}", arg));
            }
            policy => {
                config.policies.push(policy.to_string());
            }
        }
        i += 1;
    }

    Ok(config)
}

/// Run the CLI
fn run(config: CliConfig) -> Result<(), String> {
    // Validate mutually exclusive options
    let load_count = config.load.iter().count()
        + config.compile_split as usize
        + config.load_split as usize;
    if load_count > 1 {
        return Err("Multiple load source supplied".to_string());
    }

    // Load policy
    let mut sepol = if let Some(ref file) = config.load {
        SePolicy::from_file(file)
            .map_err(|e| format!("Cannot load policy from {}: {}", file, e))?
    } else if config.load_split {
        SePolicy::from_split()
            .map_err(|e| format!("Cannot load split policy: {}", e))?
    } else if config.compile_split {
        SePolicy::compile_split()
            .map_err(|e| format!("Cannot compile split policy: {}", e))?
    } else {
        SePolicy::from_file("/sys/fs/selinux/policy")
            .map_err(|e| format!("Cannot load live policy: {}", e))?
    };

    if config.print_rules {
        if config.magisk
            || !config.apply.is_empty()
            || !config.policies.is_empty()
            || config.live
            || config.save.is_some()
        {
            return Err("Cannot print rules with other options".to_string());
        }
        sepol.print_rules();
        return Ok(());
    }

    if config.magisk {
        sepol.magisk_rules();
    }

    for file in &config.apply {
        sepol
            .load_rule_file(file)
            .map_err(|e| format!("Cannot load rule file {}: {}", file, e))?;
    }

    for statement in &config.policies {
        sepol.load_rules(statement);
    }

    if config.live {
        sepol
            .to_file("/sys/fs/selinux/load")
            .map_err(|e| format!("Cannot apply policy: {}", e))?;
    }

    if let Some(ref file) = config.save {
        sepol
            .to_file(file)
            .map_err(|e| format!("Cannot dump policy to {}: {}", file, e))?;
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage(args.first().map(|s| s.as_str()).unwrap_or("magiskpolicy"));
        std::process::exit(1);
    }

    match parse_args(&args) {
        Ok(config) => {
            if let Err(e) = run(config) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
