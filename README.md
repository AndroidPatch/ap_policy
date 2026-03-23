# MagiskPolicy - SELinux Policy Manipulation Library

A Rust implementation of magiskpolicy for manipulating SELinux policies.

## Important Note

**This library requires libsepol for proper policy binary parsing.**

The SELinux policy binary format is complex and requires libsepol to properly parse. Without libsepol:
- `from_file()` and `from_data()` will not properly parse policy files
- `print_rules()` will only show rules added via the API, not from loaded policies
- `to_file()` will not work properly for creating valid policy files

## Building for Android

### Prerequisites

1. Android NDK installed
2. libsepol sources (included in Magisk project)

### Build Steps

```bash
# Build with libsepol (requires libsepol to be built first)
cargo ndk -t arm64-v8a build --release
```

### Getting libsepol

The Magisk project includes libsepol sources at:
```
native/src/external/selinux/libsepol/
```

Build libsepol first:
```bash
cd Magisk/native/src/external
# Build libsepol using the Android.mk or build scripts
```

## Project Structure

```
ap_policy/
├── Cargo.toml                    # Workspace configuration
├── crates/
│   ├── policy/                   # Core SELinux policy library
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs           # Main library with SePolicy struct
│   │   │   ├── statement.rs     # Policy statement parser
│   │   │   └── rules.rs         # Magisk-specific rules
│   │   └── README.md
│   └── magiskpolicy/            # CLI binary
│       ├── Cargo.toml
│       ├── src/
│       │   └── main.rs          # Command-line interface
│       └── README.md
└── README.md                    # This file
```

## Usage

### As a Library

Add to your `Cargo.toml`:

```toml
[dependencies]
policy = { path = "path/to/crates/policy" }
```

Example:

```rust
use policy::{SePolicy, Xperm};

fn main() -> std::io::Result<()> {
    // Load policy from a file (requires libsepol for proper parsing)
    let mut policy = SePolicy::from_file("/sys/fs/selinux/policy")?;

    // Apply Magisk rules
    policy.magisk_rules();

    // Add custom rules
    policy.allow(
        &["domain"],
        &["magisk_file"],
        &["file"],
        &["read", "write"]
    );

    // Add extended permissions
    policy.allowxperm(
        &["magisk"],
        &["dev_type"],
        &["chr_file"],
        &[Xperm::range(0x8910, 0x8926)]
    );

    // Load rules from a string
    policy.load_rules("allow domain magisk_file file { read write }");

    // Save modified policy (requires libsepol for proper serialization)
    policy.to_file("modified_policy")?;

    Ok(())
}
```

### As a Binary

Build:

```bash
cargo build --release
```

For Android (requires NDK):

```bash
cargo ndk -t arm64-v8a build --release
```

Run:

```bash
./magiskpolicy --help
./magiskpolicy --magisk --save modified_policy
./magiskpolicy --load policy --apply rules.txt --save output
```

#### Command Line Options

```
Usage: magiskpolicy [--options...] [policy statements...]

Options:
   --help            show help message for policy statements
   --load FILE       load monolithic sepolicy from FILE
   --load-split      load from precompiled sepolicy or compile split cil policies
   --compile-split   compile split cil policies
   --save FILE       dump monolithic sepolicy to FILE
   --live            immediately load sepolicy into the kernel
   --magisk          apply built-in Magisk sepolicy rules
   --apply FILE      apply rules from FILE, read line by line as policy statements
   --print-rules     print all rules in the loaded sepolicy
```

### Policy Statements

The library supports the following SELinux policy statements:

- `allow *source_type *target_type *class *perm_set`
- `deny *source_type *target_type *class *perm_set`
- `auditallow *source_type *target_type *class *perm_set`
- `dontaudit *source_type *target_type *class *perm_set`
- `allowxperm *source_type *target_type *class ioctl xperm_set`
- `auditallowxperm *source_type *target_type *class ioctl xperm_set`
- `dontauditxperm *source_type *target_type *class ioctl xperm_set`
- `permissive *type`
- `enforce *type`
- `typeattribute ^type ^attribute`
- `type type_name ^(attribute)`
- `attribute attribute_name`
- `type_transition source_type target_type class default_type (object_name)`
- `type_change source_type target_type class default_type`
- `type_member source_type target_type class default_type`
- `genfscon fs_name partial_path fs_context`

Arguments labeled with `(^)` can accept one or more entries in braces `{}`.
Arguments labeled with `(*)` additionally support the match-all operator `*`.

## API Reference

### `SePolicy`

Main structure for manipulating SELinux policies.

#### Loading/Saving

- `from_file(path)` - Load policy from a file
- `from_data(data)` - Load policy from binary data
- `from_split()` - Load from split CIL policies
- `compile_split()` - Compile split CIL policies
- `to_file(path)` - Save policy to a file

#### Rule Manipulation

- `allow(src, tgt, cls, perm)` - Add allow rule
- `deny(src, tgt, cls, perm)` - Add deny rule
- `auditallow(src, tgt, cls, perm)` - Add auditallow rule
- `dontaudit(src, tgt, cls, perm)` - Add dontaudit rule
- `allowxperm(src, tgt, cls, xperms)` - Add extended permissions
- `auditallowxperm(src, tgt, cls, xperms)` - Add audit extended permissions
- `dontauditxperm(src, tgt, cls, xperms)` - Add dontaudit extended permissions

#### Type/Attribute Management

- `permissive(types)` - Make types permissive
- `enforce(types)` - Make types enforcing
- `typeattribute(types, attrs)` - Add attributes to types
- `type_(name, attrs)` - Create new type
- `attribute(name)` - Create new attribute

#### Type Rules

- `type_transition(src, tgt, cls, def, obj)` - Add type transition rule
- `type_change(src, tgt, cls, def)` - Add type change rule
- `type_member(src, tgt, cls, def)` - Add type member rule

#### Other

- `genfscon(fs, path, ctx)` - Add genfscon rule
- `magisk_rules()` - Apply built-in Magisk rules
- `load_rules(rules)` - Load and parse rules from string
- `load_rule_file(filename)` - Load rules from file
- `print_rules()` - Print all rules

### `Xperm`

Extended permission structure for ioctl operations.

```rust
// Single ioctl command
Xperm::single(0x8910)

// Range of ioctl commands
Xperm::range(0x8910, 0x8926)

// Complement (all except range)
Xperm::complement(0x8910, 0x8926)

// All ioctl commands
Xperm::all()
```

## Current Limitations

- **Policy binary parsing requires libsepol** - This is the key limitation
- CIL parsing is not implemented
- Policy binary serialization requires libsepol
- `print_rules()` only shows in-memory rules, not loaded policy content without libsepol

## Integrating libsepol

To properly parse and manipulate real SELinux policies, you need to integrate libsepol. See the Magisk project's implementation for reference:

1. libsepol sources: `Magisk/native/src/external/selinux/libsepol/`
2. C++ wrapper: `Magisk/native/src/sepolicy/sepolicy.cpp`
3. Rust FFI: `Magisk/native/src/sepolicy/lib.rs`

## License

Apache-2.0
