use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;

fn has_reallocarray(build: &cc::Build, out_dir: &Path) -> bool {
    let src = out_dir.join("reallocarray_probe.c");
    let obj = out_dir.join("reallocarray_probe.o");
    let source = r#"
#include <stddef.h>
#include <stdlib.h>
#include <malloc.h>

int main(void) { return reallocarray(NULL, 0, 0) == NULL; }
"#;

    if fs::write(&src, source).is_err() {
        return false;
    }

    let mut cmd = build.get_compiler().to_command();
    cmd.arg(&src)
        .arg("-c")
        .arg("-o")
        .arg(&obj)
        .arg("-Werror=implicit-function-declaration")
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let ok = matches!(cmd.status(), Ok(status) if status.success());
    let _ = fs::remove_file(&src);
    let _ = fs::remove_file(&obj);
    ok
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // Check if we're building for Android
    let target = env::var("TARGET").unwrap();
    let is_android = target.contains("android");

    // Path to libsepol source
    let sepol_src = manifest_dir.join("libsepol");
    let sepol_include = sepol_src.join("include");
    let sepol_cil_include = sepol_src.join("cil").join("include");

    if sepol_src.exists() {
        println!("cargo:rustc-cfg=feature=\"sepol_linked\"");
        println!("cargo:rustc-link-search=native={}", out_dir.display());

        // Compile libsepol C files
        let mut build = cc::Build::new();

        // Include paths
        build
            .include(&sepol_include)
            .include(&sepol_cil_include)
            .include(sepol_src.join("src"));

        let have_reallocarray = has_reallocarray(&build, &out_dir);
        if have_reallocarray {
            build.define("HAVE_REALLOCARRAY", None);
        }

        // Source files from libsepol/src
        let src_files = [
            "assertion.c",
            "avrule_block.c",
            "avtab.c",
            "boolean_record.c",
            "booleans.c",
            "conditional.c",
            "constraint.c",
            "context.c",
            "context_record.c",
            "debug.c",
            "ebitmap.c",
            "expand.c",
            "handle.c",
            "hashtab.c",
            "hierarchy.c",
            "ibendport_record.c",
            "ibendports.c",
            "ibpkey_record.c",
            "ibpkeys.c",
            "iface_record.c",
            "interfaces.c",
            "kernel_to_cil.c",
            "kernel_to_common.c",
            "kernel_to_conf.c",
            "link.c",
            "mls.c",
            "module.c",
            "module_to_cil.c",
            "node_record.c",
            "nodes.c",
            "polcaps.c",
            "policydb.c",
            "policydb_convert.c",
            "policydb_public.c",
            "policydb_validate.c",
            "port_record.c",
            "ports.c",
            "services.c",
            "sidtab.c",
            "symtab.c",
            "user_record.c",
            "users.c",
            "util.c",
            "write.c",
        ];

        for src in &src_files {
            let src_path = sepol_src.join("src").join(src);
            if src_path.exists() {
                build.file(&src_path);
            }
        }

        // CIL source files
        let cil_files = [
            "cil.c",
            "cil_binary.c",
            "cil_build_ast.c",
            "cil_copy_ast.c",
            "cil_deny.c",
            "cil_find.c",
            "cil_fqn.c",
            "cil_lexer.c",
            "cil_list.c",
            "cil_log.c",
            "cil_mem.c",
            "cil_parser.c",
            "cil_policy.c",
            "cil_post.c",
            "cil_reset_ast.c",
            "cil_resolve_ast.c",
            "cil_stack.c",
            "cil_strpool.c",
            "cil_symtab.c",
            "cil_tree.c",
            "cil_verify.c",
            "cil_write_ast.c",
        ];

        for src in &cil_files {
            let src_path = sepol_src.join("cil").join("src").join(src);
            if src_path.exists() {
                build.file(&src_path);
            }
        }

        build.file("c/sepol_shim.c");

        // Compile
        build.compile("sepol");

        // Compile compatibility functions when reallocarray is not available
        let mut compat_build = cc::Build::new();
        compat_build
            .file("c/compat.c")
            .include(&sepol_include);
        if have_reallocarray {
            compat_build.define("HAVE_REALLOCARRAY", None);
        }
        compat_build.compile("compat");

        println!("cargo:rustc-link-lib=static=sepol");
        println!("cargo:rustc-link-lib=static=compat");

        // Link math library on Unix
        if !is_android && env::var("CARGO_CFG_TARGET_OS").unwrap() != "windows" {
            println!("cargo:rustc-link-lib=m");
        }

    } else {
        println!("cargo:warning=libsepol source not found, using stub implementation");
        println!("cargo:warning=print_rules() will only show rules added via the API");
        println!("cargo:rustc-cfg=feature=\"sepol_stub\"");
    }

    // Tell cargo to invalidate the build when files change
    println!("cargo:rerun-if-changed=c/compat.c");
    println!("cargo:rerun-if-changed=c/sepol_shim.c");
    println!("cargo:rerun-if-changed=src/sepol.rs");
    println!("cargo:rerun-if-changed=src/sepol_impl.rs");
    println!("cargo:rerun-if-changed=build.rs");
}
