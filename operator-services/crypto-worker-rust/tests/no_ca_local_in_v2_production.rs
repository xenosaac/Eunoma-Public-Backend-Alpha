// Codex M2a P1: privacy invariant test.
//
// The architectural rule is: `crate::ca_local` is unit/local-smoke fixture code ONLY.
// V2 production modules (`vault_ek_derivation_v2`, `ca_registration_v2`, `vault_state_v2`)
// MUST NOT import from `ca_local`. The public sigma verifier surface
// (`verify_registration_proof`, `registration_challenge_scalar`,
// `aggregate_registration_commitment`, the DTOs) was extracted out of `ca_local` into a
// new module `crate::registration_verifier` so V2 callers can depend on the same math
// without crossing the trusted-party namespace boundary.
//
// This test scans `src/lib.rs` and asserts that, within the body of each V2 production
// module, the substring `crate::ca_local` does not appear. We do this as a source-level
// regex check (a) because it's simple, (b) because the compiler doesn't expose "what does
// module X import?" reflectively at test time, and (c) because the rule we're enforcing
// IS a syntactic / textual rule: "no `use crate::ca_local::...` line in V2 production
// modules".
//
// Allowed exceptions:
//   - Doc comments referring to `ca_local` by name (e.g. "Codex M2a P1: this module MUST
//     NOT import from `crate::ca_local`"). Comments are stripped before the scan.
//   - `pub mod ca_local { ... }` itself.
//
// Modules audited (in source order):
//   1. `pub mod vault_ek_derivation_v2`
//   2. `pub mod ca_registration_v2`
//   3. `pub mod vault_state_v2`
//
// Adding a new V2 module that derives from CA state? Add its module-name to
// `V2_PRODUCTION_MODULES` below and the test will start enforcing the invariant on it.

use std::{fs, path::PathBuf};

const V2_PRODUCTION_MODULES: &[&str] = &[
    "vault_ek_derivation_v2",
    "ca_registration_v2",
    "vault_state_v2",
];

#[test]
fn v2_production_modules_do_not_import_ca_local() {
    let lib_path: PathBuf = env!("CARGO_MANIFEST_DIR").parse::<PathBuf>().unwrap().join("src/lib.rs");
    let source = fs::read_to_string(&lib_path).expect("read src/lib.rs");

    for module in V2_PRODUCTION_MODULES {
        let body = extract_module_body(&source, module)
            .unwrap_or_else(|| panic!("could not locate `pub mod {module}` in src/lib.rs"));
        let stripped = strip_comments(&body);
        if let Some(line_idx) = stripped
            .lines()
            .position(|line| line.contains("crate::ca_local") || line.contains("ca_local::"))
        {
            panic!(
                "[privacy invariant] V2 production module `{module}` imports from `ca_local` \
                 (line {} of module body):\n\
                 \n  {}\n\n\
                 V2 code must import the public verifier surface from `crate::registration_verifier` \
                 instead. `ca_local` is reserved for unit/local-smoke fixture code (see Codex M2a P1).",
                line_idx + 1,
                stripped.lines().nth(line_idx).unwrap_or("")
            );
        }
    }
}

/// Strip `//` line comments and `/* ... */` block comments from a chunk of Rust source.
/// We only need this to be good enough that doc comments in V2 module bodies that mention
/// `ca_local` by name aren't false positives.
fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '/' {
            match chars.peek() {
                Some('/') => {
                    // line comment: skip until newline (but keep the newline so the line
                    // index in the error message lines up roughly with the original)
                    chars.next();
                    for c in chars.by_ref() {
                        if c == '\n' {
                            out.push('\n');
                            break;
                        }
                    }
                }
                Some('*') => {
                    // block comment: skip until */
                    chars.next();
                    let mut prev = '\0';
                    while let Some(c) = chars.next() {
                        if prev == '*' && c == '/' {
                            break;
                        }
                        if c == '\n' {
                            out.push('\n');
                        }
                        prev = c;
                    }
                }
                _ => out.push(ch),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Extract the body of `pub mod <module_name> { ... }` (the text strictly between the
/// opening and closing braces, balanced). Returns `None` if the module is not found.
fn extract_module_body(src: &str, module_name: &str) -> Option<String> {
    let needle = format!("pub mod {module_name} {{");
    let start = src.find(&needle)?;
    let body_start = start + needle.len();
    let bytes = src.as_bytes();
    let mut depth: i32 = 1;
    let mut idx = body_start;
    while idx < bytes.len() && depth > 0 {
        match bytes[idx] {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
        idx += 1;
    }
    if depth != 0 {
        return None;
    }
    // body is bytes[body_start .. idx-1] (idx points past the closing brace)
    Some(String::from_utf8(bytes[body_start..idx - 1].to_vec()).ok()?)
}
