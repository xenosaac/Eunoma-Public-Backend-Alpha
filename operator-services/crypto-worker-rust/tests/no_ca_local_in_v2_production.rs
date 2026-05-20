// Codex M2a P1 + M3a P3 residual: privacy invariant test.
//
// THE ARCHITECTURAL RULE
// ----------------------
// `crate::ca_local` is unit/local-smoke fixture code ONLY. V2 production modules
// (anything named `<thing>_v2`) MUST NOT import from `ca_local` in any form. The public
// sigma verifier surface (`verify_registration_proof`, `registration_challenge_scalar`,
// `aggregate_registration_commitment`, the DTOs) was extracted out of `ca_local` into
// `crate::registration_verifier` so V2 callers can depend on the same math without
// crossing the trusted-party namespace boundary.
//
// AUTO-DISCOVERY (M3a P3 residual fix)
// ------------------------------------
// The previous version of this test hardcoded a `V2_PRODUCTION_MODULES = &[...]` list. A
// new V2 module added without updating the list would have silently bypassed the
// invariant. This version auto-discovers V2 production modules by scanning `src/lib.rs`:
//
//   Discovery rule: any top-level `pub mod <name> { ... }` whose name ends with `_v2`
//   IS a V2 production module, EXCEPT for modules whose name contains `ca_local` (defensive
//   carve-out; there is no such module today, but the carve-out makes the rule total).
//
// We chose "name ends in `_v2`" over "body contains the substring `v2`" because the latter
// is too noisy: nearly every module in the crate calls `assert_v2_threshold` or references
// V2 file paths in comments, which would force every module to be audited. The `_v2`
// suffix is the actual naming convention used by the V2 production code paths
// (`ca_dkg_v2`, `vault_ek_derivation_v2`, `ca_registration_v2`, `vault_state_v2`,
// `mpcca_withdraw_v2`, `frost_dkg_v2`), so the suffix rule is both unambiguous and
// resistant to renames that don't update the suffix.
//
// Regression guard: a separate test asserts that auto-discovery still finds AT LEAST the
// modules that were on the previous hardcoded list. If someone renames or deletes a V2
// module without keeping the convention, the regression guard fails before the discovery
// rule silently shrinks.
//
// ALIAS-BYPASS RESISTANCE (M3a P3 residual fix)
// ---------------------------------------------
// The previous detector only looked for `crate::ca_local` and `ca_local::`. That misses:
//
//   use crate::ca_local as cl;           // <-- caught: contains `crate::ca_local`
//   use crate::{ca_local as cl};          // <-- MISSED: substring is `crate::{ca_local`
//   use crate::{ca_local::foo, bar};      // <-- MISSED: contains `ca_local::` though, OK
//   pub use crate::ca_local::*;           // <-- caught: contains `crate::ca_local`
//   use crate::ca_local::{a, b};          // <-- caught
//
// The hardened detector flags ANY bare substring `ca_local` anywhere in a V2 module body
// (after stripping comments). This is intentionally aggressive: a V2 module has no
// legitimate reason to mention `ca_local` by name in code. If a doc comment needs to
// reference it (e.g., "see ca_local for the V1 path"), the comment-stripping pass will
// remove the reference before the scan.
//
// Allowed exceptions:
//   - Doc comments / line comments / block comments referring to `ca_local` by name.
//   - The `ca_local` module's own definition (which is not a V2 module and is therefore
//     never scanned).
//
// COUNTER-EXAMPLE TEST
// --------------------
// A second `#[test]` synthesizes a mutated copy of `lib.rs` with an injected
// `use crate::ca_local as cl;` line in `mpcca_withdraw_v2` and asserts the detector
// catches it. This proves the invariant is not a no-op and that the alias bypass is
// blocked.

use std::{collections::BTreeSet, fs, path::PathBuf};

/// Real-source invariant: every auto-discovered V2 production module is free of any
/// `ca_local` reference (direct path, qualified path, or aliased re-export).
#[test]
fn v2_production_modules_do_not_import_ca_local() {
    let lib_path = lib_rs_path();
    let source = fs::read_to_string(&lib_path).expect("read src/lib.rs");

    let modules = discover_v2_production_modules(&source);
    assert!(
        !modules.is_empty(),
        "auto-discovery returned zero V2 production modules — discovery rule is broken \
         (looked for top-level `pub mod <name>_v2 {{` in src/lib.rs)"
    );

    if let Err(violation) = scan_for_ca_local_violations(&source, &modules) {
        panic!("{}", violation.message());
    }
}

/// Regression guard: auto-discovery must always find AT LEAST the modules that were on
/// the previous hardcoded list. If this fails, either (a) someone renamed/removed a V2
/// module without keeping the `_v2` suffix, in which case the convention is broken and
/// needs to be re-anchored, or (b) someone deleted a V2 module, in which case this guard
/// needs to be relaxed in the same commit.
#[test]
fn auto_discovery_finds_known_v2_modules() {
    let source = fs::read_to_string(lib_rs_path()).expect("read src/lib.rs");
    let discovered: BTreeSet<&str> = discover_v2_production_modules(&source)
        .iter()
        .map(|m| m.name)
        .collect();

    // Anchors: every module on the original hardcoded list. If any of these stop being
    // discovered, the suffix convention has broken and we need to know.
    const KNOWN_V2_MODULES: &[&str] = &[
        "vault_ek_derivation_v2",
        "ca_registration_v2",
        "vault_state_v2",
        "mpcca_withdraw_v2",
    ];

    for known in KNOWN_V2_MODULES {
        assert!(
            discovered.contains(known),
            "regression guard: V2 production module `{known}` was on the previous hardcoded \
             list but is not being auto-discovered. discovered = {discovered:?}.\n\n\
             Either the module was renamed without keeping the `_v2` suffix (fix the name \
             or update the discovery rule) or it was deleted (relax this guard)."
        );
    }
}

/// Counter-example: synthesize a mutated copy of `lib.rs` that injects an aliased import
/// of `ca_local` into a V2 module body, and assert the detector catches it. This proves
/// the invariant is not vacuous and that the alias bypass is closed.
#[test]
fn detector_catches_aliased_ca_local_import() {
    let source = fs::read_to_string(lib_rs_path()).expect("read src/lib.rs");

    // Inject `use crate::{ca_local as cl};` (the previously-uncaught bypass form) into
    // the body of `pub mod mpcca_withdraw_v2 { ... }`. We insert immediately after the
    // opening brace so it lands inside the module.
    let target = "pub mod mpcca_withdraw_v2 {";
    let insert_at = source
        .find(target)
        .expect("test fixture: lib.rs must contain mpcca_withdraw_v2")
        + target.len();
    let mut mutated = String::with_capacity(source.len() + 64);
    mutated.push_str(&source[..insert_at]);
    mutated.push_str("\n    use crate::{ca_local as cl};\n");
    mutated.push_str(&source[insert_at..]);

    let modules = discover_v2_production_modules(&mutated);
    let result = scan_for_ca_local_violations(&mutated, &modules);
    let violation = result.expect_err(
        "counter-example test: the detector must flag an aliased ca_local import in a V2 \
         module, but it returned OK. This means the alias bypass is back.",
    );
    assert_eq!(violation.module, "mpcca_withdraw_v2");
    assert!(
        violation.offending_line.contains("ca_local"),
        "violation should quote the offending line, got: {:?}",
        violation.offending_line
    );
}

/// Counter-example #2: a direct `use crate::ca_local::...` import is also caught. This
/// is the classic, non-aliased form — same code path, different surface.
#[test]
fn detector_catches_direct_ca_local_import() {
    let source = fs::read_to_string(lib_rs_path()).expect("read src/lib.rs");
    let target = "pub mod vault_state_v2 {";
    let insert_at = source
        .find(target)
        .expect("test fixture: lib.rs must contain vault_state_v2")
        + target.len();
    let mut mutated = String::with_capacity(source.len() + 64);
    mutated.push_str(&source[..insert_at]);
    mutated.push_str("\n    use crate::ca_local::verify_registration_proof;\n");
    mutated.push_str(&source[insert_at..]);

    let modules = discover_v2_production_modules(&mutated);
    let violation = scan_for_ca_local_violations(&mutated, &modules)
        .expect_err("direct ca_local import in a V2 module must be flagged");
    assert_eq!(violation.module, "vault_state_v2");
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn lib_rs_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")
}

/// A V2 production module discovered in the source.
struct V2Module<'a> {
    name: &'a str,
    /// The raw text of the module body (between the matched `{` and its balancing `}`).
    body: String,
}

/// A detected invariant violation.
struct Violation {
    module: String,
    line_idx: usize,
    offending_line: String,
}

impl Violation {
    fn message(&self) -> String {
        format!(
            "[privacy invariant] V2 production module `{module}` references `ca_local` \
             (line {line} of module body):\n\
             \n  {line_text}\n\n\
             V2 code must import the public verifier surface from \
             `crate::registration_verifier` instead. `ca_local` is reserved for \
             unit/local-smoke fixture code (see Codex M2a P1).\n\n\
             This includes aliased imports like `use crate::{{ca_local as cl}};` — the \
             detector scans for any bare `ca_local` substring in module bodies (after \
             comment stripping).",
            module = self.module,
            line = self.line_idx + 1,
            line_text = self.offending_line
        )
    }
}

/// Auto-discover every top-level `pub mod <name> { ... }` whose name ends with `_v2`.
/// Modules whose name contains `ca_local` are skipped (defensive; no such module exists
/// today).
fn discover_v2_production_modules(source: &str) -> Vec<V2Module<'_>> {
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    // We scan only top-level `pub mod` declarations. The current `lib.rs` has all `pub
    // mod` declarations at top level (verified at commit time); if a future refactor
    // moves them into a wrapper, the `auto_discovery_finds_known_v2_modules` regression
    // guard will fail and force this scanner to be updated.
    //
    // Match a line that starts with `pub mod ` (column 0, no indentation), captures the
    // ident, and is immediately followed by ` {`. Inline `pub mod foo;` declarations
    // (file modules) are intentionally skipped — they're not v2 production modules.
    let mut idx = 0;
    while idx < source.len() {
        let Some(rel) = source[idx..].find("\npub mod ") else {
            break;
        };
        let line_start = idx + rel + 1;
        // Parse the module name: from `line_start + "pub mod ".len()` to the next space.
        let header_start = line_start + "pub mod ".len();
        let mut name_end = header_start;
        while name_end < source.len() {
            let b = bytes[name_end];
            if !(b.is_ascii_alphanumeric() || b == b'_') {
                break;
            }
            name_end += 1;
        }
        let name = &source[header_start..name_end];
        idx = name_end;
        // Skip if the next non-whitespace isn't `{` (e.g., `pub mod foo;` or `pub mod
        // foo as bar`).
        let mut probe = name_end;
        while probe < source.len() && (bytes[probe] == b' ' || bytes[probe] == b'\t') {
            probe += 1;
        }
        if probe >= source.len() || bytes[probe] != b'{' {
            continue;
        }
        // Discovery filter: name ends with `_v2` AND does not contain `ca_local`.
        if !name.ends_with("_v2") || name.contains("ca_local") {
            continue;
        }
        // Brace-balance to find the closing `}`.
        let body_start = probe + 1;
        let mut depth: i32 = 1;
        let mut cursor = body_start;
        while cursor < bytes.len() && depth > 0 {
            match bytes[cursor] {
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            }
            cursor += 1;
        }
        if depth != 0 {
            // Unbalanced — leave it; the test will report "discovered 0 modules" if this
            // breaks discovery entirely.
            continue;
        }
        let body = strip_comments(&source[body_start..cursor - 1]);
        out.push(V2Module { name, body });
        idx = cursor;
    }
    out
}

/// Scan each V2 module body for any `ca_local` reference. Returns the first violation
/// found, or `Ok(())` if all modules are clean.
fn scan_for_ca_local_violations<'a>(
    _source: &'a str,
    modules: &'a [V2Module<'a>],
) -> Result<(), Violation> {
    for module in modules {
        // Aggressive substring match: any literal `ca_local` in the comment-stripped body
        // is a violation. This catches:
        //   - `use crate::ca_local::*;`
        //   - `use crate::ca_local::{a, b};`
        //   - `use crate::ca_local as cl;`
        //   - `use crate::{ca_local as cl};`        <-- previously missed
        //   - `use crate::{ca_local::foo, bar};`
        //   - bare `ca_local::function(...)` calls
        //   - `pub use crate::ca_local::...`
        //
        // False-positive risk: a local variable or type named `ca_local_something` would
        // also trigger. That's acceptable: a V2 module should not be using that name
        // either; if it does, the code is mislabeled.
        if let Some((line_idx, line)) = module
            .body
            .lines()
            .enumerate()
            .find(|(_, line)| line.contains("ca_local"))
        {
            return Err(Violation {
                module: module.name.to_string(),
                line_idx,
                offending_line: line.trim().to_string(),
            });
        }
    }
    Ok(())
}

/// Strip `//` line comments and `/* ... */` block comments from a chunk of Rust source.
/// Good enough that doc comments in V2 module bodies that mention `ca_local` by name
/// (e.g., "this module MUST NOT import from ca_local") aren't false positives.
fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '/' {
            match chars.peek() {
                Some('/') => {
                    chars.next();
                    for c in chars.by_ref() {
                        if c == '\n' {
                            out.push('\n');
                            break;
                        }
                    }
                }
                Some('*') => {
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
