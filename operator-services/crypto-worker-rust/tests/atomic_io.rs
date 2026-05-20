// Codex M3a P2 #2 v2: TOCTOU close-out for write_atomic_no_clobber.
//
// Background: the v1 helper did `path.exists() → tmp write → fs::rename`. Two writers
// observing `exists() == false` at the same moment both wrote tmp files and the later
// `rename` silently clobbered the earlier one. The "loser fails closed" contract was
// only enforced by the pre-rename existence check, which is by definition racy.
//
// Fix: replace the final `rename(2)` with `link(2)` (via std::fs::hard_link). `link(2)`
// is the canonical POSIX atomic create-only primitive — the kernel performs the
// "does target exist?" check and the directory entry insertion in a single critical
// section, so two concurrent writers cannot both succeed.
//
// These tests pin the contract:
//   1. First call: target does not exist → create + return Ok.
//   2. Idempotent replay (same bytes): no error, no rewrite (mtime preserved as much
//      as POSIX allows; we don't assert on mtime since unlink+link would update it).
//   3. Concurrent-second-writer with DIFFERENT bytes: must fail closed with
//      InvalidDkgState(<context>_already_exists_with_different_content).
//   4. Concurrent-second-writer with SAME bytes: succeeds (idempotent race winner).

use std::{fs, path::PathBuf, sync::Arc, thread};

use eunoma_crypto_worker::{atomic_io::write_atomic_no_clobber, WorkerError};

fn temp_dir(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    path.push(format!("eunoma-atomic-io-{label}-{nanos}"));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn write_atomic_no_clobber_creates_file_when_absent() {
    let dir = temp_dir("create");
    let target = dir.join("file.json");
    write_atomic_no_clobber(&target, b"hello", "test_ctx").expect("first write");
    let bytes = fs::read(&target).expect("read");
    assert_eq!(bytes, b"hello");
    // Mode 0o600 (POSIX only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    // No leftover tmp files.
    let leftovers: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|name| name.to_string_lossy().contains(".tmp."))
        .collect();
    assert!(leftovers.is_empty(), "tmp files leaked: {leftovers:?}");
}

#[test]
fn write_atomic_no_clobber_idempotent_replay_same_bytes() {
    let dir = temp_dir("idempotent");
    let target = dir.join("file.json");
    write_atomic_no_clobber(&target, b"same", "test_ctx").expect("first write");
    // Replay with identical bytes: return Ok, no error.
    write_atomic_no_clobber(&target, b"same", "test_ctx").expect("replay same");
    assert_eq!(fs::read(&target).unwrap(), b"same");
}

#[test]
fn write_atomic_no_clobber_rejects_different_bytes_when_target_exists() {
    let dir = temp_dir("different");
    let target = dir.join("file.json");
    write_atomic_no_clobber(&target, b"alpha", "ctx_a").expect("first write");
    // Second write with DIFFERENT bytes → fail closed.
    let err = write_atomic_no_clobber(&target, b"beta", "ctx_a")
        .expect_err("must reject second write with different bytes");
    assert!(
        matches!(err, WorkerError::InvalidDkgState(ref s) if s == "ctx_a_already_exists_with_different_content"),
        "expected InvalidDkgState(ctx_a_already_exists_with_different_content), got {err:?}"
    );
    // Target unchanged.
    assert_eq!(fs::read(&target).unwrap(), b"alpha");
}

/// KILLER TOCTOU test: two threads racing to write the SAME path with DIFFERENT bytes.
/// Exactly ONE thread must succeed (winning the link(2) race) and the OTHER must fail
/// closed with InvalidDkgState. With the v1 `path.exists() + rename` shape, BOTH would
/// succeed (and silently clobber); with the v2 `link(2)` shape, the kernel guarantees
/// only one inserts the directory entry.
#[test]
fn write_atomic_no_clobber_concurrent_writers_one_wins() {
    // Run the race many times to amortise scheduling noise.
    let mut winners_a = 0u32;
    let mut winners_b = 0u32;
    let mut errors_a = 0u32;
    let mut errors_b = 0u32;
    const ITERATIONS: usize = 32;
    for i in 0..ITERATIONS {
        let dir = temp_dir(&format!("race-{i}"));
        let target = Arc::new(dir.join("contested.json"));
        let target_a = Arc::clone(&target);
        let target_b = Arc::clone(&target);
        let handle_a = thread::spawn(move || {
            write_atomic_no_clobber(&target_a, b"alpha-content", "race_ctx")
        });
        let handle_b = thread::spawn(move || {
            write_atomic_no_clobber(&target_b, b"beta-content", "race_ctx")
        });
        let ra = handle_a.join().expect("thread a panic");
        let rb = handle_b.join().expect("thread b panic");

        // KILLER: exactly one of (ra, rb) is Ok; the OTHER MUST be
        // InvalidDkgState(race_ctx_already_exists_with_different_content).
        let final_bytes = fs::read(&*target).expect("read final");
        match (&ra, &rb) {
            (Ok(()), Err(WorkerError::InvalidDkgState(s))) => {
                assert_eq!(s, "race_ctx_already_exists_with_different_content");
                assert_eq!(final_bytes, b"alpha-content", "winner A but content mismatched");
                winners_a += 1;
                errors_b += 1;
            }
            (Err(WorkerError::InvalidDkgState(s)), Ok(())) => {
                assert_eq!(s, "race_ctx_already_exists_with_different_content");
                assert_eq!(final_bytes, b"beta-content", "winner B but content mismatched");
                winners_b += 1;
                errors_a += 1;
            }
            (Ok(()), Ok(())) => panic!(
                "BOTH writers reported success — TOCTOU race was NOT closed. Final content: \
                 {:?}",
                String::from_utf8_lossy(&final_bytes)
            ),
            (Err(a), Err(b)) => panic!("both writers failed: a={a:?} b={b:?}"),
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert_eq!(
        winners_a + winners_b,
        ITERATIONS as u32,
        "every iteration must have exactly one winner"
    );
    assert_eq!(
        errors_a + errors_b,
        ITERATIONS as u32,
        "every iteration must have exactly one fail-closed loser"
    );
    // Sanity: both sides should win at least some races (else the test is flaky-but-passing
    // for the wrong reason). With 32 iterations across two threads, demanding at least 1
    // win each is generous.
    assert!(winners_a >= 1, "thread A never won any race ({winners_a}); scheduling is suspect");
    assert!(winners_b >= 1, "thread B never won any race ({winners_b}); scheduling is suspect");
}

/// Concurrent writers with SAME bytes: both should succeed (race winner's content
/// matches what the loser wanted to write, so idempotent replay).
#[test]
fn write_atomic_no_clobber_concurrent_same_bytes_both_succeed() {
    for i in 0..16 {
        let dir = temp_dir(&format!("same-race-{i}"));
        let target = Arc::new(dir.join("same.json"));
        let target_a = Arc::clone(&target);
        let target_b = Arc::clone(&target);
        let handle_a = thread::spawn(move || {
            write_atomic_no_clobber(&target_a, b"identical", "same_ctx")
        });
        let handle_b = thread::spawn(move || {
            write_atomic_no_clobber(&target_b, b"identical", "same_ctx")
        });
        let ra = handle_a.join().expect("thread a panic");
        let rb = handle_b.join().expect("thread b panic");
        assert!(ra.is_ok(), "thread a: {ra:?}");
        assert!(rb.is_ok(), "thread b: {rb:?}");
        assert_eq!(fs::read(&*target).unwrap(), b"identical");
    }
}
