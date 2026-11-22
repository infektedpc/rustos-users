# rustos-users

User/group accounts, password hashing, Unix permissions and
capabilities, and login sessions for a Rust OS. Core + `alloc` only,
no external crates, `#![no_std]` outside tests — the same pattern as
`rustos-interrupts`.

## What it does

| Module | Job |
|---|---|
| `db` | `User` / `Group` accounts in a fixed-capacity in-memory `UserDb` (max 64 users, 32 groups, 16 supplementary groups per user). Add/remove/lookup by name and by uid/gid; duplicate name/uid/gid rejected; names validated (alphanumeric + `_-.`, max 32 chars); a user's primary and supplementary groups must exist; group member lists are kept in sync both ways. `UserDb::with_root()` seeds the conventional root user + `root` group. Root (uid 0) cannot be removed. |
| `password` | Password storage. **Never plaintext** — see the hash section below. |
| `sha256` | SHA-256 (FIPS 180-4) implemented from scratch in-repo, plus hex encode/decode. Verified against the standard test vectors (empty, `abc`, the 56-byte message, one million `a`s). |
| `perm` | Unix owner/group/other rwx checks (`can_read` / `can_write` / `can_execute` / `check_access`) against a file's `(owner uid, gid, mode)` and a caller's `Creds` (uid, gids, capabilities). Root bypasses rwx — except execute, which still needs at least one `x` bit set (the standard Unix rule). `Capability` enum (`Reboot`, `Mount`, `RawIo`, `ManageUsers`, `KillAny`, `Chown`, `NetBindService`, `SysAdmin`) held in an explicit `CapabilitySet` bitmask; `exec_credentials` computes the effective uid/gid from a file's setuid/setgid bits. |
| `session` | `Session` (logged-in user, uid/gids snapshot, login tick, terminal), `LoginManager::login` (verifies the password, returns a `Session`, records every attempt in a 64-entry in-memory audit ring — `AuditLog`, oldest overwritten, `failure_count()` counts login failures only), and `ProcessCreds` (real/effective/saved uid/gid with Unix `setuid`/`setgid`/`seteuid`/`setegid` rules and `drop_privileges`). |
| `serialize` | Line-based text format for persisting the database (see below). |

## Password hash — exact choice

Stored format, one string per user:

```text
sha256iter$<iterations>$<salt hex>$<digest hex>
```

* The digest is SHA-256 over `salt || password`, then the raw
  32-byte digest is re-hashed `iterations - 1` more times.
  Default iterations: **10,000** (`DEFAULT_ITERATIONS`).
* The salt is 16 bytes by convention (any 1–64 bytes accepted on
  parse), hex-encoded. **The salt must come from the caller** —
  this crate has no RNG; the kernel supplies entropy (timer /
  RDRAND). `Salt::randomish(seed)` is a deterministic test/demo
  helper only and must never be used for real accounts.
* Verification is constant-time over the digest, and a tampered
  salt or digest fails verification. A failed login never reveals
  whether the username or the password was wrong (both are
  `SessionError::BadPassword` to the caller; the audit log records
  the attempted username).
* Minimum password length is 8, maximum 256. There is no other
  password-strength policy.

**Limits, stated plainly:** this is a simple iterated hash, **not**
a memory-hard KDF such as Argon2 or scrypt, and it was chosen
because no hashing crate is available offline. It slows a
brute-force attack only by the iteration count. It should be
replaced by a real KDF before any password protects real data.

## Permission rules

* Owner class applies when the caller's uid equals the file owner's
  uid; otherwise the group class when any caller gid matches the
  file's gid; otherwise the other class. Owner wins over group even
  when the group class is wider.
* Root (uid 0) bypasses read/write checks; execute still requires
  at least one execute bit in the mode.
* **Capabilities are explicit**: root holds *no* capability
  implicitly. The kernel grants a `CapabilitySet` at login / exec
  time (e.g. root's login policy, or a setuid helper), and
  `Creds::has_capability` answers queries against it.
* `setuid`/`setgid`: root may set any id; a non-root process may set
  its effective id only to its real, effective, or saved id (so a
  setuid helper can drop to its real id and switch back via the
  saved id). `drop_privileges` permanently returns effective/saved
  ids to the real ids and clears capabilities.

## Serialisation format

One document, three sections (hashes live only in `[shadow]`,
never in the world-readable `[passwd]` part):

```text
# rustos-users v1
[passwd]
root:0:0:/root:/bin/sh
alice:1000:100:/home/alice:/bin/sh
[shadow]
alice:sha256iter$10000$...$...
[group]
root:0:
users:100:alice
wheel:101:alice
```

`to_text` / `from_text` round-trip the whole database;
`to_passwd` / `to_shadow` / `to_group` emit the sections
separately for callers that store them as separate files with
different permissions. Parsing is two-pass (groups, then users,
then hashes, then memberships), so section order in the file does
not matter; comments (`#…`) and blank lines are ignored, and any
malformed line, unknown section, duplicate entry, shadow entry for
an unknown user, or group member that does not exist rejects the
whole document — a corrupt file never loads partially.

## API sketch

```rust
use rustos_users::*;

let mut db = UserDb::with_root();
db.add_group(Group::new(100, "users"))?;
let mut alice = User::new(1000, "alice", 100, "/home/alice", "/bin/sh");
alice.set_password_hash(hash_password("correct horse", &Salt::randomish("alice"), DEFAULT_ITERATIONS)?);
db.add_user(alice)?;

let mut lm = LoginManager::new();
let session = lm.login(&db, "alice", "correct horse", tick, "tty0")?;
let creds = session.creds();
assert!(can_read(&creds, 1000, 100, 0o640));
assert!(!creds.has_capability(Capability::Reboot));

let text = to_text(&db);
let db2 = from_text(&text)?;
```

## Tests

Run `cargo test` (host, std). Covers: SHA-256 test vectors,
password verify accept/reject, tampered salt/hash rejection,
malformed stored-hash strings, account CRUD, duplicate name/uid/gid
rejection, bad names, unknown groups, group membership both ways,
the full permission matrix (owner vs group vs other, each rwx bit,
root bypass + root execute rule, capability checks, setuid/setgid
exec credentials), session login/logout, `setuid` rules (plain
process, setuid helper switching back via the saved id, permanent
`drop_privileges`), the audit ring wrapping at capacity, and
serialise/parse round-trips plus malformed-line rejection.

## Known limits / NOT verified

* **No live boot** — QEMU is not installed on this machine; host
  tests only. Nothing here has run inside the kernel.
* **No real login flow wired in yet** — the kernel and shell do not
  call `LoginManager`; sessions are structs a caller holds, and
  `logout` is only an audit event (there is no server-side session
  table to invalidate).
* **The hash is not a memory-hard KDF** — see the password section
  above. No password-strength policy beyond the 8-character minimum.
* **No entropy source** — salts must be supplied by the caller; the
  deterministic `Salt::randomish` helper is test-only.
* The audit log is in-memory only (64 entries, ring) and is lost on
  reboot; it is not persisted with the database.
* No `/etc/passwd` file I/O — persistence is the text format above,
  to be stored later via `rustos-fs`.
