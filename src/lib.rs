//! rustos-users — user/group accounts, password hashing, Unix
//! permissions and capabilities, and login sessions for a Rust OS.
//!
//! * [`db`] — [`User`][db::User] / [`Group`][db::Group] accounts in a
//!   fixed-capacity in-memory [`UserDb`][db::UserDb].
//! * [`password`] — salted iterated SHA-256 password storage
//!   (`sha256iter$<iters>$<salt hex>$<digest hex>`), SHA-256 itself
//!   implemented from scratch in [`sha256`]. No plaintext passwords
//!   are ever stored.
//! * [`perm`] — Unix owner/group/other rwx checks
//!   ([`can_read`][perm::can_read] / [`can_write`][perm::can_write] /
//!   [`can_execute`][perm::can_execute]), the explicit
//!   [`Capability`][perm::Capability] set for privileged operations,
//!   and setuid/setgid exec credentials.
//! * [`session`] — [`Session`][session::Session] login state,
//!   [`ProcessCreds`][session::ProcessCreds] (real/effective/saved
//!   uid/gid with `setuid`/`setgid` semantics and privilege
//!   dropping), and [`LoginManager`][session::LoginManager] with an
//!   in-memory audit ring.
//! * [`serialize`] — line-based passwd/shadow/group text format for
//!   persisting the database through `rustos-fs` later.
//!
//! The crate is `#![no_std]` outside tests so it can link into a
//! kernel. Tests run on the host with std. No external crates.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod db;
pub mod password;
pub mod perm;
pub mod serialize;
pub mod session;
pub mod sha256;

pub use db::{DbError, Group, User, UserDb, MAX_GROUPS, MAX_USERS};
pub use password::{
    hash_password, verify_password, PasswordError, Salt, DEFAULT_ITERATIONS,
    MAX_PASSWORD_LEN, MIN_PASSWORD_LEN,
};
pub use perm::{
    can_execute, can_read, can_write, check_access, exec_credentials, Access,
    Capability, CapabilitySet, Creds, MODE_GROUP_EXEC, MODE_GROUP_READ,
    MODE_GROUP_WRITE, MODE_OTHER_EXEC, MODE_OTHER_READ, MODE_OTHER_WRITE,
    MODE_OWNER_EXEC, MODE_OWNER_READ, MODE_OWNER_WRITE, MODE_RWX_MASK,
    MODE_SETGID, MODE_SETUID, MODE_STICKY,
};
pub use serialize::{from_text, to_group, to_passwd, to_shadow, to_text, ParseError};
pub use session::{
    AuditEntry, AuditKind, AuditLog, LoginManager, ProcessCreds, Session, SessionError,
    MAX_AUDIT_ENTRIES,
};
pub use sha256::sha256;
