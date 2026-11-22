//! Login sessions and per-process credentials.
//!
//! A [`Session`] is a logged-in user on a terminal: it snapshots the
//! uid/gids at login time. A [`ProcessCreds`] is the per-process
//! real/effective/saved uid/gid triple with Unix `setuid`/`setgid`
//! semantics and privilege dropping. [`LoginManager`] ties them
//! together: it verifies passwords against the [`UserDb`] and keeps
//! an in-memory ring of login attempts ([`AuditLog`]).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::db::{User, UserDb};
use crate::password::{verify_password, PasswordError};
use crate::perm::{CapabilitySet, Creds};

/// Maximum audit entries kept (ring buffer).
pub const MAX_AUDIT_ENTRIES: usize = 64;

/// Errors from login / credential operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// No such user.
    UnknownUser,
    /// The account has no password set (locked).
    NoPassword,
    /// The password did not match.
    BadPassword,
    /// The stored hash is malformed (corrupt database entry).
    MalformedHash(PasswordError),
    /// `setuid`/`setgid` to a uid/gid the process is not allowed to
    /// assume (only root may pick an arbitrary id; anyone else may
    /// only switch between their real, effective, and saved ids).
    NotPermitted,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::UnknownUser => write!(f, "unknown user"),
            SessionError::NoPassword => write!(f, "account has no password"),
            SessionError::BadPassword => write!(f, "bad password"),
            SessionError::MalformedHash(e) => write!(f, "malformed stored hash: {e}"),
            SessionError::NotPermitted => write!(f, "operation not permitted"),
        }
    }
}

/// A logged-in user on a terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Login name.
    pub username: String,
    /// User id.
    pub uid: u32,
    /// Primary gid.
    pub gid: u32,
    /// All gids (primary + supplementary) snapshotted at login.
    pub groups: Vec<u32>,
    /// Kernel tick at login time (the caller supplies the clock).
    pub login_tick: u64,
    /// Terminal the session is attached to, e.g. `"tty0"`.
    pub terminal: String,
}

impl Session {
    /// The [`Creds`] this session confers (no capabilities — the
    /// caller grants capabilities explicitly, e.g. root's login
    /// policy).
    pub fn creds(&self) -> Creds {
        Creds::for_user(self.uid, self.gid, &self.groups)
    }

    /// The [`Creds`] this session confers with an explicit
    /// capability set.
    pub fn creds_with_caps(&self, caps: CapabilitySet) -> Creds {
        let mut c = self.creds();
        c.caps = caps;
        c
    }
}

/// Per-process credentials: real / effective / saved uid and gid,
/// with Unix `setuid`/`setgid` semantics.
///
/// * Root (euid 0) may set any of the three ids to any value.
/// * A non-root process may set its effective id only to its real,
///   effective, or saved id.
/// * [`ProcessCreds::drop_privileges`] permanently drops back to the
///   real ids and clears the saved ids and capabilities — the way a
///   setuid helper gives its privileges back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessCreds {
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
    /// Capabilities held by this process (cleared by
    /// [`drop_privileges`](Self::drop_privileges)).
    pub caps: CapabilitySet,
}

impl ProcessCreds {
    /// Fresh credentials for a process owned by `user`: all three
    /// ids equal the user's real ids, no capabilities.
    pub fn for_user(user: &User) -> Self {
        ProcessCreds {
            ruid: user.uid,
            euid: user.uid,
            suid: user.uid,
            rgid: user.gid,
            egid: user.gid,
            sgid: user.gid,
            caps: CapabilitySet::empty(),
        }
    }

    /// Credentials as they look after `exec` of a file: the real ids
    /// stay the caller's, the effective ids come from the file's
    /// setuid/setgid bits, and the saved ids remember the effective
    /// ids (so the process can switch back).
    pub fn after_exec(
        caller: &ProcessCreds,
        euid: u32,
        egid: u32,
        caps: CapabilitySet,
    ) -> Self {
        ProcessCreds {
            ruid: caller.ruid,
            euid,
            suid: euid,
            rgid: caller.rgid,
            egid,
            sgid: egid,
            caps,
        }
    }

    /// Unix `setuid(uid)`.
    pub fn setuid(&mut self, uid: u32) -> Result<(), SessionError> {
        if self.euid == 0 {
            self.ruid = uid;
            self.euid = uid;
            self.suid = uid;
            Ok(())
        } else if uid == self.ruid || uid == self.euid || uid == self.suid {
            self.euid = uid;
            Ok(())
        } else {
            Err(SessionError::NotPermitted)
        }
    }

    /// Unix `setgid(gid)`.
    pub fn setgid(&mut self, gid: u32) -> Result<(), SessionError> {
        if self.euid == 0 {
            self.rgid = gid;
            self.egid = gid;
            self.sgid = gid;
            Ok(())
        } else if gid == self.rgid || gid == self.egid || gid == self.sgid {
            self.egid = gid;
            Ok(())
        } else {
            Err(SessionError::NotPermitted)
        }
    }

    /// Unix `seteuid(uid)`: effective id only, same rules as
    /// `setuid` minus the root "set all three" behaviour.
    pub fn seteuid(&mut self, uid: u32) -> Result<(), SessionError> {
        if self.euid == 0 || uid == self.ruid || uid == self.euid || uid == self.suid {
            self.euid = uid;
            Ok(())
        } else {
            Err(SessionError::NotPermitted)
        }
    }

    /// Unix `setegid(gid)`.
    pub fn setegid(&mut self, gid: u32) -> Result<(), SessionError> {
        if self.euid == 0 || gid == self.rgid || gid == self.egid || gid == self.sgid {
            self.egid = gid;
            Ok(())
        } else {
            Err(SessionError::NotPermitted)
        }
    }

    /// Drop all privilege: effective and saved ids return to the
    /// real ids, and capabilities are cleared. After this call the
    /// process can never regain the dropped ids.
    pub fn drop_privileges(&mut self) {
        self.euid = self.ruid;
        self.suid = self.ruid;
        self.egid = self.rgid;
        self.sgid = self.rgid;
        self.caps = CapabilitySet::empty();
    }

    /// The [`Creds`] view of the effective identity, for permission
    /// checks. Supplementary groups are not tracked here — the
    /// caller supplies them (e.g. from the [`Session`]).
    pub fn effective_creds(&self, groups: &[u32]) -> Creds {
        Creds {
            uid: self.euid,
            gid: self.egid,
            groups: groups.to_vec(),
            caps: self.caps,
        }
    }
}

/// One login attempt, kept for auditing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub kind: AuditKind,
    pub username: String,
    pub terminal: String,
    pub tick: u64,
    /// For logins: whether authentication succeeded. Always `true`
    /// for logouts.
    pub success: bool,
}

/// What kind of audit event this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditKind {
    Login,
    Logout,
}

/// Fixed-capacity ring of login attempts (oldest overwritten).
#[derive(Debug, Clone)]
pub struct AuditLog {
    entries: [Option<AuditEntry>; MAX_AUDIT_ENTRIES],
    next: usize,
    len: usize,
}

impl Default for AuditLog {
    fn default() -> Self {
        AuditLog {
            entries: core::array::from_fn(|_| None),
            next: 0,
            len: 0,
        }
    }
}

impl AuditLog {
    pub fn new() -> Self {
        AuditLog::default()
    }

    pub fn record(&mut self, entry: AuditEntry) {
        self.entries[self.next] = Some(entry);
        self.next = (self.next + 1) % MAX_AUDIT_ENTRIES;
        if self.len < MAX_AUDIT_ENTRIES {
            self.len += 1;
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Entries oldest-first.
    pub fn entries(&self) -> Vec<&AuditEntry> {
        let mut out = Vec::with_capacity(self.len);
        for i in 0..self.len {
            let idx = (self.next + MAX_AUDIT_ENTRIES - self.len + i) % MAX_AUDIT_ENTRIES;
            if let Some(e) = &self.entries[idx] {
                out.push(e);
            }
        }
        out
    }

    /// Number of failed login attempts recorded (logouts never count).
    pub fn failure_count(&self) -> usize {
        self.entries()
            .iter()
            .filter(|e| e.kind == AuditKind::Login && !e.success)
            .count()
    }
}

/// Authenticates users against a [`UserDb`] and keeps the audit log.
#[derive(Debug, Default)]
pub struct LoginManager {
    audit: AuditLog,
}

impl LoginManager {
    pub fn new() -> Self {
        LoginManager::default()
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    /// Verify `password` for `username` and, on success, return a
    /// [`Session`] snapshotted at `tick` on `terminal`. Every
    /// attempt — success or failure — is recorded in the audit log.
    /// A failed login never reveals whether the username or the
    /// password was wrong: both are `SessionError::BadPassword` to
    /// the caller (the audit log records the attempted username).
    pub fn login(
        &mut self,
        db: &UserDb,
        username: &str,
        password: &str,
        tick: u64,
        terminal: &str,
    ) -> Result<Session, SessionError> {
        let result = self.login_inner(db, username, password, tick, terminal);
        let success = result.is_ok();
        self.audit.record(AuditEntry {
            kind: AuditKind::Login,
            username: username.into(),
            terminal: terminal.into(),
            tick,
            success,
        });
        result
    }

    fn login_inner(
        &self,
        db: &UserDb,
        username: &str,
        password: &str,
        tick: u64,
        terminal: &str,
    ) -> Result<Session, SessionError> {
        let user = db.find_user_by_name(username).ok_or(SessionError::BadPassword)?;
        let stored = user.password_hash.as_ref().ok_or(SessionError::NoPassword)?;
        let ok = verify_password(password, stored).map_err(SessionError::MalformedHash)?;
        if !ok {
            return Err(SessionError::BadPassword);
        }
        Ok(Session {
            username: user.username.clone(),
            uid: user.uid,
            gid: user.gid,
            groups: user.all_gids(),
            login_tick: tick,
            terminal: terminal.into(),
        })
    }

    /// End a session. (There is no server-side session table — a
    /// session is just the struct the shell holds — so logout is
    /// only an audit event.)
    pub fn logout(&mut self, session: &Session, tick: u64) {
        self.audit.record(AuditEntry {
            kind: AuditKind::Logout,
            username: session.username.clone(),
            terminal: session.terminal.clone(),
            tick,
            success: true,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{Group, UserDb};
    use crate::password::{hash_password, Salt};
    use crate::perm::Capability;

    fn db_with_alice() -> UserDb {
        let mut db = UserDb::with_root();
        db.add_group(Group::new(100, "users")).unwrap();
        let mut alice = User::new(1000, "alice", 100, "/home/alice", "/bin/sh");
        let stored = hash_password("correct horse", &Salt::from_bytes(b"alice-salt-16byt").unwrap(), 100)
            .unwrap();
        alice.set_password_hash(stored);
        db.add_user(alice).unwrap();
        db
    }

    #[test]
    fn login_success_returns_session_snapshot() {
        let db = db_with_alice();
        let mut lm = LoginManager::new();
        let s = lm.login(&db, "alice", "correct horse", 42, "tty0").unwrap();
        assert_eq!(s.username, "alice");
        assert_eq!(s.uid, 1000);
        assert_eq!(s.gid, 100);
        assert_eq!(s.login_tick, 42);
        assert_eq!(s.terminal, "tty0");
        assert_eq!(lm.audit().len(), 1);
        assert_eq!(lm.audit().failure_count(), 0);
    }

    #[test]
    fn login_wrong_password_and_unknown_user_fail() {
        let db = db_with_alice();
        let mut lm = LoginManager::new();
        assert_eq!(
            lm.login(&db, "alice", "wrong password", 1, "tty0"),
            Err(SessionError::BadPassword)
        );
        assert_eq!(
            lm.login(&db, "nobody", "whatever123", 2, "tty0"),
            Err(SessionError::BadPassword)
        );
        assert_eq!(lm.audit().len(), 2);
        assert_eq!(lm.audit().failure_count(), 2);
        // Audit records the attempted username even on failure.
        assert_eq!(lm.audit().entries()[1].username, "nobody");
    }

    #[test]
    fn login_locked_account_fails() {
        let db = UserDb::with_root(); // root has no password
        let mut lm = LoginManager::new();
        assert_eq!(
            lm.login(&db, "root", "anything12", 1, "tty0"),
            Err(SessionError::NoPassword)
        );
    }

    #[test]
    fn login_malformed_stored_hash_is_an_error() {
        let mut db = UserDb::with_root();
        let mut bad = User::new(1000, "bad", 0, "/home/bad", "/bin/sh");
        bad.set_password_hash("not-a-hash".into());
        db.add_user(bad).unwrap();
        let mut lm = LoginManager::new();
        assert!(matches!(
            lm.login(&db, "bad", "password12", 1, "tty0"),
            Err(SessionError::MalformedHash(_))
        ));
    }

    #[test]
    fn logout_records_audit_entry() {
        let db = db_with_alice();
        let mut lm = LoginManager::new();
        let s = lm.login(&db, "alice", "correct horse", 1, "tty0").unwrap();
        lm.logout(&s, 99);
        assert_eq!(lm.audit().len(), 2);
    }

    #[test]
    fn audit_ring_wraps_at_capacity() {
        let mut log = AuditLog::new();
        for i in 0..(MAX_AUDIT_ENTRIES + 5) {
            log.record(AuditEntry {
                kind: AuditKind::Login,
                username: alloc::format!("user{i}"),
                terminal: "tty0".into(),
                tick: i as u64,
                success: i % 2 == 0,
            });
        }
        assert_eq!(log.len(), MAX_AUDIT_ENTRIES);
        let entries = log.entries();
        assert_eq!(entries[0].username, "user5"); // oldest surviving
        assert_eq!(entries[entries.len() - 1].username, alloc::format!("user{}", MAX_AUDIT_ENTRIES + 4));
    }

    #[test]
    fn setuid_rules_non_root() {
        // alice runs a setuid-root helper: ruid 1000, euid 0, suid 0.
        let mut creds = ProcessCreds {
            ruid: 1000,
            euid: 0,
            suid: 0,
            rgid: 100,
            egid: 100,
            sgid: 100,
            caps: CapabilitySet::empty(),
        };
        // While euid is 0 it may set any id...
        creds.setuid(1000).unwrap();
        assert_eq!((creds.ruid, creds.euid, creds.suid), (1000, 1000, 1000));
        // ...but after dropping to 1000 it can no longer become root.
        assert_eq!(creds.setuid(0), Err(SessionError::NotPermitted));
        // And it cannot pick an unrelated uid.
        assert_eq!(creds.setuid(1001), Err(SessionError::NotPermitted));
    }

    #[test]
    fn setuid_rules_plain_process() {
        let mut creds = ProcessCreds::for_user(&User::new(1000, "alice", 100, "/home/alice", "/bin/sh"));
        assert_eq!(creds.setuid(1001), Err(SessionError::NotPermitted));
        assert!(creds.setuid(1000).is_ok());
        assert!(creds.seteuid(1000).is_ok());
        assert_eq!(creds.setgid(999), Err(SessionError::NotPermitted));
        assert!(creds.setgid(100).is_ok());
    }

    #[test]
    fn setuid_helper_can_switch_back_via_saved_id() {
        // Classic setuid dance: euid 0 -> drop to real -> back to saved 0.
        let mut creds = ProcessCreds {
            ruid: 1000,
            euid: 0,
            suid: 0,
            rgid: 100,
            egid: 100,
            sgid: 100,
            caps: CapabilitySet::empty(),
        };
        creds.seteuid(1000).unwrap();
        assert_eq!(creds.euid, 1000);
        creds.seteuid(0).unwrap(); // saved id allows the return
        assert_eq!(creds.euid, 0);
    }

    #[test]
    fn drop_privileges_is_permanent() {
        let mut creds = ProcessCreds {
            ruid: 1000,
            euid: 0,
            suid: 0,
            rgid: 100,
            egid: 100,
            sgid: 100,
            caps: CapabilitySet::empty().with(Capability::RawIo),
        };
        creds.drop_privileges();
        assert_eq!((creds.euid, creds.suid), (1000, 1000));
        assert_eq!((creds.egid, creds.sgid), (100, 100));
        assert!(!creds.caps.has(Capability::RawIo));
        assert_eq!(creds.setuid(0), Err(SessionError::NotPermitted));
    }

    #[test]
    fn after_exec_sets_saved_ids_from_effective() {
        let caller = ProcessCreds::for_user(&User::new(1000, "alice", 100, "/home/alice", "/bin/sh"));
        let execed = ProcessCreds::after_exec(&caller, 0, 50, CapabilitySet::empty());
        assert_eq!(execed.ruid, 1000);
        assert_eq!(execed.euid, 0);
        assert_eq!(execed.suid, 0);
        assert_eq!(execed.egid, 50);
        assert_eq!(execed.sgid, 50);
    }

    #[test]
    fn session_creds_carry_groups_and_caps() {
        let db = db_with_alice();
        let mut lm = LoginManager::new();
        let s = lm.login(&db, "alice", "correct horse", 1, "tty0").unwrap();
        let creds = s.creds_with_caps(CapabilitySet::empty().with(Capability::Mount));
        assert_eq!(creds.uid, 1000);
        assert!(creds.groups.contains(&100));
        assert!(creds.has_capability(Capability::Mount));
        assert!(!creds.has_capability(Capability::Reboot));
    }
}
