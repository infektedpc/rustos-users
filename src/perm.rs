//! Unix permission model: owner/group/other rwx mode bits plus an
//! explicit capability set for privileged operations.
//!
//! Rules, matching Unix:
//! * The owner class applies when the caller's uid equals the file
//!   owner's uid; else the group class when any of the caller's gids
//!   matches the file's gid; else the other class.
//! * Root (uid 0) bypasses the rwx checks — except execute, which
//!   still needs at least one execute bit set anywhere in the mode
//!   (the standard Unix rule for root).
//! * Capabilities are **explicit**: root does *not* implicitly hold
//!   them. The kernel grants a capability set at login / exec time
//!   and [`Creds::has_capability`] answers queries against it.

use alloc::vec::Vec;

/// Permission bits in a Unix mode (the low 9 bits; the file-type and
/// setuid/setgid/sticky bits live above them).
pub const MODE_OWNER_READ: u32 = 0o400;
pub const MODE_OWNER_WRITE: u32 = 0o200;
pub const MODE_OWNER_EXEC: u32 = 0o100;
pub const MODE_GROUP_READ: u32 = 0o040;
pub const MODE_GROUP_WRITE: u32 = 0o020;
pub const MODE_GROUP_EXEC: u32 = 0o010;
pub const MODE_OTHER_READ: u32 = 0o004;
pub const MODE_OTHER_WRITE: u32 = 0o002;
pub const MODE_OTHER_EXEC: u32 = 0o001;
pub const MODE_RWX_MASK: u32 = 0o777;
/// setuid / setgid / sticky bits.
pub const MODE_SETUID: u32 = 0o4000;
pub const MODE_SETGID: u32 = 0o2000;
pub const MODE_STICKY: u32 = 0o1000;

/// Which access is being requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Execute,
}

/// Privileged operations the kernel gates behind a capability.
/// Capabilities are granted explicitly (e.g. to a setuid helper or
/// to root's login session by policy); uid 0 alone grants none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Reboot / power off the machine.
    Reboot,
    /// Mount / unmount filesystems.
    Mount,
    /// Raw I/O port / device access.
    RawIo,
    /// Create, delete, or modify user/group accounts.
    ManageUsers,
    /// Signal or kill processes owned by other users.
    KillAny,
    /// Change ownership (chown) of files.
    Chown,
    /// Bind to privileged ports (< 1024) / raw sockets.
    NetBindService,
    /// Load kernel modules / change kernel parameters.
    SysAdmin,
}

impl Capability {
    /// Bit position in a [`CapabilitySet`].
    pub fn bit(self) -> u32 {
        1u32 << (self as u32)
    }
}

/// A set of capabilities, stored as a bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapabilitySet(pub u32);

impl CapabilitySet {
    pub const EMPTY: CapabilitySet = CapabilitySet(0);
    /// Every capability defined in [`Capability`].
    pub const ALL: CapabilitySet = CapabilitySet(
        (1u32 << (Capability::SysAdmin as u32 + 1)) - 1,
    );

    pub fn empty() -> Self {
        CapabilitySet::EMPTY
    }
    pub fn all() -> Self {
        CapabilitySet::ALL
    }
    pub fn with(mut self, cap: Capability) -> Self {
        self.0 |= cap.bit();
        self
    }
    pub fn without(mut self, cap: Capability) -> Self {
        self.0 &= !cap.bit();
        self
    }
    pub fn has(self, cap: Capability) -> bool {
        self.0 & cap.bit() != 0
    }
    pub fn contains_all(self, other: CapabilitySet) -> bool {
        self.0 & other.0 == other.0
    }
    pub fn union(self, other: CapabilitySet) -> Self {
        CapabilitySet(self.0 | other.0)
    }
    pub fn intersect(self, other: CapabilitySet) -> Self {
        CapabilitySet(self.0 & other.0)
    }
}

/// The identity a permission check is made against: effective uid,
/// effective gid, supplementary gids, and the capability set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Creds {
    /// Effective uid (0 = root).
    pub uid: u32,
    /// Effective gid.
    pub gid: u32,
    /// Supplementary gids (the primary gid should be included by
    /// the caller when it matters; see [`Creds::for_user`]).
    pub groups: Vec<u32>,
    /// Explicitly granted capabilities.
    pub caps: CapabilitySet,
}

impl Creds {
    /// Credentials for a user: uid, primary gid, supplementary
    /// groups (primary gid prepended), no capabilities.
    pub fn for_user(uid: u32, gid: u32, groups: &[u32]) -> Self {
        let mut all = Vec::with_capacity(1 + groups.len());
        all.push(gid);
        for &g in groups {
            if !all.contains(&g) {
                all.push(g);
            }
        }
        Creds {
            uid,
            gid,
            groups: all,
            caps: CapabilitySet::empty(),
        }
    }

    /// Root credentials with an explicit capability set (root holds
    /// no capability implicitly — the caller decides the set).
    pub fn root(caps: CapabilitySet) -> Self {
        Creds {
            uid: 0,
            gid: 0,
            groups: alloc::vec![0],
            caps,
        }
    }

    pub fn is_root(&self) -> bool {
        self.uid == 0
    }

    pub fn has_capability(&self, cap: Capability) -> bool {
        self.caps.has(cap)
    }

    fn in_group(&self, gid: u32) -> bool {
        self.gid == gid || self.groups.contains(&gid)
    }
}

/// Answer one access check: may `creds` perform `access` on a file
/// owned by (`owner_uid`, `owner_gid`) with `mode`?
pub fn check_access(
    creds: &Creds,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
    access: Access,
) -> bool {
    let mode = mode & MODE_RWX_MASK;
    if creds.is_root() {
        // Root bypasses read/write; execute still needs any x bit.
        return match access {
            Access::Read | Access::Write => true,
            Access::Execute => mode & 0o111 != 0,
        };
    }
    let bits = if creds.uid == owner_uid {
        (mode >> 6) & 0o7
    } else if creds.in_group(owner_gid) {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    };
    let want = match access {
        Access::Read => 0o4,
        Access::Write => 0o2,
        Access::Execute => 0o1,
    };
    bits & want != 0
}

/// Convenience wrappers over [`check_access`].
pub fn can_read(creds: &Creds, owner_uid: u32, owner_gid: u32, mode: u32) -> bool {
    check_access(creds, owner_uid, owner_gid, mode, Access::Read)
}
pub fn can_write(creds: &Creds, owner_uid: u32, owner_gid: u32, mode: u32) -> bool {
    check_access(creds, owner_uid, owner_gid, mode, Access::Write)
}
pub fn can_execute(creds: &Creds, owner_uid: u32, owner_gid: u32, mode: u32) -> bool {
    check_access(creds, owner_uid, owner_gid, mode, Access::Execute)
}

/// The effective uid/gid a process gets when executing a file, from
/// the file's setuid/setgid bits. Returns `(euid, egid)`: the file
/// owner's uid when setuid is set (else the caller's uid), and the
/// file's gid when setgid is set (else the caller's gid).
pub fn exec_credentials(
    caller_uid: u32,
    caller_gid: u32,
    file_uid: u32,
    file_gid: u32,
    mode: u32,
) -> (u32, u32) {
    let euid = if mode & MODE_SETUID != 0 { file_uid } else { caller_uid };
    let egid = if mode & MODE_SETGID != 0 { file_gid } else { caller_gid };
    (euid, egid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Creds {
        Creds::for_user(1000, 100, &[101])
    }
    fn bob() -> Creds {
        Creds::for_user(1001, 100, &[])
    }
    fn stranger() -> Creds {
        Creds::for_user(1002, 200, &[])
    }

    #[test]
    fn owner_group_other_matrix() {
        // 0640: owner rw, group r, other none. File owned by alice:100.
        let mode = 0o640;
        assert!(can_read(&alice(), 1000, 100, mode));
        assert!(can_write(&alice(), 1000, 100, mode));
        assert!(!can_execute(&alice(), 1000, 100, mode));

        assert!(can_read(&bob(), 1000, 100, mode)); // same group
        assert!(!can_write(&bob(), 1000, 100, mode));
        assert!(!can_execute(&bob(), 1000, 100, mode));

        assert!(!can_read(&stranger(), 1000, 100, mode));
        assert!(!can_write(&stranger(), 1000, 100, mode));
    }

    #[test]
    fn each_rwx_bit_is_independent() {
        // 0711: owner rwx, group --x, other --x.
        let mode = 0o711;
        assert!(can_execute(&bob(), 1000, 100, mode));
        assert!(!can_read(&bob(), 1000, 100, mode));
        assert!(!can_write(&bob(), 1000, 100, mode));
        assert!(can_execute(&stranger(), 1000, 100, mode));
        assert!(!can_read(&stranger(), 1000, 100, mode));
        // 0000: nobody but root.
        assert!(!can_read(&alice(), 1000, 100, 0o000));
        assert!(!can_write(&alice(), 1000, 100, 0o000));
        // 0777: everyone.
        assert!(can_write(&stranger(), 1000, 100, 0o777));
        // Owner class wins over group class even when group is wider.
        // File 0040, owned by alice: alice (owner) gets nothing.
        assert!(!can_read(&alice(), 1000, 100, 0o040));
        assert!(can_read(&bob(), 1000, 100, 0o040));
    }

    #[test]
    fn supplementary_group_counts() {
        // alice is in group 101 via supplementary membership; the file
        // is owned by bob (so the owner class does not shadow the
        // group class for alice).
        let mode = 0o070; // group rwx only
        assert!(can_write(&alice(), 1001, 101, mode));
        assert!(!can_write(&bob(), 1001, 101, mode));
    }

    #[test]
    fn root_bypasses_rwx_but_not_execute_without_x_bit() {
        let root = Creds::root(CapabilitySet::empty());
        assert!(can_read(&root, 1000, 100, 0o000));
        assert!(can_write(&root, 1000, 100, 0o000));
        assert!(!can_execute(&root, 1000, 100, 0o000));
        assert!(!can_execute(&root, 1000, 100, 0o644));
        assert!(can_execute(&root, 1000, 100, 0o100));
        assert!(can_execute(&root, 1000, 100, 0o001));
    }

    #[test]
    fn capabilities_are_explicit_even_for_root() {
        let bare_root = Creds::root(CapabilitySet::empty());
        assert!(!bare_root.has_capability(Capability::Reboot));
        assert!(!bare_root.has_capability(Capability::ManageUsers));
        let admin = Creds::root(CapabilitySet::all());
        assert!(admin.has_capability(Capability::Reboot));
        assert!(admin.has_capability(Capability::SysAdmin));
        let partial = Creds::root(CapabilitySet::empty().with(Capability::Mount));
        assert!(partial.has_capability(Capability::Mount));
        assert!(!partial.has_capability(Capability::RawIo));
        // Non-root with a capability keeps it.
        let alice_caps = Creds {
            caps: CapabilitySet::empty().with(Capability::NetBindService),
            ..alice()
        };
        assert!(alice_caps.has_capability(Capability::NetBindService));
        assert!(!alice_caps.has_capability(Capability::Reboot));
    }

    #[test]
    fn capability_set_algebra() {
        let a = CapabilitySet::empty()
            .with(Capability::Mount)
            .with(Capability::Reboot);
        let b = CapabilitySet::empty().with(Capability::Mount);
        assert!(a.contains_all(b));
        assert!(!b.contains_all(a));
        assert_eq!(a.without(Capability::Mount), CapabilitySet::empty().with(Capability::Reboot));
        assert_eq!(a.intersect(b), b);
        assert_eq!(a.union(b), a);
        // ALL really contains every defined capability.
        for cap in [
            Capability::Reboot,
            Capability::Mount,
            Capability::RawIo,
            Capability::ManageUsers,
            Capability::KillAny,
            Capability::Chown,
            Capability::NetBindService,
            Capability::SysAdmin,
        ] {
            assert!(CapabilitySet::all().has(cap));
        }
    }

    #[test]
    fn setuid_setgid_exec_credentials() {
        // Plain exec: caller keeps its ids.
        assert_eq!(exec_credentials(1000, 100, 0, 0, 0o755), (1000, 100));
        // setuid root binary: euid becomes the file owner.
        assert_eq!(exec_credentials(1000, 100, 0, 0, 0o4755), (0, 100));
        // setgid binary: egid becomes the file group.
        assert_eq!(exec_credentials(1000, 100, 0, 50, 0o2755), (1000, 50));
        // Both bits.
        assert_eq!(exec_credentials(1000, 100, 0, 50, 0o6755), (0, 50));
    }
}
