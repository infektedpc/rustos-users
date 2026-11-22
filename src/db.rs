//! User and group accounts: an in-memory, fixed-capacity database.
//!
//! No plaintext passwords are stored here: a [`User`] holds at most
//! the stored hash string produced by [`crate::password`]
//! (`None` = account locked / no password set, login always fails).

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

/// Maximum users and groups the database holds. Enforced by
/// [`UserDb::add_user`] / [`add_group`]; this keeps the table
/// bounded for a kernel that cannot grow it without thinking.
pub const MAX_USERS: usize = 64;
pub const MAX_GROUPS: usize = 32;
/// Maximum supplementary groups one user may belong to.
pub const MAX_SUPPLEMENTARY_GROUPS: usize = 16;
/// Maximum username / group name length (bytes).
pub const MAX_NAME_LEN: usize = 32;

/// Errors from database operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbError {
    /// A user or group with this name already exists.
    DuplicateName,
    /// A user or group with this uid/gid already exists.
    DuplicateId,
    /// The database is full ([`MAX_USERS`] / [`MAX_GROUPS`]).
    Full,
    /// Name is empty, too long, or contains a disallowed character
    /// (`:` `,` whitespace, or a leading `-`).
    BadName,
    /// No such user or group.
    NotFound,
    /// The requested supplementary-group list is too long.
    TooManyGroups,
    /// The referenced primary or supplementary group does not exist.
    UnknownGroup,
    /// The group is still referenced by a user (primary or
    /// supplementary) and cannot be removed yet.
    GroupInUse,
    /// The root account (uid 0) may not be removed.
    CannotRemoveRoot,
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbError::DuplicateName => write!(f, "name already exists"),
            DbError::DuplicateId => write!(f, "uid/gid already exists"),
            DbError::Full => write!(f, "database is full"),
            DbError::BadName => write!(f, "bad name"),
            DbError::NotFound => write!(f, "not found"),
            DbError::TooManyGroups => write!(f, "too many supplementary groups"),
            DbError::UnknownGroup => write!(f, "unknown group"),
            DbError::GroupInUse => write!(f, "group is still in use"),
            DbError::CannotRemoveRoot => write!(f, "cannot remove root"),
        }
    }
}

fn valid_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_LEN || name.starts_with('-') {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// One user account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// Numeric user id. 0 is root.
    pub uid: u32,
    /// Login name.
    pub username: String,
    /// Primary group id.
    pub gid: u32,
    /// Supplementary group ids.
    pub groups: Vec<u32>,
    /// Home directory, e.g. `/home/alice`.
    pub home: String,
    /// Login shell, e.g. `/bin/sh`.
    pub shell: String,
    /// Stored password hash (`sha256iter$...`), or `None` when the
    /// account has no password (login with a password always fails;
    /// see [`User::set_password_hash`]).
    pub password_hash: Option<String>,
}

impl User {
    /// Build a user with no password set. Use
    /// [`UserDb::add_user`] to insert it (which validates the name,
    /// uid uniqueness, and that the primary group exists).
    pub fn new(uid: u32, username: &str, gid: u32, home: &str, shell: &str) -> Self {
        User {
            uid,
            username: username.into(),
            gid,
            groups: Vec::new(),
            home: home.into(),
            shell: shell.into(),
            password_hash: None,
        }
    }

    /// The conventional root account.
    pub fn root() -> Self {
        User {
            uid: 0,
            username: "root".into(),
            gid: 0,
            groups: Vec::new(),
            home: "/root".into(),
            shell: "/bin/sh".into(),
            password_hash: None,
        }
    }

    /// Replace the stored hash (already in `sha256iter$...` form).
    pub fn set_password_hash(&mut self, stored: String) {
        self.password_hash = Some(stored);
    }

    /// Lock the account: remove the password hash so password login
    /// can never succeed.
    pub fn lock_password(&mut self) {
        self.password_hash = None;
    }

    /// All group ids this user belongs to: primary first, then
    /// supplementary (deduplicated).
    pub fn all_gids(&self) -> Vec<u32> {
        let mut gids = Vec::with_capacity(1 + self.groups.len());
        gids.push(self.gid);
        for &g in &self.groups {
            if !gids.contains(&g) {
                gids.push(g);
            }
        }
        gids
    }

    /// True when the user is a member of `gid` (primary or
    /// supplementary).
    pub fn is_member_of(&self, gid: u32) -> bool {
        self.gid == gid || self.groups.contains(&gid)
    }
}

/// One group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Numeric group id.
    pub gid: u32,
    /// Group name.
    pub name: String,
    /// Member usernames (kept in sync with users' supplementary
    /// lists by [`UserDb`]).
    pub members: Vec<String>,
}

impl Group {
    pub fn new(gid: u32, name: &str) -> Self {
        Group {
            gid,
            name: name.into(),
            members: Vec::new(),
        }
    }
}

/// In-memory user/group database. Fixed capacity ([`MAX_USERS`] /
/// [`MAX_GROUPS`]), `alloc`-only, no file I/O — persistence is the
/// serialiser's job ([`crate::serialize`]).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UserDb {
    users: Vec<User>,
    groups: Vec<Group>,
}

impl UserDb {
    pub fn new() -> Self {
        UserDb::default()
    }

    /// A database pre-seeded with the root user and the `root` group,
    /// the state a fresh install boots into.
    pub fn with_root() -> Self {
        let mut db = UserDb::new();
        let _ = db.add_group(Group::new(0, "root"));
        let _ = db.add_user(User::root());
        db
    }

    pub fn user_count(&self) -> usize {
        self.users.len()
    }
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }
    pub fn users(&self) -> &[User] {
        &self.users
    }
    pub fn groups(&self) -> &[Group] {
        &self.groups
    }

    pub fn find_user_by_name(&self, name: &str) -> Option<&User> {
        self.users.iter().find(|u| u.username == name)
    }
    pub fn find_user_by_uid(&self, uid: u32) -> Option<&User> {
        self.users.iter().find(|u| u.uid == uid)
    }
    pub fn find_user_by_name_mut(&mut self, name: &str) -> Option<&mut User> {
        self.users.iter_mut().find(|u| u.username == name)
    }
    pub fn find_group_by_name(&self, name: &str) -> Option<&Group> {
        self.groups.iter().find(|g| g.name == name)
    }
    pub fn find_group_by_gid(&self, gid: u32) -> Option<&Group> {
        self.groups.iter().find(|g| g.gid == gid)
    }
    pub fn find_group_by_gid_mut(&mut self, gid: u32) -> Option<&mut Group> {
        self.groups.iter_mut().find(|g| g.gid == gid)
    }

    /// Insert a user. The primary group must already exist and the
    /// supplementary groups must exist too; the group member lists
    /// are updated to match.
    pub fn add_user(&mut self, mut user: User) -> Result<(), DbError> {
        if !valid_name(&user.username) {
            return Err(DbError::BadName);
        }
        if self.find_user_by_name(&user.username).is_some() {
            return Err(DbError::DuplicateName);
        }
        if self.find_user_by_uid(user.uid).is_some() {
            return Err(DbError::DuplicateId);
        }
        if self.users.len() >= MAX_USERS {
            return Err(DbError::Full);
        }
        if self.find_group_by_gid(user.gid).is_none() {
            return Err(DbError::UnknownGroup);
        }
        if user.groups.len() > MAX_SUPPLEMENTARY_GROUPS {
            return Err(DbError::TooManyGroups);
        }
        for &g in &user.groups {
            if self.find_group_by_gid(g).is_none() {
                return Err(DbError::UnknownGroup);
            }
        }
        // Deduplicate supplementary groups (and drop the primary).
        user.groups.retain(|&g| g != user.gid);
        user.groups.sort_unstable();
        user.groups.dedup();
        for &g in &user.groups {
            if let Some(group) = self.find_group_by_gid_mut(g) {
                if !group.members.contains(&user.username) {
                    group.members.push(user.username.clone());
                }
            }
        }
        self.users.push(user);
        Ok(())
    }

    /// Remove a user by name. Also removes them from group member
    /// lists. Root (uid 0) cannot be removed.
    pub fn remove_user(&mut self, name: &str) -> Result<User, DbError> {
        let pos = self
            .users
            .iter()
            .position(|u| u.username == name)
            .ok_or(DbError::NotFound)?;
        if self.users[pos].uid == 0 {
            return Err(DbError::CannotRemoveRoot);
        }
        let user = self.users.remove(pos);
        for group in self.groups.iter_mut() {
            group.members.retain(|m| m != name);
        }
        Ok(user)
    }

    /// Insert a group.
    pub fn add_group(&mut self, group: Group) -> Result<(), DbError> {
        if !valid_name(&group.name) {
            return Err(DbError::BadName);
        }
        if self.find_group_by_name(&group.name).is_some() {
            return Err(DbError::DuplicateName);
        }
        if self.find_group_by_gid(group.gid).is_some() {
            return Err(DbError::DuplicateId);
        }
        if self.groups.len() >= MAX_GROUPS {
            return Err(DbError::Full);
        }
        self.groups.push(group);
        Ok(())
    }

    /// Remove a group by name. Fails while any user still has it as
    /// primary or supplementary group (remove/reassign those first).
    pub fn remove_group(&mut self, name: &str) -> Result<Group, DbError> {
        let pos = self
            .groups
            .iter()
            .position(|g| g.name == name)
            .ok_or(DbError::NotFound)?;
        let gid = self.groups[pos].gid;
        if self.users.iter().any(|u| u.gid == gid || u.groups.contains(&gid)) {
            return Err(DbError::GroupInUse);
        }
        Ok(self.groups.remove(pos))
    }

    /// Add `username` to supplementary group `gid` (both directions).
    pub fn add_user_to_group(&mut self, username: &str, gid: u32) -> Result<(), DbError> {
        let already_member = self
            .find_user_by_name(username)
            .ok_or(DbError::NotFound)?
            .is_member_of(gid);
        if already_member {
            return Ok(()); // already a member (primary or supplementary)
        }
        if self.find_group_by_gid(gid).is_none() {
            return Err(DbError::UnknownGroup);
        }
        let user = self.find_user_by_name_mut(username).unwrap();
        if user.groups.len() >= MAX_SUPPLEMENTARY_GROUPS {
            return Err(DbError::TooManyGroups);
        }
        user.groups.push(gid);
        let group = self.find_group_by_gid_mut(gid).unwrap();
        if !group.members.contains(&username.to_string()) {
            group.members.push(username.to_string());
        }
        Ok(())
    }

    /// Remove `username` from supplementary group `gid`.
    pub fn remove_user_from_group(&mut self, username: &str, gid: u32) -> Result<(), DbError> {
        let user = self
            .find_user_by_name_mut(username)
            .ok_or(DbError::NotFound)?;
        user.groups.retain(|&g| g != gid);
        if let Some(group) = self.find_group_by_gid_mut(gid) {
            group.members.retain(|m| m != username);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded_db() -> UserDb {
        let mut db = UserDb::with_root();
        db.add_group(Group::new(100, "users")).unwrap();
        db.add_group(Group::new(101, "wheel")).unwrap();
        let mut alice = User::new(1000, "alice", 100, "/home/alice", "/bin/sh");
        alice.groups.push(101);
        db.add_user(alice).unwrap();
        db
    }

    #[test]
    fn with_root_seeds_root_user_and_group() {
        let db = UserDb::with_root();
        assert_eq!(db.user_count(), 1);
        assert_eq!(db.group_count(), 1);
        let root = db.find_user_by_uid(0).unwrap();
        assert_eq!(root.username, "root");
        assert_eq!(root.home, "/root");
    }

    #[test]
    fn add_and_lookup_by_name_and_uid() {
        let db = seeded_db();
        let alice = db.find_user_by_name("alice").unwrap();
        assert_eq!(alice.uid, 1000);
        assert_eq!(alice.gid, 100);
        assert_eq!(db.find_user_by_uid(1000).unwrap().username, "alice");
        assert!(db.find_user_by_name("nobody").is_none());
        assert!(db.find_user_by_uid(9999).is_none());
    }

    #[test]
    fn duplicate_name_and_uid_rejected() {
        let mut db = seeded_db();
        let dup_name = User::new(1001, "alice", 100, "/home/alice2", "/bin/sh");
        assert_eq!(db.add_user(dup_name), Err(DbError::DuplicateName));
        let dup_uid = User::new(1000, "bob", 100, "/home/bob", "/bin/sh");
        assert_eq!(db.add_user(dup_uid), Err(DbError::DuplicateId));
        let dup_group = Group::new(102, "users");
        assert_eq!(db.add_group(dup_group), Err(DbError::DuplicateName));
        let dup_gid = Group::new(100, "staff");
        assert_eq!(db.add_group(dup_gid), Err(DbError::DuplicateId));
    }

    #[test]
    fn bad_names_rejected() {
        let mut db = UserDb::with_root();
        assert_eq!(
            db.add_user(User::new(1000, "", 0, "/home/x", "/bin/sh")),
            Err(DbError::BadName)
        );
        assert_eq!(
            db.add_user(User::new(1000, "has:colon", 0, "/home/x", "/bin/sh")),
            Err(DbError::BadName)
        );
        assert_eq!(
            db.add_user(User::new(1000, "has space", 0, "/home/x", "/bin/sh")),
            Err(DbError::BadName)
        );
        assert_eq!(
            db.add_user(User::new(1000, "-dash", 0, "/home/x", "/bin/sh")),
            Err(DbError::BadName)
        );
        assert_eq!(
            db.add_user(User::new(1000, "ok_name-1.2", 0, "/home/x", "/bin/sh")),
            Ok(())
        );
    }

    #[test]
    fn unknown_primary_or_supplementary_group_rejected() {
        let mut db = UserDb::with_root();
        let no_group = User::new(1000, "alice", 999, "/home/alice", "/bin/sh");
        assert_eq!(db.add_user(no_group), Err(DbError::UnknownGroup));
        let mut bad_supp = User::new(1000, "alice", 0, "/home/alice", "/bin/sh");
        bad_supp.groups.push(999);
        assert_eq!(db.add_user(bad_supp), Err(DbError::UnknownGroup));
    }

    #[test]
    fn remove_user_cleans_group_membership() {
        let mut db = seeded_db();
        assert!(db.find_group_by_gid(101).unwrap().members.contains(&"alice".to_string()));
        let removed = db.remove_user("alice").unwrap();
        assert_eq!(removed.uid, 1000);
        assert!(db.find_user_by_name("alice").is_none());
        assert!(!db
            .find_group_by_gid(101)
            .unwrap()
            .members
            .contains(&"alice".to_string()));
        assert_eq!(db.remove_user("alice"), Err(DbError::NotFound));
    }

    #[test]
    fn root_cannot_be_removed() {
        let mut db = UserDb::with_root();
        assert_eq!(db.remove_user("root"), Err(DbError::CannotRemoveRoot));
    }

    #[test]
    fn group_membership_both_directions() {
        let mut db = seeded_db();
        db.add_user_to_group("alice", 100).unwrap(); // primary: no-op
        db.add_group(Group::new(102, "audio")).unwrap();
        db.add_user_to_group("alice", 102).unwrap();
        assert!(db.find_user_by_name("alice").unwrap().is_member_of(102));
        assert!(db
            .find_group_by_gid(102)
            .unwrap()
            .members
            .contains(&"alice".to_string()));
        db.remove_user_from_group("alice", 102).unwrap();
        assert!(!db.find_user_by_name("alice").unwrap().is_member_of(102));
        assert_eq!(db.add_user_to_group("alice", 999), Err(DbError::UnknownGroup));
        assert_eq!(db.add_user_to_group("ghost", 102), Err(DbError::NotFound));
    }

    #[test]
    fn all_gids_deduplicates_primary() {
        let db = seeded_db();
        let alice = db.find_user_by_name("alice").unwrap();
        assert_eq!(alice.all_gids(), vec![100, 101]);
    }

    #[test]
    fn group_in_use_cannot_be_removed() {
        let mut db = seeded_db();
        assert!(db.remove_group("users").is_err());
        assert!(db.remove_group("wheel").is_err());
        db.remove_user("alice").unwrap();
        assert!(db.remove_group("wheel").is_ok());
        assert_eq!(db.remove_group("wheel"), Err(DbError::NotFound));
    }
}
