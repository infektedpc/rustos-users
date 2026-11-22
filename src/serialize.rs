//! Serialisation of the user/group database to a line-based text
//! format, for persistence through `rustos-fs` later.
//!
//! The database serialises to one document with three sections:
//!
//! ```text
//! # rustos-users v1
//! [passwd]
//! root:0:0:/root:/bin/sh
//! alice:1000:100:/home/alice:/bin/sh
//! [shadow]
//! alice:sha256iter$10000$...$...
//! [group]
//! root:0:
//! users:100:alice
//! wheel:101:alice
//! ```
//!
//! * `[passwd]` — world-readable account data: `name:uid:gid:home:shell`.
//! * `[shadow]` — password hashes only, one line per user that has
//!   one: `name:sha256iter$<iters>$<salt hex>$<digest hex>`. The
//!   hash never appears in the `[passwd]` section (the Unix split).
//! * `[group]` — `name:gid:member1,member2` (empty member list = a
//!   trailing colon and nothing after it).
//! * Lines starting with `#` are comments and are ignored on parse;
//!   blank lines are ignored. Unknown sections and malformed lines
//!   are rejected with [`ParseError`] — a corrupt file never loads
//!   partially.
//!
//! The individual sections are also available on their own
//! ([`to_passwd`], [`to_shadow`], [`to_group`]) so a caller that
//! stores the files separately (e.g. different permissions on disk)
//! can do so.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::db::{DbError, Group, User, UserDb};

/// Errors from parsing a serialised database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// A line does not have the expected number of `:` fields, or a
    /// numeric field does not parse.
    MalformedLine(String),
    /// A line appears before any section header.
    LineOutsideSection(String),
    /// An unknown `[section]` header.
    UnknownSection(String),
    /// The document's `# rustos-users v1` header is missing or the
    /// version is not `1`.
    BadHeader,
    /// A `[shadow]` entry names a user that has no `[passwd]` entry,
    /// or a `[passwd]` entry appears twice.
    Inconsistent(String),
    /// The database rejected a parsed entry (duplicate, bad name,
    /// unknown group, ...).
    Db(DbError),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::MalformedLine(l) => write!(f, "malformed line: {l}"),
            ParseError::LineOutsideSection(l) => write!(f, "line outside section: {l}"),
            ParseError::UnknownSection(s) => write!(f, "unknown section: {s}"),
            ParseError::BadHeader => write!(f, "bad or missing header"),
            ParseError::Inconsistent(s) => write!(f, "inconsistent database: {s}"),
            ParseError::Db(e) => write!(f, "database error: {e}"),
        }
    }
}

impl From<DbError> for ParseError {
    fn from(e: DbError) -> Self {
        ParseError::Db(e)
    }
}

const HEADER: &str = "# rustos-users v1";

/// Serialise the whole database to one document (see module docs).
pub fn to_text(db: &UserDb) -> String {
    let mut out = String::new();
    out.push_str(HEADER);
    out.push('\n');
    out.push_str("[passwd]\n");
    out.push_str(&to_passwd(db));
    out.push_str("[shadow]\n");
    out.push_str(&to_shadow(db));
    out.push_str("[group]\n");
    out.push_str(&to_group(db));
    out
}

/// The `[passwd]` section only: `name:uid:gid:home:shell` per line.
pub fn to_passwd(db: &UserDb) -> String {
    let mut out = String::new();
    for u in db.users() {
        out.push_str(&alloc::format!(
            "{}:{}:{}:{}:{}\n",
            u.username, u.uid, u.gid, u.home, u.shell
        ));
    }
    out
}

/// The `[shadow]` section only: `name:stored-hash` per line, only
/// for users that have a password hash.
pub fn to_shadow(db: &UserDb) -> String {
    let mut out = String::new();
    for u in db.users() {
        if let Some(hash) = &u.password_hash {
            out.push_str(&alloc::format!("{}:{}\n", u.username, hash));
        }
    }
    out
}

/// The `[group]` section only: `name:gid:member1,member2` per line.
pub fn to_group(db: &UserDb) -> String {
    let mut out = String::new();
    for g in db.groups() {
        out.push_str(&alloc::format!(
            "{}:{}:{}\n",
            g.name,
            g.gid,
            g.members.join(",")
        ));
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Passwd,
    Shadow,
    Group,
}

/// Parse a document produced by [`to_text`] back into a database.
/// Rejects malformed input outright (see [`ParseError`]).
pub fn from_text(text: &str) -> Result<UserDb, ParseError> {
    let mut lines = text.lines();
    let first = lines.next().ok_or(ParseError::BadHeader)?;
    if first.trim() != HEADER {
        return Err(ParseError::BadHeader);
    }
    let mut db = UserDb::new();
    let mut section: Option<Section> = None;
    // Entries are collected during the scan and applied afterwards:
    // groups first (users' primary groups must exist before the
    // users are inserted), then users, then shadow hashes, then
    // supplementary memberships. Section order in the file therefore
    // does not matter.
    let mut passwd_users: Vec<User> = Vec::new();
    let mut shadow_entries: Vec<(String, String)> = Vec::new();
    let mut group_defs: Vec<Group> = Vec::new();
    let mut group_members: Vec<(u32, Vec<String>)> = Vec::new();

    for raw in lines {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = Some(match name {
                "passwd" => Section::Passwd,
                "shadow" => Section::Shadow,
                "group" => Section::Group,
                other => return Err(ParseError::UnknownSection(other.into())),
            });
            continue;
        }
        let section = section.ok_or_else(|| ParseError::LineOutsideSection(line.into()))?;
        match section {
            Section::Passwd => {
                let user = parse_passwd_line(line)?;
                if passwd_users.iter().any(|u| u.username == user.username) {
                    return Err(ParseError::Inconsistent(alloc::format!(
                        "duplicate user {}",
                        user.username
                    )));
                }
                passwd_users.push(user);
            }
            Section::Shadow => {
                let (name, hash) = line
                    .split_once(':')
                    .ok_or_else(|| ParseError::MalformedLine(line.into()))?;
                shadow_entries.push((name.into(), hash.into()));
            }
            Section::Group => {
                let (group, members) = parse_group_line(line)?;
                if group_defs.iter().any(|g| g.name == group.name || g.gid == group.gid) {
                    return Err(ParseError::Inconsistent(alloc::format!(
                        "duplicate group {}",
                        group.name
                    )));
                }
                group_members.push((group.gid, members));
                group_defs.push(group);
            }
        }
    }

    for group in group_defs {
        db.add_group(group)?;
    }
    for user in passwd_users {
        db.add_user(user)?;
    }
    // Apply shadow entries.
    for (name, hash) in shadow_entries {
        let user = db
            .find_user_by_name_mut(&name)
            .ok_or_else(|| ParseError::Inconsistent(alloc::format!("shadow entry for unknown user {name}")))?;
        user.set_password_hash(hash);
    }
    // Apply group memberships (supplementary lists on the user side).
    for (gid, members) in group_members {
        for member in members {
            if db.find_user_by_name(&member).is_none() {
                return Err(ParseError::Inconsistent(alloc::format!(
                    "group {gid} lists unknown user {member}"
                )));
            }
            db.add_user_to_group(&member, gid)?;
        }
    }
    Ok(db)
}

fn parse_passwd_line(line: &str) -> Result<User, ParseError> {
    let fields: Vec<&str> = line.split(':').collect();
    if fields.len() != 5 {
        return Err(ParseError::MalformedLine(line.into()));
    }
    let uid: u32 = fields[1]
        .parse()
        .map_err(|_| ParseError::MalformedLine(line.into()))?;
    let gid: u32 = fields[2]
        .parse()
        .map_err(|_| ParseError::MalformedLine(line.into()))?;
    Ok(User {
        uid,
        username: fields[0].into(),
        gid,
        groups: Vec::new(),
        home: fields[3].into(),
        shell: fields[4].into(),
        password_hash: None,
    })
}

/// Parse a group line into (group, member names). The group is not
/// inserted here — [`from_text`] inserts all groups before users.
fn parse_group_line(line: &str) -> Result<(Group, Vec<String>), ParseError> {
    let fields: Vec<&str> = line.split(':').collect();
    if fields.len() != 3 {
        return Err(ParseError::MalformedLine(line.into()));
    }
    let gid: u32 = fields[1]
        .parse()
        .map_err(|_| ParseError::MalformedLine(line.into()))?;
    let members: Vec<String> = if fields[2].is_empty() {
        Vec::new()
    } else {
        fields[2].split(',').map(String::from).collect()
    };
    let mut group = Group::new(gid, fields[0]);
    group.members = members.clone();
    Ok((group, members))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Group;
    use crate::password::{hash_password, Salt};

    fn seeded_db() -> UserDb {
        let mut db = UserDb::with_root();
        db.add_group(Group::new(100, "users")).unwrap();
        db.add_group(Group::new(101, "wheel")).unwrap();
        let mut alice = User::new(1000, "alice", 100, "/home/alice", "/bin/sh");
        alice.groups.push(101);
        let stored = hash_password("correct horse", &Salt::from_bytes(b"alice-salt-16byt").unwrap(), 100)
            .unwrap();
        alice.set_password_hash(stored);
        db.add_user(alice).unwrap();
        db
    }

    #[test]
    fn round_trip_preserves_everything() {
        let db = seeded_db();
        let text = to_text(&db);
        let back = from_text(&text).unwrap();
        assert_eq!(back.user_count(), db.user_count());
        assert_eq!(back.group_count(), db.group_count());
        let alice = back.find_user_by_name("alice").unwrap();
        let orig = db.find_user_by_name("alice").unwrap();
        assert_eq!(alice, orig);
        assert_eq!(alice.password_hash, orig.password_hash);
        assert_eq!(
            back.find_group_by_gid(101).unwrap(),
            db.find_group_by_gid(101).unwrap()
        );
        // Serialising twice is stable.
        assert_eq!(to_text(&back), text);
    }

    #[test]
    fn hash_stays_out_of_passwd_section() {
        let db = seeded_db();
        let passwd = to_passwd(&db);
        assert!(!passwd.contains("sha256iter"));
        let shadow = to_shadow(&db);
        assert!(shadow.contains("alice:sha256iter$"));
        // Root has no password: absent from shadow.
        assert!(!shadow.contains("root:"));
    }

    #[test]
    fn sections_serialise_independently() {
        let db = seeded_db();
        assert!(to_passwd(&db).contains("alice:1000:100:/home/alice:/bin/sh\n"));
        assert!(to_group(&db).contains("wheel:101:alice\n"));
        assert!(to_group(&db).contains("root:0:\n"));
    }

    #[test]
    fn malformed_lines_rejected() {
        // Missing header.
        assert_eq!(from_text("[passwd]\nroot:0:0:/root:/bin/sh\n"), Err(ParseError::BadHeader));
        // Wrong version.
        assert_eq!(
            from_text("# rustos-users v2\n[passwd]\n"),
            Err(ParseError::BadHeader)
        );
        // Line before any section.
        assert_eq!(
            from_text("# rustos-users v1\nroot:0:0:/root:/bin/sh\n"),
            Err(ParseError::LineOutsideSection("root:0:0:/root:/bin/sh".into()))
        );
        // Unknown section.
        assert_eq!(
            from_text("# rustos-users v1\n[other]\nx\n"),
            Err(ParseError::UnknownSection("other".into()))
        );
        // Too few passwd fields.
        assert!(matches!(
            from_text("# rustos-users v1\n[passwd]\nalice:1000:100\n"),
            Err(ParseError::MalformedLine(_))
        ));
        // Non-numeric uid.
        assert!(matches!(
            from_text("# rustos-users v1\n[passwd]\nalice:notanum:100:/home/alice:/bin/sh\n"),
            Err(ParseError::MalformedLine(_))
        ));
        // Bad group line.
        assert!(matches!(
            from_text("# rustos-users v1\n[group]\nusers:100\n"),
            Err(ParseError::MalformedLine(_))
        ));
        // Duplicate user.
        assert!(matches!(
            from_text(
                "# rustos-users v1\n[group]\nroot:0:\n[passwd]\nroot:0:0:/root:/bin/sh\nroot:0:0:/root:/bin/sh\n"
            ),
            Err(ParseError::Inconsistent(_))
        ));
        // Shadow entry for unknown user.
        assert!(matches!(
            from_text("# rustos-users v1\n[shadow]\nghost:sha256iter$1$00$00\n"),
            Err(ParseError::Inconsistent(_))
        ));
        // Group member that does not exist.
        assert!(matches!(
            from_text(
                "# rustos-users v1\n[group]\nroot:0:\nusers:100:ghost\n[passwd]\nroot:0:0:/root:/bin/sh\n"
            ),
            Err(ParseError::Inconsistent(_))
        ));
        // Unknown primary group for a user.
        assert!(matches!(
            from_text(
                "# rustos-users v1\n[passwd]\nalice:1000:999:/home/alice:/bin/sh\n"
            ),
            Err(ParseError::Db(DbError::UnknownGroup))
        ));
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let text = "# rustos-users v1\n\n# a comment\n[group]\nroot:0:\n\n[passwd]\nroot:0:0:/root:/bin/sh\n";
        let db = from_text(text).unwrap();
        assert_eq!(db.user_count(), 1);
        assert_eq!(db.group_count(), 1);
    }

    #[test]
    fn empty_db_round_trips() {
        let db = UserDb::new();
        let back = from_text(&to_text(&db)).unwrap();
        assert_eq!(back.user_count(), 0);
        assert_eq!(back.group_count(), 0);
    }
}
