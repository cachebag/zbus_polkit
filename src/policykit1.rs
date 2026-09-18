use std::{borrow::Cow, collections::HashMap, os::fd::AsFd};

use enumflags2::{bitflags, BitFlags};
use serde::{
    de::{
        self,
        value::{MapDeserializer, SeqDeserializer},
        IgnoredAny, IntoDeserializer, MapAccess, SeqAccess, Visitor,
    },
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_repr::{Deserialize_repr, Serialize_repr};
use static_assertions::assert_impl_all;
use zbus::{
    fdo, names::OwnedUniqueName, DeserializeDict, OwnedFd, OwnedValue, SerializeDict, Type, Value,
};

use crate::Error;

/// Flags used in the CheckAuthorization() method.
#[bitflags]
#[repr(u32)]
#[derive(Type, Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub enum CheckAuthorizationFlags {
    /// If the Subject can obtain the authorization through authentication, and an authentication
    /// agent is available, then attempt to do so. Note, this means that the CheckAuthorization()
    /// method will block while the user is being asked to authenticate.
    AllowUserInteraction = 0x01,
}

assert_impl_all!(CheckAuthorizationFlags: Send, Sync, Unpin);

/// An enumeration for granting implicit authorizations.
#[repr(u32)]
#[derive(Deserialize_repr, Serialize_repr, Type, Debug, PartialEq, Eq)]
pub enum ImplicitAuthorization {
    /// The Subject is not authorized.
    NotAuthorized = 0,
    /// Authentication is required.
    AuthenticationRequired = 1,
    /// Authentication as an administrator is required.
    AdministratorAuthenticationRequired = 2,
    /// Authentication is required. If the authorization is obtained, it is retained.
    AuthenticationRequiredRetained = 3,
    /// Authentication as an administrator is required. If the authorization is obtained, it is
    /// retained.
    AdministratorAuthenticationRequiredRetained = 4,
    /// The subject is authorized.
    Authorized = 5,
}

assert_impl_all!(ImplicitAuthorization: Send, Sync, Unpin);

/// Flags describing features supported by the Authority implementation.
#[bitflags]
#[repr(u32)]
#[derive(Type, Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub enum AuthorityFeatures {
    /// The authority supports temporary authorizations that can be obtained through
    /// authentication.
    TemporaryAuthorization = 0x01,
}

assert_impl_all!(AuthorityFeatures: Send, Sync, Unpin);

/// Details of a temporary authorization as provided by the /org/freedesktop/PolicyKit1/Authority
/// object in the system bus.
#[derive(Debug, Type, Deserialize, Serialize)]
pub struct TemporaryAuthorization {
    /// An opaque identifier for the temporary authorization.
    pub id: String,

    /// The action the temporary authorization is for.
    pub action_id: String,

    /// The subject the temporary authorization is for.
    pub subject: Subject,

    /// When the temporary authorization was obtained, in seconds since the Epoch Jan 1, 1970 0:00
    /// UTC. Note that the PolicyKit daemon is using monotonic time internally so the returned
    /// value may change if system time changes.
    pub time_obtained: u64,

    /// When the temporary authorization is set to expire, in seconds since the Epoch Jan 1, 1970
    /// 0:00 UTC. Note that the PolicyKit daemon is using monotonic time internally so the returned
    /// value may change if system time changes.
    pub time_expires: u64,
}

assert_impl_all!(TemporaryAuthorization: Send, Sync, Unpin);

/// This struct describes identities such as UNIX users and UNIX groups. It is typically used to
/// check if a given process is authorized for an action.
///
/// The following kinds of identities are known:
///
/// * Unix User. `identity_kind` should be set to `unix-user` with key uid (of type uint32).
///
/// * Unix Group. `identity_kind` should be set to `unix-group` with key gid (of type uint32).
#[derive(Debug, Type, Serialize)]
pub struct Identity<'a> {
    pub identity_kind: &'a str,

    pub identity_details: &'a HashMap<&'a str, Value<'a>>,
}

assert_impl_all!(Identity<'_>: Send, Sync, Unpin);

/// This enum describes subjects such as UNIX processes. It is typically used to check if a given
/// process is authorized for an action.
///
/// On the wire a subject is a kind string and a dictionary of details whose contents depend on that
/// kind. Each kind polkit documents has its details spelled out as a struct here; anything else
/// arrives as [`Subject::Other`].
#[derive(Debug, Type)]
#[zbus(signature = "(sa{sv})")]
#[non_exhaustive]
pub enum Subject {
    /// A UNIX process, sent as `unix-process`.
    UnixProcess(UnixProcess),

    /// A login session, sent as `unix-session`.
    UnixSession(UnixSession),

    /// The owner of a name on the bus, sent as `system-bus-name`.
    SystemBusName(SystemBusName),

    /// A kind of subject this crate does not know about, left as it came off the wire.
    Other {
        /// The kind the authority named.
        kind: String,

        /// The details, undecoded.
        details: HashMap<String, OwnedValue>,
    },
}

assert_impl_all!(Subject: Send, Sync, Unpin);

/// The details of a [`Subject::UnixProcess`].
///
/// polkit accepts a process in two forms, and looks up whatever it is not given in `/proc`:
///
/// * a `pidfd` and a `uid`, which is what [`Subject::new_for_owner`] sends, or
///
/// * a `pid`, a `start-time` and a `uid`, which is what [`Subject::new_for_pid`] sends.
#[derive(Debug, Default, SerializeDict, DeserializeDict, Type)]
#[zbus(signature = "a{sv}")]
pub struct UnixProcess {
    /// A pidfd naming one specific incarnation of the process.
    ///
    /// polkit only trusts this when `uid` is sent with it, and then reads the process from it
    /// rather than from `pid` and `start_time`.
    pub pidfd: Option<OwnedFd>,

    /// The process ID.
    ///
    /// A PID can be reused once the process it named exits, so `start_time` is what makes this
    /// name specific.
    pub pid: Option<u32>,

    /// The start time of `pid`, in clock ticks since boot, as in field 22 of `/proc/<pid>/stat`.
    #[zbus(rename = "start-time")]
    pub start_time: Option<u64>,

    /// The (real, not effective) uid of the owner of the process.
    ///
    /// polkit reads this as a *signed* 32-bit integer, which is why this is an `i32` and not a
    /// `u32`. Sent as any other type it is silently ignored and polkit falls back to its own racy
    /// `/proc` lookup.
    pub uid: Option<i32>,
}

assert_impl_all!(UnixProcess: Send, Sync, Unpin);

/// The details of a [`Subject::UnixSession`].
#[derive(Debug, SerializeDict, DeserializeDict, Type)]
#[zbus(signature = "a{sv}")]
pub struct UnixSession {
    /// The identifier of the session, as the login manager knows it.
    #[zbus(rename = "session-id")]
    pub session_id: String,
}

assert_impl_all!(UnixSession: Send, Sync, Unpin);

/// The details of a [`Subject::SystemBusName`].
#[derive(Debug, SerializeDict, DeserializeDict, Type)]
#[zbus(signature = "a{sv}")]
pub struct SystemBusName {
    /// The unique name of the connection that owns the subject.
    pub name: OwnedUniqueName,
}

assert_impl_all!(SystemBusName: Send, Sync, Unpin);

impl Subject {
    /// The kind this subject is sent as.
    pub fn kind(&self) -> &str {
        match self {
            Self::UnixProcess(_) => UNIX_PROCESS,
            Self::UnixSession(_) => UNIX_SESSION,
            Self::SystemBusName(_) => SYSTEM_BUS_NAME,
            Self::Other { kind, .. } => kind,
        }
    }

    /// Create a `Subject` for a process identified by `pidfd`.
    ///
    /// A pidfd names a specific process incarnation, so this is not subject to the PID-reuse
    /// race that [`new_for_pid`](Self::new_for_pid) is. Polkit requires `uid` to be sent
    /// together with a pidfd and will not look it up itself; obtain both from a trusted source
    /// at the same time (e.g. `SO_PEERPIDFD` and `SO_PEERCRED`, or `pidfd_open` and a known
    /// uid).
    ///
    /// # Arguments
    ///
    /// * `pidfd` - A pidfd for the process (from `pidfd_open(2)` or `SO_PEERPIDFD`)
    ///
    /// * `uid` - The (real, not effective) uid of the owner of the process
    pub fn new_for_owner(pidfd: impl AsFd, uid: u32) -> Result<Self, Error> {
        Ok(Self::UnixProcess(UnixProcess {
            pidfd: Some(pidfd.as_fd().try_clone_to_owned()?.into()),
            uid: Some(uid as i32),
            ..Default::default()
        }))
    }

    /// Create a `Subject` for `pid`, `start_time` & `uid`.
    ///
    /// A PID can be reused after the original process exits, so this form is racy. Prefer
    /// [`new_for_owner`](Self::new_for_owner) when the kernel and polkit support pidfds.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process ID
    ///
    /// * `start_time` - The start time for `pid` or `None` to look it up in e.g. `/proc`
    ///
    /// * `uid` - The (real, not effective) uid of the owner of `pid` or `None` to look it up in
    ///   e.g. `/proc`
    pub fn new_for_pid(pid: u32, start_time: Option<u64>, uid: Option<u32>) -> Result<Self, Error> {
        let start_time = match start_time {
            Some(s) => s,
            None => pid_start_time(pid)?,
        };
        let uid = match uid {
            Some(u) => u,
            None => pid_uid_racy(pid)?,
        };

        Ok(Self::UnixProcess(UnixProcess {
            pid: Some(pid),
            start_time: Some(start_time),
            uid: Some(uid as i32),
            pidfd: None,
        }))
    }

    /// Create a `Subject` for a message for querying if the sender of a Message is permitted to
    /// execute an action.
    ///
    /// # Arguments
    ///
    /// * `message_header` - The header of the message which caused an authentication to be
    ///   necessary.
    pub fn new_for_message_header(
        message_header: &zbus::message::Header<'_>,
    ) -> Result<Self, Error> {
        let sender = message_header.sender().ok_or(Error::MissingSender)?;

        Ok(Self::SystemBusName(SystemBusName {
            name: OwnedUniqueName::from(sender.clone()),
        }))
    }
}

impl Serialize for Subject {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut subject = serializer.serialize_struct("Subject", 2)?;
        subject.serialize_field(SUBJECT_KIND, self.kind())?;
        match self {
            Self::UnixProcess(details) => subject.serialize_field(SUBJECT_DETAILS, details)?,
            Self::UnixSession(details) => subject.serialize_field(SUBJECT_DETAILS, details)?,
            Self::SystemBusName(details) => subject.serialize_field(SUBJECT_DETAILS, details)?,
            Self::Other { details, .. } => subject.serialize_field(SUBJECT_DETAILS, details)?,
        }

        subject.end()
    }
}

impl<'de> Deserialize<'de> for Subject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_struct("Subject", SUBJECT_FIELDS, SubjectVisitor)
    }
}

struct SubjectVisitor;

impl<'de> Visitor<'de> for SubjectVisitor {
    type Value = Subject;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a subject kind and the details for that kind")
    }

    // Which type the details decode as is only known once the kind has been read, which is why
    // this is written out rather than derived.
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Subject, A::Error> {
        let kind: String = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        fn details<'de, T: Deserialize<'de>, A: SeqAccess<'de>>(
            seq: &mut A,
        ) -> Result<T, A::Error> {
            seq.next_element()?
                .ok_or_else(|| de::Error::invalid_length(1, &"the details of the subject"))
        }

        Ok(match kind.as_str() {
            UNIX_PROCESS => Subject::UnixProcess(details(&mut seq)?),
            UNIX_SESSION => Subject::UnixSession(details(&mut seq)?),
            SYSTEM_BUS_NAME => Subject::SystemBusName(details(&mut seq)?),
            _ => Subject::Other {
                kind,
                details: details(&mut seq)?,
            },
        })
    }

    // D-Bus hands the fields over as a sequence, but a self-describing format hands them over as a
    // map, and not necessarily in the order `Serialize` wrote them: `serde_json::to_value`, for
    // one, sorts keys, which puts the details before the kind. The kind is what says which type
    // the details decode as, so they are kept as they arrived until it has turned up.
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Subject, A::Error> {
        let mut kind: Option<String> = None;
        let mut details: Option<Buffered<'de>> = None;

        while let Some(field) = map.next_key::<String>()? {
            match field.as_str() {
                SUBJECT_KIND => {
                    if kind.replace(map.next_value()?).is_some() {
                        return Err(de::Error::duplicate_field(SUBJECT_KIND));
                    }
                }
                SUBJECT_DETAILS => {
                    if details.replace(map.next_value()?).is_some() {
                        return Err(de::Error::duplicate_field(SUBJECT_DETAILS));
                    }
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }

        let kind = kind.ok_or_else(|| de::Error::missing_field(SUBJECT_KIND))?;
        let details = details.ok_or_else(|| de::Error::missing_field(SUBJECT_DETAILS))?;
        fn decode<'de, T: Deserialize<'de>, E: de::Error>(details: Buffered<'de>) -> Result<T, E> {
            T::deserialize(details).map_err(E::custom)
        }

        Ok(match kind.as_str() {
            UNIX_PROCESS => Subject::UnixProcess(decode(details)?),
            UNIX_SESSION => Subject::UnixSession(decode(details)?),
            SYSTEM_BUS_NAME => Subject::SystemBusName(decode(details)?),
            _ => Subject::Other {
                kind,
                details: decode(details)?,
            },
        })
    }
}

/// A value kept exactly as a self-describing format handed it over, for when what it has to
/// decode as is not known until later.
///
/// Only the map path of [`SubjectVisitor`] needs this, for details that arrive before their kind.
/// Borrowed strings and bytes stay borrowed: an unknown kind's details decode as [`OwnedValue`],
/// whose signature still deserializes only from a borrowed string, so replaying an owned copy
/// would not do. (A known kind's typed details go through zbus's `as_value`, which takes either.)
/// Numbers keep the widest form the format offered, which is the form serde's own integer visitors
/// narrow from.
enum Buffered<'de> {
    Bool(bool),
    Signed(i64),
    Unsigned(u64),
    Float(f64),
    Str(Cow<'de, str>),
    Bytes(Cow<'de, [u8]>),
    Unit,
    None,
    Some(Box<Buffered<'de>>),
    Seq(Vec<Buffered<'de>>),
    Map(Vec<(Buffered<'de>, Buffered<'de>)>),
}

impl<'de> Deserialize<'de> for Buffered<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(BufferedVisitor)
    }
}

struct BufferedVisitor;

impl<'de> Visitor<'de> for BufferedVisitor {
    type Value = Buffered<'de>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any value")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
        Ok(Buffered::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        Ok(Buffered::Signed(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        Ok(Buffered::Unsigned(v))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
        Ok(Buffered::Float(v))
    }

    fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<Self::Value, E> {
        Ok(Buffered::Str(Cow::Borrowed(v)))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(Buffered::Str(Cow::Owned(v.to_owned())))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
        Ok(Buffered::Str(Cow::Owned(v)))
    }

    fn visit_borrowed_bytes<E: de::Error>(self, v: &'de [u8]) -> Result<Self::Value, E> {
        Ok(Buffered::Bytes(Cow::Borrowed(v)))
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        Ok(Buffered::Bytes(Cow::Owned(v.to_vec())))
    }

    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
        Ok(Buffered::Bytes(Cow::Owned(v)))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Buffered::Unit)
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Buffered::None)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        Buffered::deserialize(deserializer).map(|v| Buffered::Some(Box::new(v)))
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        Buffered::deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }

        Ok(Buffered::Seq(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut entries = Vec::new();
        while let Some(entry) = map.next_entry()? {
            entries.push(entry);
        }

        Ok(Buffered::Map(entries))
    }
}

impl<'de> IntoDeserializer<'de, de::value::Error> for Buffered<'de> {
    type Deserializer = Self;

    fn into_deserializer(self) -> Self {
        self
    }
}

impl<'de> Deserializer<'de> for Buffered<'de> {
    type Error = de::value::Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self {
            Self::Bool(v) => visitor.visit_bool(v),
            Self::Signed(v) => visitor.visit_i64(v),
            Self::Unsigned(v) => visitor.visit_u64(v),
            Self::Float(v) => visitor.visit_f64(v),
            Self::Str(Cow::Borrowed(v)) => visitor.visit_borrowed_str(v),
            Self::Str(Cow::Owned(v)) => visitor.visit_string(v),
            Self::Bytes(Cow::Borrowed(v)) => visitor.visit_borrowed_bytes(v),
            Self::Bytes(Cow::Owned(v)) => visitor.visit_byte_buf(v),
            Self::Unit => visitor.visit_unit(),
            Self::None => visitor.visit_none(),
            Self::Some(v) => visitor.visit_some(*v),
            Self::Seq(v) => visitor.visit_seq(SeqDeserializer::new(v.into_iter())),
            Self::Map(v) => visitor.visit_map(MapDeserializer::new(v.into_iter())),
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self {
            Self::None | Self::Unit => visitor.visit_none(),
            Self::Some(v) => visitor.visit_some(*v),
            present => visitor.visit_some(present),
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf unit
        unit_struct seq tuple tuple_struct map struct enum identifier ignored_any
    }
}

const SUBJECT_KIND: &str = "subject_kind";
const SUBJECT_DETAILS: &str = "subject_details";
const SUBJECT_FIELDS: &[&str] = &[SUBJECT_KIND, SUBJECT_DETAILS];
const UNIX_PROCESS: &str = "unix-process";
const UNIX_SESSION: &str = "unix-session";
const SYSTEM_BUS_NAME: &str = "system-bus-name";

fn pid_start_time(pid: u32) -> Result<u64, Error> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_start_time(&stat)
}

// Extract the process start time (field 22 of proc(5) `stat`, in clock ticks since boot).
//
// The second field, `comm`, is the executable name wrapped in parentheses and may itself contain
// spaces and parentheses, so fields are counted from the *last* closing parenthesis rather than
// from the start of the line.
fn parse_start_time(stat: &str) -> Result<u64, Error> {
    let start_time = stat
        .rfind(')')
        .and_then(|i| stat[i..].split(' ').nth(20))
        .ok_or(Error::MalformedProc("start-time"))?;

    Ok(start_time.parse()?)
}

// Return the "current" UID.  Note that this is inherently racy, and the value may already be
// obsolete by the time this function returns; this function only guarantees that the UID was valid
// at some point during its execution.
fn pid_uid_racy(pid: u32) -> Result<u32, Error> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    parse_uid(&status)
}

// Extract the real UID from the contents of proc(5) `status`.
//
// The `Uid:` line lists the real, effective, saved set and filesystem UIDs; only the first one is
// returned, since that is what polkit expects in a `unix-process` subject.
fn parse_uid(status: &str) -> Result<u32, Error> {
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|uids| uids.split_whitespace().next())
        .ok_or(Error::MalformedProc("uid"))?;

    Ok(uid.parse()?)
}

/// This struct describes actions registered with the PolicyKit daemon.
#[derive(Debug, Type, Serialize, Deserialize)]
pub struct ActionDescription {
    /// Action Identifier.
    pub action_id: String,

    /// Localized description of the action.
    pub description: String,

    /// Localized message to be displayed when making the user authenticate for an action.
    pub message: String,

    /// Name of the provider of the action or the empty string.
    pub vendor_name: String,

    /// A URL pointing to a place with more information about the action or the empty string.
    pub vendor_url: String,

    /// The themed icon describing the action or the empty string if no icon is set.
    pub icon_name: String,

    /// A value from the ImplicitAuthorization. enumeration for implicit authorizations that apply
    /// to any Subject.
    pub implicit_any: ImplicitAuthorization,

    /// A value from the ImplicitAuthorization. enumeration for implicit authorizations that apply
    /// any Subject in an inactive user session on the local console.
    pub implicit_inactive: ImplicitAuthorization,

    /// A value from the ImplicitAuthorization. enumeration for implicit authorizations that apply
    /// any Subject in an active user session on the local console.
    pub implicit_active: ImplicitAuthorization,

    /// Annotations for the action.
    pub annotations: HashMap<String, String>,
}

assert_impl_all!(ActionDescription: Send, Sync, Unpin);

/// Describes the result of calling `CheckAuthorization()`
#[derive(Debug, Type, Serialize, Deserialize)]
pub struct AuthorizationResult {
    /// TRUE if the given `Subject` is authorized for the given action.
    pub is_authorized: bool,

    /// TRUE if the given `Subject` could be authorized if more information was provided, and
    /// `CheckAuthorizationFlags::AllowUserInteraction` wasn't passed or no suitable authentication
    /// agent was available.
    pub is_challenge: bool,

    /// Details for the result. Known key/value-pairs include `polkit.temporary_authorization_id`
    /// (if the authorization is temporary, this is set to the opaque temporary authorization id),
    /// `polkit.retains_authorization_after_challenge` (Set to a non-empty string if the
    /// authorization will be retained after authentication (if is_challenge is TRUE)),
    /// `polkit.dismissed` (Set to a non-empty string if the authentication dialog was dismissed by
    /// the user).
    pub details: std::collections::HashMap<String, String>,
}

assert_impl_all!(AuthorizationResult: Send, Sync, Unpin);

/// This D-Bus interface is implemented by the /org/freedesktop/PolicyKit1/Authority object on the
/// well-known name org.freedesktop.PolicyKit1 on the system message bus.
#[zbus::proxy(
    interface = "org.freedesktop.PolicyKit1.Authority",
    default_service = "org.freedesktop.PolicyKit1",
    default_path = "/org/freedesktop/PolicyKit1/Authority"
)]
pub trait Authority {
    /// Method for authentication agents to invoke on successful authentication, intended only for
    /// use by a privileged helper process internal to polkit. This method will fail unless a
    /// sufficiently privileged +caller invokes it. Deprecated in favor of
    /// `AuthenticationAgentResponse2()`.
    fn authentication_agent_response(
        &self,
        cookie: &str,
        identity: &Identity<'_>,
    ) -> zbus::Result<()>;

    /// Method for authentication agents to invoke on successful authentication, intended only for
    /// use by a privileged helper process internal to polkit. This method will fail unless a
    /// sufficiently privileged caller invokes it. Note this method was introduced in 0.114 and
    /// should be preferred over `AuthenticationAgentResponse()` as it fixes a security issue.
    fn authentication_agent_response2(
        &self,
        uid: u32,
        cookie: &str,
        identity: &Identity<'_>,
    ) -> zbus::Result<()>;

    /// Cancels an authorization check.
    ///
    /// # Arguments
    ///
    /// * `cancellation_id` - The cancellation_id passed to `CheckAuthorization()`.
    fn cancel_check_authorization(&self, cancellation_id: &str) -> zbus::Result<()>;

    /// Checks if subject is authorized to perform the action with identifier `action_id`
    ///
    /// If `cancellation_id` is non-empty and already in use for the caller, the
    /// `org.freedesktop.PolicyKit1.Error.CancellationIdNotUnique` error is returned.
    ///
    /// Note that `CheckAuthorizationFlags::AllowUserInteraction` SHOULD be passed ONLY if the event
    /// that triggered the authorization check is stemming from an user action, e.g. the user
    /// pressing a button or attaching a device.
    ///
    /// # Arguments
    ///
    /// * `subject` - A Subject struct.
    ///
    /// * `action_id` - Identifier for the action that subject is attempting to do.
    ///
    /// * `details` - Details describing the action. Keys starting with `polkit.` can only be set
    /// if defined in this document.
    ///
    /// Known keys include `polkit.message` and `polkit.gettext_domain` that can be used to override
    /// the message shown to the user. This latter is needed because the user could be running an
    /// authentication agent in another locale than the calling process.
    ///
    /// The (translated version of) `polkit.message` may include references to other keys that are
    /// expanded with their respective values. For example if the key `device_file` has the value
    /// `/dev/sda` then the message "Authenticate to format $(device_file)" is expanded to
    /// "Authenticate to format /dev/sda".
    ///
    /// The key `polkit.icon_name` is used to override the icon shown in the authentication dialog.
    ///
    /// If non-empty, then the request will fail with `org.freedesktop.PolicyKit1.Error.Failed`
    /// unless the process doing the check itself is sufficiently authorized (e.g. running as uid
    /// 0).
    ///
    /// * `flags` - A set of `CheckAuthorizationFlags`.
    ///
    /// * `cancellation_id` - A unique id used to cancel the the authentication check via
    /// `CancelCheckAuthorization()` or the empty string if cancellation is not needed.
    ///
    /// Returns: An `AuthorizationResult` structure.
    fn check_authorization(
        &self,
        subject: &Subject,
        action_id: &str,
        details: &std::collections::HashMap<&str, &str>,
        flags: BitFlags<CheckAuthorizationFlags>,
        cancellation_id: &str,
    ) -> zbus::Result<AuthorizationResult>;

    /// Enumerates all registered PolicyKit actions.
    ///
    /// # Arguments:
    ///
    /// * `locale` - The locale to get descriptions in or the blank string to use the system locale.
    fn enumerate_actions(&self, locale: &str) -> zbus::Result<Vec<ActionDescription>>;

    /// Retrieves all temporary authorizations that applies to subject.
    fn enumerate_temporary_authorizations(
        &self,
        subject: &Subject,
    ) -> zbus::Result<Vec<TemporaryAuthorization>>;

    /// Register an authentication agent.
    ///
    /// Note that this should be called by same effective UID which will be passed to
    /// `AuthenticationAgentResponse2()`.
    ///
    /// # Arguments
    ///
    /// * `subject` - The subject to register the authentication agent for, typically a session
    /// subject.
    ///
    /// * `locale` - The locale of the authentication agent.
    ///
    /// * `object_path` - The object path of authentication agent object on the unique name of the
    /// caller.
    fn register_authentication_agent(
        &self,
        subject: &Subject,
        locale: &str,
        object_path: &str,
    ) -> zbus::Result<()>;

    /// Like `RegisterAuthenticationAgent` but takes additional options. If the option fallback (of
    /// type Boolean) is TRUE, then the authentication agent will only be used as a fallback, e.g.
    /// if another agent (without the fallback option set TRUE) is available, it will be used
    /// instead.
    fn register_authentication_agent_with_options(
        &self,
        subject: &Subject,
        locale: &str,
        object_path: &str,
        options: &std::collections::HashMap<&str, Value<'_>>,
    ) -> zbus::Result<()>;

    /// Revokes all temporary authorizations that applies to `id`.
    fn revoke_temporary_authorization_by_id(&self, id: &str) -> zbus::Result<()>;

    /// Revokes all temporary authorizations that applies to `subject`.
    fn revoke_temporary_authorizations(&self, subject: &Subject) -> zbus::Result<()>;

    /// Unregister an authentication agent.
    ///
    /// # Arguments
    ///
    /// * `subject` - The subject passed to `RegisterAuthenticationAgent()`.
    ///
    /// * `object_path` - The object_path passed to `RegisterAuthenticationAgent()`.
    fn unregister_authentication_agent(
        &self,
        subject: &Subject,
        object_path: &str,
    ) -> zbus::Result<()>;

    /// This signal is emitted when actions and/or authorizations change
    #[zbus(signal)]
    fn changed(&self) -> fdo::Result<()>;

    /// The features supported by the currently used Authority backend.
    ///
    /// This is a flag set, not a single feature: a backend without any of them reports an empty
    /// set, and a newer polkit may report a bit this crate does not name yet, which is an error
    /// rather than an unnamed variant.
    #[zbus(property)]
    fn backend_features(&self) -> fdo::Result<BitFlags<AuthorityFeatures>>;

    /// The name of the currently used Authority backend.
    #[zbus(property)]
    fn backend_name(&self) -> fdo::Result<String>;

    /// The version of the currently used Authority backend.
    #[zbus(property)]
    fn backend_version(&self) -> fdo::Result<String>;
}

assert_impl_all!(AuthorityProxy<'_>: Send, Sync, Unpin);
#[cfg(feature = "blocking-api")]
assert_impl_all!(AuthorityProxyBlocking<'_>: Send, Sync, Unpin);

#[cfg(test)]
mod tests {
    use zbus::{
        message::Message,
        wire::{serialized::Context, to_bytes, LE},
    };

    use super::*;

    /// The `(kind, details)` pair `subject` is sent as, read back off the wire.
    fn sent_as(subject: &Subject) -> (String, HashMap<String, OwnedValue>) {
        let encoded = to_bytes(Context::new(LE, 0), subject).expect("serialize the subject");

        encoded
            .deserialize()
            .expect("decode the subject as the types polkit reads")
            .0
    }

    /// A `Subject` decoded from the `(kind, details)` pair an authority would send.
    fn received_as<const N: usize>(kind: &str, details: [(&str, Value<'_>); N]) -> Subject {
        let details: HashMap<String, OwnedValue> = details
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.try_into().unwrap()))
            .collect();
        let encoded =
            to_bytes(Context::new(LE, 0), &(kind.to_string(), details)).expect("serialize details");

        encoded.deserialize().expect("decode a subject").0
    }

    #[cfg(unix)]
    #[test]
    fn subject_for_owner_sends_pidfd_and_uid() {
        // What is on the other end of the descriptor does not matter here: `new_for_owner` takes
        // any `AsFd`, and what is under test is how it is sent, not what polkit makes of it.
        let pidfd = std::fs::File::open("/dev/null").unwrap();
        let subject = Subject::new_for_owner(&pidfd, 1234).unwrap();

        let Subject::UnixProcess(details) = &subject else {
            panic!("expected a unix-process subject, got {subject:?}");
        };
        assert!(details.pidfd.is_some());
        assert_eq!(details.uid, Some(1234));
        // A pidfd names one incarnation of the process, so polkit needs neither of these, and
        // ignores them when a pidfd is there.
        assert_eq!(details.pid, None);
        assert_eq!(details.start_time, None);

        let (kind, sent) = sent_as(&subject);

        assert_eq!(kind, "unix-process");
        assert_eq!(sent.len(), 2);
        // A UNIX_FD ('h'), not a raw i32: polkit looks the handle up in the message's fd list.
        // Sent as any other type it is ignored and polkit falls back to pid+start-time.
        assert_eq!(sent["pidfd"].value_signature().to_string(), "h");
        // polkit refuses a pidfd subject without a uid, and ignores a uid that is not i32.
        assert_eq!(*sent["uid"], Value::I32(1234));
    }

    #[test]
    fn subject_for_pid_uses_polkit_wire_types() {
        let subject = Subject::new_for_pid(4242, Some(1_000_000), Some(1234)).unwrap();
        let (kind, sent) = sent_as(&subject);

        assert_eq!(kind, "unix-process");
        // A pidfd is absent rather than sent as an empty value, so polkit reads the process from
        // the fields below.
        assert_eq!(sent.len(), 3);
        assert_eq!(*sent["pid"], Value::U32(4242));
        assert_eq!(*sent["start-time"], Value::U64(1_000_000));
        // polkit reads `uid` as a signed 32-bit integer. Sent as any other type it is silently
        // ignored and polkit falls back to its own racy /proc lookup, which defeats the purpose
        // of passing a UID obtained from a trusted source (see #101).
        assert_eq!(*sent["uid"], Value::I32(1234));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn subject_for_pid_looks_up_the_process_in_proc() {
        use std::os::unix::fs::MetadataExt;

        let pid = std::process::id();
        let subject = Subject::new_for_pid(pid, None, None).unwrap();

        // /proc/<pid> is owned by the process's UID, which gives us an independent source of
        // truth that doesn't go through the parser under test.
        let uid = std::fs::metadata("/proc/self").unwrap().uid();
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        let start_time = parse_start_time(&stat).unwrap();

        let Subject::UnixProcess(details) = &subject else {
            panic!("expected a unix-process subject, got {subject:?}");
        };
        assert_eq!(details.pid, Some(pid));
        assert_eq!(details.uid, Some(uid as i32));
        assert_eq!(details.start_time, Some(start_time));
    }

    #[test]
    fn subject_decodes_the_details_of_the_kind_it_was_sent_as() {
        // What polkit puts in a temporary authorization: no pidfd, and on older versions no uid
        // either, so a missing key cannot be an error. A key this crate does not know about cannot
        // be one either, or a future polkit would stop being readable.
        let process = received_as(
            "unix-process",
            [
                ("pid", Value::U32(4242)),
                ("start-time", Value::U64(7)),
                ("something-new", Value::from("ignore me")),
            ],
        );
        let Subject::UnixProcess(details) = &process else {
            panic!("expected a unix-process subject, got {process:?}");
        };
        assert_eq!(details.pid, Some(4242));
        assert_eq!(details.start_time, Some(7));
        assert_eq!(details.uid, None);
        assert!(details.pidfd.is_none());

        let session = received_as("unix-session", [("session-id", Value::from("c2"))]);
        let Subject::UnixSession(details) = &session else {
            panic!("expected a unix-session subject, got {session:?}");
        };
        assert_eq!(details.session_id, "c2");

        let bus_name = received_as("system-bus-name", [("name", Value::from(":1.42"))]);
        let Subject::SystemBusName(details) = &bus_name else {
            panic!("expected a system-bus-name subject, got {bus_name:?}");
        };
        assert_eq!(details.name.as_str(), ":1.42");
    }

    // `Serialize` writes a struct, which D-Bus takes as the sequence `visit_seq` reads but a
    // self-describing format takes as a map. Both have to decode, or a `Subject` cannot be read
    // back out of anything it was written to.
    #[test]
    fn subject_decodes_from_a_map_as_well_as_a_sequence() {
        let subject = Subject::Other {
            kind: "brand-new-kind".into(),
            details: HashMap::from([(
                "k".to_string(),
                OwnedValue::try_from(Value::from("v")).unwrap(),
            )]),
        };

        let json = serde_json::to_string(&subject).unwrap();
        let Subject::Other { kind, details } = serde_json::from_str::<Subject>(&json).unwrap()
        else {
            panic!("decoded as something other than an unknown kind");
        };

        assert_eq!(kind, "brand-new-kind");
        assert_eq!(*details["k"], Value::from("v"));
    }

    // A kind with no details set exercises the same dispatch for a variant this crate does know.
    #[test]
    fn subject_decodes_a_known_kind_from_a_map() {
        let subject: Subject =
            serde_json::from_str(r#"{"subject_kind":"unix-process","subject_details":{}}"#)
                .unwrap();

        let Subject::UnixProcess(details) = &subject else {
            panic!("decoded as {subject:?}");
        };
        assert_eq!(details.pid, None);
        assert_eq!(details.uid, None);
    }

    // A known kind's typed details go through zbus's `as_value` wrapper, which takes both the map
    // a self-describing format writes and either input form, so these round-trip through a borrowed
    // input (`from_str`) and an owned one (`serde_json::Value`) alike. It also proves the wrapper
    // keeps integer widths: `pid` comes back the `u32` it left as, not the format's widest integer.
    #[test]
    fn subject_round_trips_through_a_self_describing_format() {
        let session = Subject::UnixSession(UnixSession {
            session_id: "c2".into(),
        });
        for back in [
            serde_json::from_str::<Subject>(&serde_json::to_string(&session).unwrap()).unwrap(),
            serde_json::from_value::<Subject>(serde_json::to_value(&session).unwrap()).unwrap(),
        ] {
            let Subject::UnixSession(details) = back else {
                panic!("decoded as another kind");
            };
            assert_eq!(details.session_id, "c2");
        }

        let process = Subject::new_for_pid(4242, Some(1_000_000), Some(1234)).unwrap();
        for back in [
            serde_json::from_str::<Subject>(&serde_json::to_string(&process).unwrap()).unwrap(),
            serde_json::from_value::<Subject>(serde_json::to_value(&process).unwrap()).unwrap(),
        ] {
            let Subject::UnixProcess(details) = back else {
                panic!("decoded as another kind");
            };
            assert_eq!(details.pid, Some(4242));
            assert_eq!(details.start_time, Some(1_000_000));
            assert_eq!(details.uid, Some(1234));
            assert!(details.pidfd.is_none());
        }

        // And enclosed in something the derive handles, since that is how one usually arrives.
        let authorization = TemporaryAuthorization {
            id: "x".into(),
            action_id: "a".into(),
            subject: session,
            time_obtained: 1,
            time_expires: 2,
        };
        for back in [
            serde_json::from_str::<TemporaryAuthorization>(
                &serde_json::to_string(&authorization).unwrap(),
            )
            .unwrap(),
            serde_json::from_value::<TemporaryAuthorization>(
                serde_json::to_value(&authorization).unwrap(),
            )
            .unwrap(),
        ] {
            assert_eq!(back.id, "x");
            assert!(matches!(back.subject, Subject::UnixSession(_)));
        }
    }

    // The details can arrive before the kind: `serde_json::to_value` sorts keys, which puts them
    // first. The kind is what says how to read them, so they are held until it turns up. An
    // unknown kind's details are an `OwnedValue` map, whose signature still decodes only from a
    // borrowed string, so this uses a borrowed `from_str` input; the same subject through
    // `to_value`/`from_value` would fail on that, unlike the known kinds in the round-trip test.
    #[test]
    fn subject_decodes_its_details_before_its_kind() {
        // What `serde_json::to_value(&Subject::Other { .. }).unwrap()` lays the keys out as.
        let reversed = r#"{"subject_details":{"k":{"signature":"s","value":"v"}},"subject_kind":"brand-new-kind"}"#;

        let Subject::Other { kind, details } = serde_json::from_str::<Subject>(reversed).unwrap()
        else {
            panic!("decoded as something other than an unknown kind");
        };
        assert_eq!(kind, "brand-new-kind");
        assert_eq!(*details["k"], Value::from("v"));
    }

    #[test]
    fn subject_keeps_a_kind_it_does_not_know_as_it_arrived() {
        let subject = received_as("unix-netgroup", [("name", Value::from("engineering"))]);

        let Subject::Other { kind, details } = &subject else {
            panic!("expected an unknown kind to be kept, got {subject:?}");
        };
        assert_eq!(kind, "unix-netgroup");
        assert_eq!(*details["name"], Value::from("engineering"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn subject_for_pid_fails_for_a_missing_process() {
        // pid_max is capped at 2^22 on Linux, so this PID can never exist.
        let err = Subject::new_for_pid(u32::MAX, None, None).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "{err:?}");
    }

    #[test]
    fn start_time_is_field_22_counted_from_the_last_paren() {
        // proc(5): pid, (comm), state, ppid, pgrp, session, tty_nr, tpgid, flags, minflt,
        // cminflt, majflt, cmajflt, utime, stime, cutime, cstime, priority, nice, num_threads,
        // itrealvalue, starttime, vsize, rss, ...
        let stat = "1 (systemd) S 0 1 1 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 42 12345678 100\n";
        assert_eq!(parse_start_time(stat).unwrap(), 42);

        // `comm` is not escaped, so a process name containing spaces and parentheses shifts
        // every naive field count. Counting from the last `)` is what makes this work.
        let stat = "1234 (my (weird) proc) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 \
                    0 987654 12345678 100\n";
        assert_eq!(parse_start_time(stat).unwrap(), 987654);
    }

    #[test]
    fn start_time_rejects_malformed_stat() {
        assert!(matches!(parse_start_time(""), Err(Error::MalformedProc(_))));
        assert!(matches!(
            parse_start_time("no parens here"),
            Err(Error::MalformedProc(_))
        ));
        // Too few fields after `comm`.
        assert!(matches!(
            parse_start_time("1234 (x) S 1 1234"),
            Err(Error::MalformedProc(_))
        ));
        // Field 22 present but not a number.
        let stat = "1 (x) S 0 1 1 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 forty-two 12345678 100";
        assert!(matches!(parse_start_time(stat), Err(Error::ParseInt(_))));
    }

    #[test]
    fn uid_is_the_real_uid_from_status() {
        let status = "Name:\tmy proc\n\
                      Umask:\t0022\n\
                      State:\tS (sleeping)\n\
                      Tgid:\t1234\n\
                      Pid:\t1234\n\
                      PPid:\t1\n\
                      TracerPid:\t0\n\
                      Uid:\t1000\t1001\t1002\t1003\n\
                      Gid:\t2000\t2001\t2002\t2003\n";
        // Real UID, not effective (1001) or saved-set (1002).
        assert_eq!(parse_uid(status).unwrap(), 1000);
    }

    #[test]
    fn uid_rejects_malformed_status() {
        assert!(matches!(parse_uid(""), Err(Error::MalformedProc(_))));
        assert!(matches!(
            parse_uid("Name:\tx\nGid:\t0\t0\t0\t0\n"),
            Err(Error::MalformedProc(_))
        ));
        assert!(matches!(parse_uid("Uid:\n"), Err(Error::MalformedProc(_))));
        assert!(matches!(
            parse_uid("Uid:\tnobody\n"),
            Err(Error::ParseInt(_))
        ));
    }

    // Signatures as documented in the polkit D-Bus API reference:
    // https://polkit.pages.freedesktop.org/polkit/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html
    #[test]
    fn wire_signatures_match_polkit() {
        assert_eq!(Subject::SIGNATURE.to_string(), "(sa{sv})");
        assert_eq!(UnixProcess::SIGNATURE.to_string(), "a{sv}");
        assert_eq!(UnixSession::SIGNATURE.to_string(), "a{sv}");
        assert_eq!(SystemBusName::SIGNATURE.to_string(), "a{sv}");
        assert_eq!(<Identity<'_>>::SIGNATURE.to_string(), "(sa{sv})");
        assert_eq!(
            TemporaryAuthorization::SIGNATURE.to_string(),
            "(ss(sa{sv})tt)"
        );
        assert_eq!(ActionDescription::SIGNATURE.to_string(), "(ssssssuuua{ss})");
        assert_eq!(AuthorizationResult::SIGNATURE.to_string(), "(bba{ss})");

        assert_eq!(CheckAuthorizationFlags::SIGNATURE.to_string(), "u");
        assert_eq!(
            BitFlags::<CheckAuthorizationFlags>::SIGNATURE.to_string(),
            "u"
        );
        assert_eq!(ImplicitAuthorization::SIGNATURE.to_string(), "u");
        assert_eq!(AuthorityFeatures::SIGNATURE.to_string(), "u");
    }

    #[test]
    fn enums_serialize_as_their_u32_discriminant() {
        let ctxt = Context::new(LE, 0);

        let encoded = to_bytes(ctxt, &ImplicitAuthorization::Authorized).unwrap();
        assert_eq!(encoded.bytes(), 5u32.to_le_bytes());
        let (decoded, _) = encoded.deserialize::<ImplicitAuthorization>().unwrap();
        assert_eq!(decoded, ImplicitAuthorization::Authorized);

        let flags: BitFlags<CheckAuthorizationFlags> =
            CheckAuthorizationFlags::AllowUserInteraction.into();
        let encoded = to_bytes(ctxt, &flags).unwrap();
        assert_eq!(encoded.bytes(), 1u32.to_le_bytes());
    }

    #[test]
    fn authority_features_decode_from_their_bits() {
        let ctxt = Context::new(LE, 0);
        let decode = |bits: u32| {
            to_bytes(ctxt, &bits)
                .unwrap()
                .deserialize::<BitFlags<AuthorityFeatures>>()
                .map(|(features, _)| features)
        };

        assert_eq!(
            decode(1).unwrap(),
            AuthorityFeatures::TemporaryAuthorization
        );
        // A backend that supports none of them is not an error.
        assert!(decode(0).unwrap().is_empty());
        // A bit this crate does not name is. The previous `transmute` turned it into an
        // `AuthorityFeatures` that matched no variant.
        assert!(decode(0b10).is_err());
    }

    #[test]
    fn subject_for_message_header_uses_the_sender_bus_name() {
        let msg = Message::method_call("/org/example/Object", "Frobnicate")
            .sender(":1.42")
            .build(&())
            .unwrap();

        let subject = Subject::new_for_message_header(&msg.header()).unwrap();

        let Subject::SystemBusName(details) = &subject else {
            panic!("expected a system-bus-name subject, got {subject:?}");
        };
        assert_eq!(details.name.as_str(), ":1.42");

        let (kind, sent) = sent_as(&subject);

        assert_eq!(kind, "system-bus-name");
        assert_eq!(sent.len(), 1);
        assert_eq!(*sent["name"], Value::Str(":1.42".into()));
    }

    #[test]
    fn subject_for_message_header_requires_a_sender() {
        let msg = Message::method_call("/org/example/Object", "Frobnicate")
            .build(&())
            .unwrap();

        let err = Subject::new_for_message_header(&msg.header()).unwrap_err();
        assert!(matches!(err, Error::MissingSender), "{err:?}");
    }
}
