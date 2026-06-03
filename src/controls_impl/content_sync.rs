use std::collections::HashSet;

use crate::ResultEntry;
use crate::controls::{ControlParser, MakeCritical, RawControl};
use crate::result::{LdapError, Result};

use bytes::BytesMut;

use lber::common::TagClass;
use lber::parse::{parse_tag, parse_uint};
use lber::structure::{PL, StructureTag};
use lber::structures::{ASNTag, Boolean, Enumerated, OctetString, Sequence, Tag};
use lber::universal::Types;
use lber::{IResult, write};

pub const SYNC_REQUEST_OID: &str = "1.3.6.1.4.1.4203.1.9.1.1";
pub const SYNC_STATE_OID: &str = "1.3.6.1.4.1.4203.1.9.1.2";
pub const SYNC_DONE_OID: &str = "1.3.6.1.4.1.4203.1.9.1.3";
const SYNC_INFO_OID: &str = "1.3.6.1.4.1.4203.1.9.1.4";

/// Sync Request control ([RFC 4533](https://tools.ietf.org/html/rfc4533)).
#[derive(Clone, Debug, Default)]
pub struct SyncRequest {
    pub mode: RefreshMode,
    pub cookie: Option<Vec<u8>>,
    pub reload_hint: bool,
}

/// Content refresh mode.
///
/// See the Content Synchronization specification
/// ([RFC 4533](https://tools.ietf.org/html/rfc4533)).
#[derive(Clone, Debug, Default)]
pub enum RefreshMode {
    #[default]
    RefreshOnly,
    RefreshAndPersist,
}

impl From<RefreshMode> for i64 {
    fn from(mode: RefreshMode) -> i64 {
        match mode {
            RefreshMode::RefreshOnly => 1,
            RefreshMode::RefreshAndPersist => 3,
        }
    }
}

impl MakeCritical for SyncRequest {}

impl From<SyncRequest> for RawControl {
    fn from(sr: SyncRequest) -> RawControl {
        let mut cap_est = 16; // covers sequence, selector and hint if any
        let mut tags = vec![Tag::Enumerated(Enumerated {
            inner: i64::from(sr.mode),
            ..Default::default()
        })];
        if let Some(cookie) = sr.cookie {
            cap_est += cookie.len();
            tags.push(Tag::OctetString(OctetString {
                inner: cookie,
                ..Default::default()
            }));
        }
        if sr.reload_hint {
            tags.push(Tag::Boolean(Boolean {
                inner: sr.reload_hint,
                ..Default::default()
            }));
        }
        let sreq = Tag::Sequence(Sequence {
            inner: tags,
            ..Default::default()
        })
        .into_structure();
        let mut buf = BytesMut::with_capacity(cap_est);
        write::encode_into(&mut buf, sreq).expect("encoded");
        RawControl {
            ctype: SYNC_REQUEST_OID.to_owned(),
            crit: false,
            val: Some(Vec::from(&buf[..])),
        }
    }
}

/// Sync State response control ([RFC 4533](https://tools.ietf.org/html/rfc4533)).
#[derive(Debug)]
pub struct SyncState {
    pub state: EntryState,
    pub entry_uuid: Vec<u8>,
    pub cookie: Option<Vec<u8>>,
}

/// Possible states for the Sync State control.
#[derive(Debug)]
pub enum EntryState {
    Present,
    Add,
    Modify,
    Delete,
}

impl SyncState {
    /// Parse a Sync State control value, returning a decoding error on a
    /// malformed or unexpected value.
    pub fn try_parse(val: &[u8]) -> Result<Self> {
        fn decode<S: Into<String>>(msg: S) -> LdapError {
            LdapError::DecodingError(msg.into())
        }

        let mut tags = match parse_tag(val) {
            IResult::Ok((_, tag)) => tag,
            _ => return Err(decode("syncstate: failed to parse tag")),
        }
        .expect_constructed()
        .ok_or_else(|| decode("syncstate: elements"))?
        .into_iter();
        let state = match match parse_uint(
            tags.next()
                .ok_or_else(|| decode("syncstate: missing state element"))?
                .match_class(TagClass::Universal)
                .and_then(|t| t.match_id(Types::Enumerated as u64))
                .and_then(|t| t.expect_primitive())
                .ok_or_else(|| decode("syncstate: state"))?
                .as_slice(),
        ) {
            Ok((_, state)) => state,
            _ => return Err(decode("syncstate: failed to parse state")),
        } {
            0 => EntryState::Present,
            1 => EntryState::Add,
            2 => EntryState::Modify,
            3 => EntryState::Delete,
            _ => return Err(decode("syncstate: unknown state")),
        };
        let entry_uuid = tags
            .next()
            .ok_or_else(|| decode("syncstate: missing entryUUID element"))?
            .expect_primitive()
            .ok_or_else(|| decode("syncstate: entryUUID"))?;
        let cookie = match tags.next() {
            None => None,
            Some(tag) => Some(
                tag.expect_primitive()
                    .ok_or_else(|| decode("syncstate: synCookie"))?,
            ),
        };
        Ok(SyncState {
            state,
            entry_uuid,
            cookie,
        })
    }
}

impl ControlParser for SyncState {
    fn parse(val: &[u8]) -> Self {
        SyncState::try_parse(val).expect("syncstate")
    }
}

/// Sync Done response control ([RFC 4533](https://tools.ietf.org/html/rfc4533)).
#[derive(Debug)]
pub struct SyncDone {
    pub cookie: Option<Vec<u8>>,
    pub refresh_deletes: bool,
}

impl SyncDone {
    /// Parse a Sync Done control value, returning a decoding error on a
    /// malformed or unexpected value.
    pub fn try_parse(val: &[u8]) -> Result<Self> {
        fn decode<S: Into<String>>(msg: S) -> LdapError {
            LdapError::DecodingError(msg.into())
        }

        let tags = match parse_tag(val) {
            Ok((_, tag)) => tag,
            _ => return Err(decode("syncdone: failed to parse tag")),
        }
        .expect_constructed()
        .ok_or_else(|| decode("syncdone: elements"))?
        .into_iter();
        let mut cookie = None;
        let mut refresh_deletes = false;
        for tag in tags {
            match tag {
                StructureTag { id, payload, .. } if id == Types::OctetString as u64 => {
                    cookie = Some(match payload {
                        PL::P(ostr) => ostr,
                        PL::C(_) => return Err(decode("syncdone: constructed octet string?")),
                    });
                }
                StructureTag { id, payload, .. } if id == Types::Boolean as u64 => {
                    refresh_deletes = match payload {
                        PL::P(ostr) => ostr.first().is_some_and(|b| *b != 0),
                        PL::C(_) => return Err(decode("syncdone: constructed boolean?")),
                    };
                }
                _ => return Err(decode("syncdone: unrecognized component")),
            }
        }
        Ok(SyncDone {
            cookie,
            refresh_deletes,
        })
    }
}

impl ControlParser for SyncDone {
    fn parse(val: &[u8]) -> Self {
        SyncDone::try_parse(val).expect("syncdone")
    }
}

/// Values of the Sync Info intermediate message ([RFC 4533](https://tools.ietf.org/html/rfc4533)).
#[derive(Clone, Debug)]
pub enum SyncInfo {
    NewCookie(Vec<u8>),
    RefreshDelete {
        cookie: Option<Vec<u8>>,
        refresh_done: bool,
    },
    RefreshPresent {
        cookie: Option<Vec<u8>>,
        refresh_done: bool,
    },
    SyncIdSet {
        cookie: Option<Vec<u8>>,
        refresh_deletes: bool,
        sync_uuids: HashSet<Vec<u8>>,
    },
}

/// Parse the Sync Info value from the Search result entry.
///
/// Panics on a malformed message; see [`try_parse_syncinfo`] for a fallible variant.
pub fn parse_syncinfo(entry: ResultEntry) -> SyncInfo {
    try_parse_syncinfo(entry).expect("syncinfo")
}

/// Parse the Sync Info value from the Search result entry, returning a decoding
/// error on a malformed or unexpected message.
pub fn try_parse_syncinfo(entry: ResultEntry) -> Result<SyncInfo> {
    fn decode<S: Into<String>>(msg: S) -> LdapError {
        LdapError::DecodingError(msg.into())
    }

    let mut tags = entry
        .0
        .match_id(25)
        .and_then(|t| t.expect_constructed())
        .ok_or_else(|| decode("syncinfo: intermediate seq"))?
        .into_iter();
    loop {
        match tags.next() {
            None => return Err(decode("syncinfo: out of tags")),
            Some(tag) if tag.id == 0 => {
                let oid = String::from_utf8(
                    tag.expect_primitive()
                        .ok_or_else(|| decode("syncinfo: oid octet string"))?,
                )
                .map_err(|e| decode(format!("syncinfo: oid is not valid UTF-8: {e}")))?;
                if oid != SYNC_INFO_OID {
                    return Err(decode("syncinfo: oid mismatch"));
                }
            }
            Some(tag) if tag.id == 1 => {
                let syncinfo_val = match parse_tag(
                    tag.expect_primitive()
                        .ok_or_else(|| decode("syncinfo: value octet string"))?
                        .as_ref(),
                ) {
                    Ok((_, tag)) => tag,
                    _ => return Err(decode("syncinfo: error parsing value")),
                };
                return match syncinfo_val {
                    StructureTag { id, class, payload } if class == TagClass::Context && id < 4 => {
                        match id {
                            0 => {
                                let cookie = match payload {
                                    PL::P(payload) => payload,
                                    PL::C(_) => return Err(decode("syncinfo: [0] not primitive")),
                                };
                                Ok(SyncInfo::NewCookie(cookie))
                            }
                            1..=3 => {
                                let mut syncinfo_val = match payload {
                                    PL::C(payload) => payload,
                                    PL::P(_) => {
                                        return Err(decode("syncinfo: [1,2,3] not a sequence"));
                                    }
                                }
                                .into_iter();
                                let mut sync_cookie = None;
                                let mut flag = id != 3;
                                let mut uuids = HashSet::new();
                                let mut pass = 1;
                                'it: loop {
                                    match syncinfo_val.next() {
                                        None => break 'it,
                                        Some(comp) => match comp {
                                            StructureTag { id, class, .. }
                                                if class == TagClass::Universal
                                                    && id == Types::OctetString as u64
                                                    && pass <= 1 =>
                                            {
                                                sync_cookie = comp.expect_primitive();
                                            }
                                            StructureTag { id, class, .. }
                                                if class == TagClass::Universal
                                                    && id == Types::Boolean as u64
                                                    && pass <= 2 =>
                                            {
                                                flag = comp
                                                    .expect_primitive()
                                                    .ok_or_else(|| decode("syncinfo: flag"))?
                                                    .first()
                                                    .is_some_and(|b| *b != 0);
                                            }
                                            StructureTag { id, class, .. }
                                                if class == TagClass::Universal
                                                    && id == Types::Set as u64
                                                    && pass <= 3 =>
                                            {
                                                uuids = comp
                                                    .expect_constructed()
                                                    .ok_or_else(|| decode("syncinfo: uuid set"))?
                                                    .into_iter()
                                                    .map(|u| {
                                                        u.expect_primitive().ok_or_else(|| {
                                                            decode("syncinfo: uuid octet string")
                                                        })
                                                    })
                                                    .collect::<Result<_>>()?;
                                            }
                                            _ => {
                                                return Err(decode(
                                                    "syncinfo: unexpected component",
                                                ));
                                            }
                                        },
                                    }
                                    pass += 1;
                                }
                                match id {
                                    1 => Ok(SyncInfo::RefreshDelete {
                                        cookie: sync_cookie,
                                        refresh_done: flag,
                                    }),
                                    2 => Ok(SyncInfo::RefreshPresent {
                                        cookie: sync_cookie,
                                        refresh_done: flag,
                                    }),
                                    3 => Ok(SyncInfo::SyncIdSet {
                                        cookie: sync_cookie,
                                        refresh_deletes: flag,
                                        sync_uuids: uuids,
                                    }),
                                    _ => Err(decode("syncinfo: got id > 3")),
                                }
                            }
                            _ => Err(decode("syncinfo: got id > 3")),
                        }
                    }
                    _ => Err(decode("syncinfo: got id > 3")),
                };
            }
            _ => return Err(decode("syncinfo: unrecognized tag")),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn sync_state_garbage_is_error() {
        assert!(matches!(
            SyncState::try_parse(&[0xff, 0xff]),
            Err(LdapError::DecodingError(_))
        ));
    }

    #[test]
    fn sync_done_garbage_is_error() {
        assert!(matches!(
            SyncDone::try_parse(&[0xff, 0xff]),
            Err(LdapError::DecodingError(_))
        ));
    }
}
