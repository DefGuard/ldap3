use std::{collections::HashMap, sync::LazyLock};

use lber::{
    structure::{PL, StructureTag},
    structures::{ASNTag, Boolean, OctetString, Sequence, Tag},
    universal::Types,
};

use crate::result::{LdapError, Result};

/// Recognized control types.
///
/// The variants can't be exhaustively matched, since the list of
/// recognized and internally implemented controls can change from one
/// release to the next.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub enum ControlType {
    PagedResults,
    PostReadResp,
    PreReadResp,
    SyncDone,
    SyncState,
    ManageDsaIt,
    MatchedValues,
}

mod assertion;
pub use self::assertion::Assertion;

mod content_sync;
pub use self::content_sync::{
    EntryState, RefreshMode, SyncDone, SyncInfo, SyncRequest, SyncState, parse_syncinfo,
    try_parse_syncinfo,
};

mod paged_results;
pub use self::paged_results::PagedResults;

mod proxy_auth;
pub use self::proxy_auth::ProxyAuth;

mod read_entry;
pub use self::read_entry::{PostRead, PostReadResp, PreRead, PreReadResp, ReadEntryResp};

mod relax_rules;
pub use self::relax_rules::RelaxRules;

mod manage_dsa_it;
pub use self::manage_dsa_it::ManageDsaIt;

mod matched_values;
pub use self::matched_values::MatchedValues;

mod txn;
pub use self::txn::TxnSpec;

#[rustfmt::skip]
static CONTROLS: LazyLock<HashMap<&'static str, ControlType>> = LazyLock::new(|| {
    HashMap::from([
        (self::paged_results::PAGED_RESULTS_OID, ControlType::PagedResults),
        (self::read_entry::POST_READ_OID, ControlType::PostReadResp),
        (self::read_entry::PRE_READ_OID, ControlType::PreReadResp),
        (self::content_sync::SYNC_DONE_OID, ControlType::SyncDone),
        (self::content_sync::SYNC_STATE_OID, ControlType::SyncState),
        (self::manage_dsa_it::MANAGE_DSA_IT_OID, ControlType::ManageDsaIt),
        (self::matched_values::MATCHED_VALUES_OID, ControlType::MatchedValues),
    ])
});

/// Conversion trait for single control instances.
///
/// The [`Ldap::with_controls()`](crate::Ldap::with_controls) method and its sync counterpart
/// accept a vector of controls, as dictated by the LDAP specification. However, it's expected
/// that most uses of controls involve a single instance, so constructing a vector at the call
/// site is noisy. If a control implements this trait, its single instance may be used
/// in the call, and a single-element vector is constructed internally.
pub trait IntoRawControlVec {
    /// Create a control vector.
    fn into(self) -> Vec<RawControl>;
}

/// Trivial implementation for a control vector, returning itself.
impl IntoRawControlVec for Vec<RawControl> {
    fn into(self) -> Vec<RawControl> {
        self
    }
}

/// Blanket implementation for any control. The vector is constructed by the conversion
/// method.
impl<R> IntoRawControlVec for R
where
    RawControl: From<R>,
{
    fn into(self) -> Vec<RawControl> {
        vec![std::convert::Into::into(self)]
    }
}

/// Mark a control as critical.
///
/// Most controls provided by this library implement this trait. All controls
/// are instantiated as non-critical by default, unless dictated otherwise by
/// their specification.
pub trait MakeCritical {
    /// Mark the control instance as critical. This operation consumes the control,
    /// and is irreversible.
    fn critical(self) -> CriticalControl<Self>
    where
        Self: Sized,
    {
        CriticalControl { control: self }
    }
}

/// Wrapper for a control marked as critical.
///
/// The wrapper ensures that the criticality of the control will be set to
/// true when the control is encoded.
pub struct CriticalControl<T> {
    control: T,
}

impl<T> From<CriticalControl<T>> for RawControl
where
    T: Into<RawControl>,
{
    fn from(cc: CriticalControl<T>) -> RawControl {
        let mut rc = cc.control.into();
        rc.crit = true;
        rc
    }
}

/// Conversion trait for response controls.
pub trait ControlParser {
    /// Convert the raw BER value into a control-specific struct.
    fn parse(val: &[u8]) -> Self;
}

/// Response control.
///
/// If the OID is recognized as corresponding to one of controls implemented by this
/// library while parsing raw BER data of the response, the first element will have
/// a value, otherwise it will be `None`.
#[derive(Clone, Debug)]
pub struct Control(pub Option<ControlType>, pub RawControl);

/// Generic control.
///
/// This struct can be used both for request and response controls. For requests, an
/// independently implemented control can produce an instance of this type and use it
/// to provide an element of the vector passed to
/// [`with_controls()`](../struct.LdapConn.html#method.with_controls) by calling
/// `into()` on the instance.
///
/// For responses, an instance is packed into a [`Control`](struct.Control.html) and
/// can be parsed by calling type-qualified [`parse()`](#method.parse) on that instance,
/// if a [`ControlParser`](trait.ControlParser.html) implementation exists for the
/// specified type.
#[derive(Clone, Debug)]
pub struct RawControl {
    /// OID of the control.
    pub ctype: String,
    /// Criticality, has no meaning on response.
    pub crit: bool,
    /// Raw value of the control, if any.
    pub val: Option<Vec<u8>>,
}

impl RawControl {
    /// Parse the generic control into a control-specific struct.
    ///
    /// The parser will panic if the control value is `None`.
    /// __Note__: no control known to the author signals the lack of return value by
    /// omitting the control value, so this shouldn't be a problem in practice.
    /// Nevertheless, it should be possible to report this along with other parsing errors,
    /// if it proves necessary.
    pub fn parse<T: ControlParser>(&self) -> T {
        T::parse(self.val.as_ref().expect("value"))
    }
}

pub fn build_tag(rc: RawControl) -> StructureTag {
    let mut seq = vec![Tag::OctetString(OctetString {
        inner: Vec::from(rc.ctype.as_bytes()),
        ..Default::default()
    })];
    if rc.crit {
        seq.push(Tag::Boolean(Boolean {
            inner: true,
            ..Default::default()
        }));
    }
    if let Some(val) = rc.val {
        seq.push(Tag::OctetString(OctetString {
            inner: val,
            ..Default::default()
        }));
    }
    Tag::Sequence(Sequence {
        inner: seq,
        ..Default::default()
    })
    .into_structure()
}

pub fn parse_controls(t: StructureTag) -> Result<Vec<Control>> {
    fn decode<S: Into<String>>(msg: S) -> LdapError {
        LdapError::DecodingError(msg.into())
    }

    let tags = t
        .expect_constructed()
        .ok_or_else(|| decode("control result sequence"))?
        .into_iter();
    let mut ctrls = Vec::new();
    for ctrl in tags {
        let mut components = ctrl
            .expect_constructed()
            .ok_or_else(|| decode("control components"))?
            .into_iter();
        let ctype = String::from_utf8(
            components
                .next()
                .ok_or_else(|| decode("missing control type element"))?
                .expect_primitive()
                .ok_or_else(|| decode("control type octet string"))?,
        )
        .map_err(|e| decode(format!("control type is not valid UTF-8: {e}")))?;
        let next = components.next();
        let (crit, maybe_val) = match next {
            None => (false, None),
            Some(c) => match c {
                StructureTag {
                    id, ref payload, ..
                } if id == Types::Boolean as u64 => match *payload {
                    PL::P(ref v) => (v.first().is_some_and(|b| *b != 0), components.next()),
                    PL::C(_) => return Err(decode("control criticality not primitive")),
                },
                StructureTag { id, .. } if id == Types::OctetString as u64 => {
                    (false, Some(c.clone()))
                }
                _ => return Err(decode("unexpected control component")),
            },
        };
        let val = match maybe_val {
            None => None,
            Some(v) => Some(
                v.expect_primitive()
                    .ok_or_else(|| decode("control value octet string"))?,
            ),
        };
        let known_type = CONTROLS.get(&*ctype).copied();
        ctrls.push(Control(known_type, RawControl { ctype, crit, val }));
    }
    Ok(ctrls)
}

#[cfg(test)]
mod test {
    use super::*;

    // A primitive top-level tag is not a control sequence; this used to panic
    // in `expect("result sequence")`.
    #[test]
    fn parse_controls_non_sequence_is_error() {
        let tag = Tag::OctetString(OctetString {
            inner: b"not a sequence".to_vec(),
            ..Default::default()
        })
        .into_structure();
        assert!(matches!(
            parse_controls(tag),
            Err(LdapError::DecodingError(_))
        ));
    }

    // A control whose entry is a bare primitive (not a sequence of components)
    // used to panic in `expect("components")`.
    #[test]
    fn parse_controls_non_sequence_entry_is_error() {
        let tag = Tag::Sequence(Sequence {
            inner: vec![Tag::OctetString(OctetString {
                inner: b"bogus".to_vec(),
                ..Default::default()
            })],
            ..Default::default()
        })
        .into_structure();
        assert!(matches!(
            parse_controls(tag),
            Err(LdapError::DecodingError(_))
        ));
    }

    #[test]
    fn parse_controls_empty_is_ok() {
        let tag = Tag::Sequence(Sequence {
            inner: vec![],
            ..Default::default()
        })
        .into_structure();
        assert!(matches!(parse_controls(tag), Ok(v) if v.is_empty()));
    }
}
