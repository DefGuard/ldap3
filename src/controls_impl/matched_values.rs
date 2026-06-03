use bytes::BytesMut;
use lber::{structures::ASNTag, write};

use super::RawControl;

use crate::filter::parse_matched_values;
use crate::result::{LdapError, Result};

pub const MATCHED_VALUES_OID: &str = "1.2.826.0.1.3344810.2.3";

/// Matched Values control ([RFC 3876](https://tools.ietf.org/html/rfc3876.html))
///
/// This control is used to return a subset of attribute values from an entry.
/// To avoid complicating the filter parser, the `dnAttributes` flag can be set
/// in an Extensible Match expression despite not being specified in the RFC and
/// having no meaning in this kind of filter.
#[derive(Clone, Debug)]
pub struct MatchedValues<S> {
    filter: S,
}

impl<S: AsRef<str>> MatchedValues<S> {
    /// Create a new control instance with the specified filter.
    ///
    /// Panics if the filter string can't be parsed; see
    /// [`try_new()`](Self::try_new) for a non-panicking variant.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(filter: S) -> RawControl {
        MatchedValues::try_new(filter).expect("filter")
    }

    /// Create a new control instance with the specified filter, returning a
    /// filter parsing error on a malformed filter string.
    pub fn try_new(filter: S) -> Result<RawControl> {
        let filter_ref = filter.as_ref();
        let filter = parse_matched_values(filter_ref)
            .map_err(|_| LdapError::FilterParsing)?
            .into_structure();
        let mut buf = BytesMut::with_capacity(filter_ref.len()); // ballpark
        write::encode_into(&mut buf, filter).expect("encoded");
        Ok(RawControl {
            ctype: MATCHED_VALUES_OID.to_owned(),
            crit: false,
            val: Some(Vec::from(&buf[..])),
        })
    }
}

impl<S: AsRef<str>> From<MatchedValues<S>> for RawControl {
    fn from(assn: MatchedValues<S>) -> RawControl {
        MatchedValues::try_new(assn.filter).expect("filter")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn try_new_invalid_filter_is_error() {
        assert!(matches!(
            MatchedValues::try_new("(this is not a filter"),
            Err(LdapError::FilterParsing)
        ));
    }
}
