use bytes::BytesMut;
use lber::{structures::ASNTag, write};

use super::{MakeCritical, RawControl};
use crate::{
    filter::parse,
    result::{LdapError, Result},
};

pub const ASSERTION_OID: &str = "1.3.6.1.1.12";

/// Assertion control ([RFC 4528](https://tools.ietf.org/html/rfc4528)).
#[derive(Debug)]
pub struct Assertion<S> {
    /// String representation of the assertion filter.
    pub filter: S,
}

impl<S: AsRef<str>> Assertion<S> {
    /// Create a new control instance with the specified filter.
    ///
    /// Panics if the filter string can't be parsed; see
    /// [`try_new()`](Self::try_new) for a non-panicking variant.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(filter: S) -> RawControl {
        Assertion::try_new(filter).expect("filter")
    }

    /// Create a new control instance with the specified filter, returning a
    /// filter parsing error on a malformed filter string.
    pub fn try_new(filter: S) -> Result<RawControl> {
        let filter_ref = filter.as_ref();
        let filter = parse(filter_ref)
            .map_err(|_| LdapError::FilterParsing)?
            .into_structure();
        let mut buf = BytesMut::with_capacity(filter_ref.len()); // ballpark
        write::encode_into(&mut buf, filter).expect("encoded");
        Ok(RawControl {
            ctype: ASSERTION_OID.to_owned(),
            crit: false,
            val: Some(Vec::from(&buf[..])),
        })
    }
}

impl<S> MakeCritical for Assertion<S> {}

impl<S: AsRef<str>> From<Assertion<S>> for RawControl {
    fn from(assn: Assertion<S>) -> RawControl {
        Assertion::try_new(assn.filter).expect("filter")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn try_new_invalid_filter_is_error() {
        assert!(matches!(
            Assertion::try_new("(this is not a filter"),
            Err(LdapError::FilterParsing)
        ));
    }

    #[test]
    fn try_new_valid_filter_is_ok() {
        assert!(Assertion::try_new("(cn=foo)").is_ok());
    }
}
