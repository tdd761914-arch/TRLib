//! Zero-copy Telegram TL primitives.

mod cursor;
mod prefix;
pub mod schema;
mod writer;

pub use cursor::{Cursor, TlBytes, TlString};
pub use prefix::{Constructor, ConstructorId, RawObject};
pub use schema::{Peer, Value};
pub use writer::Writer;

/// Telegram's built-in vector constructor.
pub const VECTOR: ConstructorId = ConstructorId::new(0x1cb5_c415);

/// One field of a schema constructor, as streamed from the vendored TL schema.
///
/// The signature is stored as raw text so the metadata table needs no runtime
/// parser; `flags_field` is the zero-based index of the `flags:#`/`flags2:#`
/// argument this field depends on and `flags_bit` its bit position, with
/// `0xFF` meaning the field is always present.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FieldMeta {
    /// Field name from the TL schema.
    pub name: &'static str,
    /// Raw TL type text, e.g. `"Vector<InputMessage>"` or `"true"`.
    pub ty: &'static str,
    /// Index of the flags field that gates this optional field.
    pub flags_field: u8,
    /// Bit position in that flags field, when `flags_field != 0xFF`.
    pub flags_bit: u8,
}

/// One schema constructor, as streamed from the vendored TL schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ConstructorMeta {
    /// Wire constructor identifier.
    pub id: ConstructorId,
    /// Fully-qualified schema name, e.g. `"messages.sendMessage"`.
    pub name: &'static str,
    /// Result type text, e.g. `"Updates"` or `"messages.Messages"`.
    pub result: &'static str,
    /// Field signatures in declaration order.
    pub fields: &'static [FieldMeta],
}

/// Declares a TL constructor parser without creating an intermediate AST.
///
/// The parser checks the four-byte constructor prefix and then executes the
/// supplied cursor expression directly over the caller-owned input.
#[macro_export]
macro_rules! tl_constructor {
    (
        $(#[$meta:meta])*
        $vis:vis fn $parser:ident<$lt:lifetime>($cursor:ident) -> $output:ty {
            id = $id:expr;
            $body:block
        }
    ) => {
        $(#[$meta])*
        #[inline]
        $vis fn $parser<$lt>(
            $cursor: &mut $crate::tl::Cursor<$lt>,
        ) -> $crate::Result<$output> {
            $cursor.expect_constructor($crate::tl::ConstructorId::new($id))?;
            $body
        }
    };
}
