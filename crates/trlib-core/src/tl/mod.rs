//! Zero-copy Telegram TL primitives.

mod cursor;
mod prefix;
mod writer;

pub use cursor::{Cursor, TlBytes, TlString};
pub use prefix::{Constructor, ConstructorId, RawObject};
pub use writer::Writer;

/// Telegram's built-in vector constructor.
pub const VECTOR: ConstructorId = ConstructorId::new(0x1cb5_c415);

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
