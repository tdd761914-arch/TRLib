//! Fixed-size runtime limits; compile-time modules are selected by Cargo features.

/// Resource limits for a single gateway session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct GatewayConfig {
    /// Maximum accepted transport frame size.
    pub max_frame_bytes: u32,
    /// Maximum accepted decrypted message body size.
    pub max_message_bytes: u32,
    /// Maximum number of messages in one MTProto container.
    pub max_container_messages: u16,
    /// Maximum number of elements accepted by eager consumers of TL vectors.
    pub max_vector_elements: u16,
    /// Reject non-zero TL alignment padding when set.
    pub strict_tl_padding: bool,
}

impl GatewayConfig {
    /// Conservative defaults suitable for a metadata/update gateway.
    pub const LOW_MEMORY: Self = Self {
        max_frame_bytes: 1_048_576,
        max_message_bytes: 1_048_576,
        max_container_messages: 128,
        max_vector_elements: 4_096,
        strict_tl_padding: true,
    };

    /// Defaults suitable for larger media-independent API responses.
    pub const BALANCED: Self = Self {
        max_frame_bytes: 4_194_304,
        max_message_bytes: 4_194_304,
        max_container_messages: 1_024,
        max_vector_elements: 16_384,
        strict_tl_padding: true,
    };
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self::LOW_MEMORY
    }
}

/// Bitset describing modules linked into this build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct CompiledFeatures(u8);

impl CompiledFeatures {
    /// Abridged TCP framing is linked.
    pub const ABRIDGED: u8 = 1 << 0;
    /// Intermediate TCP framing is linked.
    pub const INTERMEDIATE: u8 = 1 << 1;
    /// MTProto service-object parsing is linked.
    pub const SERVICE: u8 = 1 << 2;
    /// RustCrypto-backed MTProto 2.0 session cryptography is linked.
    pub const CRYPTO: u8 = 1 << 3;

    /// Returns the feature set selected at compile time.
    pub const fn current() -> Self {
        let mut bits = 0;
        if cfg!(feature = "transport-abridged") {
            bits |= Self::ABRIDGED;
        }
        if cfg!(feature = "transport-intermediate") {
            bits |= Self::INTERMEDIATE;
        }
        if cfg!(feature = "service") {
            bits |= Self::SERVICE;
        }
        if cfg!(feature = "crypto-rustcrypto") {
            bits |= Self::CRYPTO;
        }
        Self(bits)
    }

    /// Checks whether a feature bit is present.
    #[inline]
    pub const fn contains(self, feature: u8) -> bool {
        self.0 & feature != 0
    }

    /// Returns the raw feature bitset.
    #[inline]
    pub const fn bits(self) -> u8 {
        self.0
    }
}
