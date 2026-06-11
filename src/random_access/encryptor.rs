// Copyright 2026 Damir Jelić, Snowflake Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Module containing the random-access encryption support defined in the [Floe
//! specification].
//!
//! [Floe specification]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#semi-public-functions-random-access

use aead::{AeadCore, Key, array::ArraySize};
#[cfg(feature = "getrandom")]
use getrandom::SysRng;
use rand_core::CryptoRng;
#[cfg(feature = "getrandom")]
use rand_core::UnwrapErr;
use zerocopy::{FromBytes, Immutable, IntoBytes, Unaligned};

#[cfg(doc)]
use crate::types::Segment;
use crate::{
    EncryptionError, FloeAead, FloeKdf,
    keys::{FloeKey, MessageKey},
    result::ConfigurationError,
    types::{AeadRotationMask, Header, SegmentSize, floe_iv::FloeIv, segment::SegmentMut},
    utils::{check_segment_size, plaintext_size},
};

/// Generic implementation of the Floe random-access encryption APIs.
///  
/// The random-access APIs do not directly protect you against truncation
/// attacks or prevent you from incorrectly encrypting the same segment multiple
/// times.
pub struct FloeEncryptor<'a, A, K, const N: usize, const S: SegmentSize>
where
    A: FloeAead,
    K: FloeKdf,
{
    /// The header of the Floe session.
    header: Header<N>,

    /// The message key, used to derive the AEAD key for the segments.
    message_key: MessageKey<A, K>,

    /// The user-provided additional associated data.
    associated_data: &'a [u8],

    /// The AEAD rotation mask this encryptor will be using.
    ///
    /// Defaults to [`FloeAead::AEAD_ROTATION_MASK`].
    rotation_mask: AeadRotationMask,
}

impl<'a, A, K, const N: usize, const S: SegmentSize> FloeEncryptor<'a, A, K, N, S>
where
    A: FloeAead,
    K: FloeKdf,
    <<A as AeadCore>::TagSize as ArraySize>::ArrayType<u8>: FromBytes + Immutable + IntoBytes,
    <<A as AeadCore>::NonceSize as ArraySize>::ArrayType<u8>:
        FromBytes + Immutable + IntoBytes + Unaligned,
{
    /// Create a new [`FloeEncryptor`] with the given key and associated data.
    ///
    /// The Floe initialization vector will be randomly generated using the
    /// [SysRng] for the rng implementation.
    ///
    /// # Arguments
    ///
    /// * `key` - The main Floe key, used to derive the per-segment keys to
    ///   encrypt segments.
    /// * `associated_data` - Any additional associated data, can be used to
    ///   bind this [`FloeEncryptor`] to a specific protocol.
    ///
    /// # Panics
    ///
    /// This function will panic if not enough randomness can be gathered to
    /// generate the Floe initialization vector or if the Floe parameters are
    /// invalid.
    ///
    /// # Examples
    #[cfg_attr(feature = "floe-gcm", doc = "```")]
    #[cfg_attr(not(feature = "floe-gcm"), doc = "```ignore")]
    /// use floe_rs::random_access::FloeEncryptor;
    ///
    /// use aead::{Key, consts::U32};
    /// use aes_gcm::Aes256Gcm;
    /// use hkdf::hmac::Hmac;
    /// use sha2::Sha384;
    ///
    /// type Encryptor<'a> = FloeEncryptor<'a, Aes256Gcm, Sha384, 32, 1024>;
    ///
    /// let key = [0u8; 32];
    /// let key = (&key).into();
    ///
    /// let encryptor = Encryptor::new(key, b"my_custom_protocol");
    ///
    /// let plaintext = b"";
    ///
    /// let output_size = encryptor.output_size(plaintext);
    /// let mut buffer = vec![0u8; output_size];
    ///
    /// encryptor.encrypt_segment(plaintext, &mut buffer, 0, true)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    #[cfg(feature = "getrandom")]
    pub fn new(key: &Key<A>, associated_data: &'a [u8]) -> Self {
        let mut rng = UnwrapErr(SysRng);

        #[allow(clippy::expect_used)]
        Self::with_rng(key, associated_data, &mut rng)
            .expect("should have been able to create an encryptor, the parameters are incorrect?")
    }

    /// Create a new [`FloeEncryptor`] with the given key and associated data
    /// using the provided random number generator.
    ///
    /// The rng is required to generate a new random Floe IV.
    ///
    /// # Arguments
    ///
    /// * `key` - The main Floe key, used to derive the per-segment keys to
    ///   encrypt segments.
    /// * `associated_data` - Any additional associated data, can be used to
    ///   bind this [`FloeEncryptor`] to a specific protocol.
    /// * `rng` - A random number generator which implements the [`CryptoRng`]
    ///   trait.
    ///
    /// # Errors
    ///
    /// Returns an error if not enough randomness can be gathered to generate
    /// the Floe initialization vector or if the configured parameters are
    /// invalid.
    pub fn with_rng<R: CryptoRng>(
        key: &Key<A>,
        associated_data: &'a [u8],
        rng: &mut R,
    ) -> Result<Self, EncryptionError> {
        Self::with_rotation_mask(key, associated_data, rng, A::AEAD_ROTATION_MASK)
    }

    /// Create a new [`FloeEncryptor`] with the given key and associated data
    /// using a custom AEAD rotation mask.
    ///
    /// The rng is required to generate a new random Floe IV.
    ///
    /// # Arguments
    ///
    /// * `key` - The main Floe key, used to derive the per-segment keys to
    ///   encrypt segments.
    /// * `associated_data` - Any additional associated data, can be used to
    ///   bind this [`FloeEncryptor`] to a specific protocol.
    /// * `rng` - A random number generator which implements the [`CryptoRng`]
    ///   trait.
    /// * `rotation_mask` - A value designating how many segments will be
    ///   encrypted before deriving a new encryption key. `2^rotation_mask`
    ///   segments are encrypted under a single key.
    ///
    /// # Errors
    ///
    /// Returns an error if not enough randomness can be gathered to generate
    /// the Floe initialization vector or if the configured parameters are
    /// invalid.
    pub fn with_rotation_mask<R: CryptoRng>(
        key: &Key<A>,
        associated_data: &'a [u8],
        rng: &mut R,
        rotation_mask: AeadRotationMask,
    ) -> Result<Self, EncryptionError> {
        check_segment_size::<A, S>()?;

        let floe_key = FloeKey::new(key);
        let floe_iv = FloeIv::generate(rng).map_err(|_| EncryptionError::FloeIvGenerationFailed)?;

        let header_tag = floe_key.derive_header_tag::<N, S>(&floe_iv, associated_data);
        let message_key = floe_key.derive_message_key::<N, S>(&floe_iv, associated_data);

        let header = Header::new::<A, K, S>(floe_iv, header_tag);

        Ok(Self { message_key, header, associated_data, rotation_mask })
    }

    /// Get the input size this [`FloeEncryptor`] expects.
    ///
    /// The [`FloeEncryptor`] expects a constant input (plaintext) size for each
    /// [`FloeEncryptor::encrypt_segment`] call, unless the segment is
    /// considered to be final.
    pub fn input_size(&self) -> usize {
        // SAFETY: The constructor of the FloeEncryptor checks that the segment size
        // fits into an usize and that it's bigger than the overhead.
        plaintext_size::<A, S>()
    }

    /// Get the output size this [`FloeEncryptor`] expects.
    ///
    /// The [`FloeEncryptor`] requires an output buffer to be pre-allocated. For
    /// non-final segments this will be the same as the configured segment
    /// size.
    ///
    /// For a final segment, this will depend on the length of the final
    /// plaintext.
    ///
    /// # Panics
    ///
    /// This funnction panics if the length of the plaintext is bigger than the
    /// input size, returned by the [`FloeEncryptor::input_size`] method.
    pub fn output_size(&self, plaintext: &[u8]) -> usize {
        assert!(
            plaintext.len() <= self.input_size(),
            "The plaintext size can't be bigger than the input size"
        );

        SegmentMut::<A>::output_size(plaintext)
    }

    /// Get the header of this Floe encryption session.
    ///
    /// The header is usually prepended to the first encrypted segment. It will
    /// be needed to start decrypting segments.
    pub fn header(&self) -> &Header<N> {
        &self.header
    }

    /// Encrypt a part of the plaintext using this [`FloeEncryptor`].
    ///
    /// # Arguments
    ///
    /// * `plaintext` - A chunk of plaintext bytes which should be encrypted
    /// * `buffer` - The output buffer where the encrypted segment will be
    ///   copied to.
    /// * `segment_number` - The current segment number.
    /// * `is_final` - Is this the final segment?
    ///
    /// # Panics
    ///
    /// This function panics if not enough randomness can be gathered to
    /// generate an AEAD nonce to encrypt this segment.
    ///
    /// # Errors
    ///
    /// May return an error in case the:
    /// * Plaintext length is invalid, i.e. it doesn't match the segment size or
    ///   in case of the final segment is bigger than the configured segment
    ///   size.
    /// * The maximum number of segments has been reached for the used AEAD.
    /// * Not enough randomness can be generated for the per-segment nonce.
    /// * The output buffer doesn't have the correct size.
    #[cfg(feature = "getrandom")]
    pub fn encrypt_segment(
        &self,
        plaintext: &[u8],
        buffer: &mut [u8],
        segment_number: u64,
        is_final: bool,
    ) -> Result<(), EncryptionError> {
        let mut rng = UnwrapErr(SysRng);
        self.encrypt_segment_with_rng(plaintext, buffer, segment_number, is_final, &mut rng)
    }

    /// Encrypt a part of the plaintext using this [`FloeEncryptor`].
    ///
    /// # Arguments
    ///
    /// * `plaintext` - A chunk of plaintext bytes which should be encrypted
    /// * `buffer` - The output buffer where the encrypted segment will be
    ///   copied to.
    /// * `segment_number` - The current segment number.
    /// * `is_final` - Is this the final segment?
    /// * `rng` - A [`CryptoRng`] which will be used to generate a new AEAD
    ///   nonce for this segment.
    ///
    /// # Errors
    ///
    /// May return an error in case the:
    ///
    /// * Plaintext length is invalid, i.e. it doesn't match the segment size or
    ///   in case of the final segment is bigger than the configured segment
    ///   size.
    /// * The maximum number of segments has been reached for the used AEAD.
    /// * Not enough randomness can be generated for the per-segment nonce.
    /// * The output buffer doesn't have the correct size.
    pub fn encrypt_segment_with_rng<R>(
        &self,
        plaintext: &[u8],
        buffer: &mut [u8],
        segment_number: u64,
        is_final: bool,
        rng: &mut R,
    ) -> Result<(), EncryptionError>
    where
        R: CryptoRng,
    {
        let allowed_plaintext_length = self.input_size();
        let plaintext_length = plaintext.len();

        if is_final {
            if plaintext_length > allowed_plaintext_length {
                return Err(EncryptionError::InvalidPlaintextLength {
                    expected: allowed_plaintext_length,
                    got: plaintext_length,
                });
            }

            if segment_number >= A::AEAD_MAX_SEGMENTS.get() {
                return Err(
                    ConfigurationError::MaxSegmentsReached(A::AEAD_MAX_SEGMENTS.get()).into()
                );
            }
        } else {
            if plaintext_length != allowed_plaintext_length {
                return Err(EncryptionError::InvalidPlaintextLength {
                    expected: allowed_plaintext_length,
                    got: plaintext_length,
                });
            }

            // SAFETY: This subtraction is always fine since AEAD_MAX_SEGMENTS is NonZero.
            if segment_number >= (A::AEAD_MAX_SEGMENTS.get() - 1) {
                return Err(
                    ConfigurationError::MaxSegmentsReached(A::AEAD_MAX_SEGMENTS.get()).into()
                );
            }
        }

        // Parse the output buffer as a SegmentMut, this copies the plaintext into the
        // output buffer as well.
        let segment = SegmentMut::from_buffer_and_plaintext(plaintext, buffer)?;

        // Now we derive an epoch key for this segment.
        let epoch_key = self.message_key.derive_epoch_key::<N, S>(
            self.header.iv(),
            self.associated_data,
            segment_number,
            self.rotation_mask,
            is_final,
        );

        // And finally we encrypt the segment.
        epoch_key.encrypt_segment(segment, rng)
    }
}
