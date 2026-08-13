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

//! Module containing the random-access decryption support defined in the [Floe
//! specification].
//!
//! [Floe specification]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#semi-public-functions-random-access

use aead::{AeadCore, Key, array::ArraySize};
use subtle::ConstantTimeEq;
use zerocopy::{FromBytes, Immutable};

use crate::{
    DecryptionError, FloeAead, FloeKdf,
    keys::{FloeKey, MessageKey},
    result::ConfigurationError,
    types::{AeadRotationMask, FloeIv, Header, Parameters, Segment, SegmentSize},
    utils::{check_segment_size, plaintext_size},
};

/// Generic implementation of the Floe random-access decryption APIs.
pub struct FloeDecryptor<'a, A, K, const N: usize, const S: SegmentSize>
where
    A: FloeAead,
    K: FloeKdf,
{
    /// The message key, used to derive the AEAD key for the segments.
    message_key: MessageKey<A, K>,

    /// The Floe initialization vector.
    ///
    /// This was created when the Floe session was created while the segments
    /// were encrypted.
    floe_iv: FloeIv<N>,

    /// The user-provided additional associated data.
    associated_data: &'a [u8],

    /// The AEAD rotation mask this encryptor will be using.
    ///
    /// Defaults to [`FloeAead::AEAD_ROTATION_MASK`].
    rotation_mask: AeadRotationMask,
}

impl<'a, A, K, const N: usize, const S: SegmentSize> FloeDecryptor<'a, A, K, N, S>
where
    A: FloeAead,
    K: FloeKdf,
    <<A as AeadCore>::TagSize as ArraySize>::ArrayType<u8>: FromBytes + Immutable,
    <<A as AeadCore>::NonceSize as ArraySize>::ArrayType<u8>: FromBytes + Immutable,
{
    /// Create a new [`FloeDecryptor`] with the given key and associated data
    /// and header.
    ///
    /// # Arguments
    ///
    /// * `key` - The main Floe key, used to derive the per-segment keys to
    ///   encrypt segments.
    /// * `associated_data` - Any additional associated data, can be used to
    ///   bind this [`FloeEncryptor`] to a specific protocol.
    /// * `header` - The Floe [`Header`] the encryptor created before any
    ///   segments were encrypted.
    ///
    /// # Errors
    ///
    /// Returns an error if the parameters in the [`Header`] don't match to the
    /// configured parameters of the [`FloeDecryptor`], if the tag of the
    /// header is invalid, or if the configured Floe parameters are not valid.
    ///
    /// # Examples
    #[cfg_attr(feature = "floe-gcm", doc = "```no_run")]
    #[cfg_attr(not(feature = "floe-gcm"), doc = "```ignore")]
    /// use floe_rs::{random_access::FloeDecryptor, types::{Segment, Header}};
    ///
    /// use aead::{Key, consts::U32};
    /// use aes_gcm::Aes256Gcm;
    /// use hkdf::hmac::Hmac;
    /// use sha2::Sha384;
    ///
    /// type Decryptor<'a> = FloeDecryptor<'a, Aes256Gcm, Sha384, 32, 1024>;
    ///
    /// let key = [0u8; 32];
    /// let key = (&key).into();
    ///
    /// let header = Header::from_bytes(b"example_header")?;
    /// let decryptor = Decryptor::new(key, b"my_custom_protocol", &header)?;
    ///
    /// let plaintext_size = decryptor.plaintext_size();
    /// let mut buffer = vec![0u8; plaintext_size];
    ///
    /// let segment = Segment::from_bytes(b"example_segment", true)?;
    ///
    /// decryptor.decrypt_segment(&segment, &mut buffer, 0)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn new(
        key: &Key<A>,
        associated_data: &'a [u8],
        header: &Header<N>,
    ) -> Result<Self, DecryptionError> {
        Self::with_rotation_mask(key, associated_data, header, A::AEAD_ROTATION_MASK)
    }

    /// Create a new [`FloeDecryptor`] with the given key and associated data
    /// using a custom AEAD rotation mask.
    ///
    /// # Arguments
    ///
    /// * `key` - The main Floe key, used to derive the per-segment keys to
    ///   encrypt segments.
    /// * `associated_data` - Any additional associated data, can be used to
    ///   bind this [`FloeEncryptor`] to a specific protocol.
    /// * `header` - The Floe [`Header`] the encryptor created before any
    ///   segments were encrypted.
    /// * `rotation_mask` - A value designating how many segments will be
    ///   encrypted before deriving a new encryption key. `2^rotation_mask`
    ///   segments are encrypted under a single key.
    ///
    /// # Errors
    ///
    /// Returns an error if the parameters in the [`Header`] don't match to the
    /// configured parameters of the [`FloeDecryptor`], if the tag of the
    /// header is invalid, or if the configured Floe parameters are not valid.
    pub fn with_rotation_mask(
        key: &Key<A>,
        associated_data: &'a [u8],
        header: &Header<N>,
        rotation_mask: AeadRotationMask,
    ) -> Result<Self, DecryptionError> {
        check_segment_size::<A, S>()?;

        let expected_parameters = Parameters::new::<A, K, N, S>();

        if &expected_parameters != header.parameters() {
            return Err(DecryptionError::InvalidParameters {
                expected: expected_parameters,
                got: *header.parameters(),
            });
        }

        let floe_key = FloeKey::new(key);

        let expected_tag = floe_key.derive_header_tag::<N, S>(header.iv(), associated_data);
        let is_header_tag_valid: bool = expected_tag.ct_eq(header.tag()).into();

        if !is_header_tag_valid {
            Err(DecryptionError::InvalidHeaderTag)
        } else {
            let message_key = floe_key.derive_message_key::<N, S>(header.iv(), associated_data);
            let floe_iv = *header.iv();

            Ok(Self { message_key, floe_iv, associated_data, rotation_mask })
        }
    }

    /// The length of the plaintext decrypting any non-final segment will
    /// produce.
    ///
    /// The length of the plaintext the final segment will produce can be found
    /// using the [`Segment::plaintext_size`] method if the segment is the final
    /// segment.
    pub fn plaintext_size(&self) -> usize {
        // SAFETY: The constructor of the FloeDecryptor checks that the segment size
        // fits into an usize and that it's bigger than the overhead.
        plaintext_size::<A, S>()
    }

    /// Decrypt a single Floe segment using this [`FloeDecryptor`].
    ///
    /// # Arguments
    ///
    /// * `segment` - A chunk of plaintext bytes which should be encrypted
    /// * `buffer` - The output buffer where the decrypted plaintext will be
    ///   copied to.
    /// * `segment_number` - The current segment number.
    ///
    /// # Errors
    ///
    /// Returns an error if the parameters in the [`Header`] don't match to the
    /// configured parameters of the [`FloeDecryptor`], if the tag of the
    /// header is invalid, or if the configured Floe parameters are not valid.
    pub fn decrypt_segment(
        &self,
        segment: &Segment<'_, A, S>,
        buffer: &mut [u8],
        segment_number: u64,
    ) -> Result<(), DecryptionError> {
        // SAFETY: This subtraction is always fine since AEAD_MAX_SEGMENTS is NonZero.
        //
        // We're subtracting by 0 or by 1 depending on if the segment is final. If you
        // cast a bool into an integer, true will be 1 and false will be 0[1].
        //
        // This trick with the boolean avoids a if/else branch on the is_final() result.
        //
        // [1]: https://doc.rust-lang.org/std/primitive.bool.html
        let max_segments = A::AEAD_MAX_SEGMENTS.get() - u64::from(!segment.is_final());

        if segment_number > max_segments {
            return Err(ConfigurationError::MaxSegmentsReached(A::AEAD_MAX_SEGMENTS.get()).into());
        }

        let ciphertext_length = segment.ciphertext().len();
        let buffer_length = buffer.len();

        if ciphertext_length != buffer_length {
            return Err(ConfigurationError::InvalidBuffer {
                got: buffer_length,
                expected: ciphertext_length,
            }
            .into());
        }

        let epoch_key = self.message_key.derive_epoch_key::<N, S>(
            &self.floe_iv,
            self.associated_data,
            segment_number,
            self.rotation_mask,
            segment.is_final(),
        );

        epoch_key.decrypt_segment(segment, buffer)
    }
}
