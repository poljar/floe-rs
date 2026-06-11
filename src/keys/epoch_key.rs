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

//! Module for the Floe epoch keys.
//!
//! See the [`EpochKey`] documentation for more info.

use aead::{AeadCore, AeadInOut, Generate, Key, KeyInit, Nonce, array::ArraySize};
use rand_core::CryptoRng;
use zerocopy::{BigEndian, FromBytes, Immutable, IntoBytes, KnownLayout, U64};

use crate::{
    DecryptionError, EncryptionError,
    types::{
        SegmentSize,
        segment::{NON_FINAL_SEGMENT_HEADER, Segment, SegmentMut},
    },
};

/// The additional associated data for the AEAD.
///
/// Defined as the 64 bit segment number encoded as a big endian value (8 bytes)
/// and a `is_final` flag (1 byte).
///
/// This is not the same associated data the caller has given us. This
/// associated data binds the segment number and whether the segment is
/// the final one to the ciphertext.
///
/// This implements a part of the `encryptSegment` and `decryptSegment`
/// function from the [spec], namely:
///
/// ```text
/// aead_aad = I2BE(position, 8) || aad_tail
/// ```
///
/// [spec]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#semi-public-functions-random-access
#[derive(Debug, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct AssociatedData {
    /// The number of the segment.
    segment_number: U64<BigEndian>,

    /// Is this the final segment?
    is_final: bool,
}

/// The key to encrypt or decrypt a segment.
///
/// The epoch key is derived on a per-segment basis from the
/// [`crate::keys::MessageKey`]. This key is used as the input-key material for
/// the AEAD, as such its length depends on the picked AEAD.
///
/// The `AEAD_ROTATION_MASK` determines how many segments will use the same
/// [`EpochKey`].
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub(crate) struct EpochKey<A>
where
    A: AeadInOut + KeyInit,
{
    /// The AEAD key used for encrypt or decrypt operations.
    pub(super) key: Key<A>,

    /// The number of the segment this [`EpochKey`] operates on.
    pub(super) segment_number: u64,

    /// Is this [`EpochKey`] used for the last segment?
    pub(super) is_final: bool,
}

impl<A> EpochKey<A>
where
    A: AeadInOut + KeyInit,
    <<A as AeadCore>::TagSize as ArraySize>::ArrayType<u8>: FromBytes + Immutable,
    <<A as AeadCore>::NonceSize as ArraySize>::ArrayType<u8>: FromBytes + Immutable,
{
    /// Encrypt a single segment using this [`EpochKey`].
    ///
    /// The segment needs to be prepared before this method is called. Namely
    /// the [`SegmentMut::ciphertext`] field needs to contain the plaintext.
    /// This will be in-place replaced with the ciphertext by the AEAD.
    ///
    /// The [`SegmentMut::header`], [`SegmentMut::nonce`], and
    /// [`SegmentMut::tag`] on the other hand will be filled out by this
    /// method.
    ///
    /// This implements the second part of the `encryptSegment` function from
    /// the [spec].
    ///
    /// # Panics
    ///
    /// Panics if the:
    /// * addition of the length of the plaintext segment and length of the
    ///   encrypted segment overhead overflows.
    /// * length of the encrypted segment can't fit into a `u32`
    ///
    /// [spec]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#semi-public-functions-random-access
    pub(crate) fn encrypt_segment<R>(
        self,
        segment: SegmentMut<'_, A>,
        rng: &mut R,
    ) -> Result<(), EncryptionError>
    where
        R: CryptoRng,
    {
        // Creating a SegmentMut has already copied the plaintext into the ciphertext
        // field, let's just create a borrow of that field for our convenience.
        let plaintext_buffer = segment.ciphertext;

        // Calculate the correct header, depending on if the segment is final or not.
        //
        // If it's the final segment, we're putting the length of the segment into the
        // header, otherwise a static placeholder header is used.
        let header = Self::segment_header(plaintext_buffer.len(), self.is_final);

        // Generate a new random AEAD nonce.
        let nonce = Nonce::<A>::try_generate_from_rng(rng)
            .map_err(|_| EncryptionError::NonceGenerationFailed)?;

        // Create the AEAD and build the associated data for this segment.
        let aead = A::new(&self.key);
        let associated_data = self.associated_data();

        // Encrypt the plaintext and return the AEAD tag.
        let tag = aead.encrypt_inout_detached(
            &nonce,
            associated_data.as_bytes(),
            plaintext_buffer.into(),
        )?;

        // Copy the rest of the important data into the segment.
        segment.header.set(header);
        segment.nonce.copy_from_slice(&nonce);
        segment.tag.copy_from_slice(&tag);

        Ok(())
    }

    /// Decrypt a single segment using this [`EpochKey`].
    ///
    /// This implements the second part of the `decryptSegment` function from
    /// the [spec].
    ///
    /// # Panics
    ///
    /// This function panics if the length of the buffer differs from the length
    /// of the [`Segment::ciphertext`] field.
    ///
    /// [spec]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#semi-public-functions-random-access
    pub(crate) fn decrypt_segment<const S: SegmentSize>(
        self,
        segment: &Segment<'_, A, S>,
        buffer: &mut [u8],
    ) -> Result<(), DecryptionError> {
        debug_assert_eq!(
            segment.ciphertext().len(),
            buffer.len(),
            "The ciphertext and output buffer for the plaintext should have the same size"
        );

        // Create the AEAD and build the associated data for this segment.
        let aead = A::new(&self.key);
        let associated_data = self.associated_data();

        // Copy the ciphertext into the output buffer, the AEAD will replace the
        // ciphertext with the plaintext.
        buffer.copy_from_slice(segment.ciphertext());

        // Finally, decrypt the ciphertext.
        Ok(aead.decrypt_inout_detached(
            segment.nonce(),
            associated_data.as_bytes(),
            buffer.into(),
            segment.tag(),
        )?)
    }

    /// Create an array of associated data for the segment
    /// encryption/decryption.
    fn associated_data(&self) -> AssociatedData {
        AssociatedData { segment_number: U64::new(self.segment_number), is_final: self.is_final }
    }

    /// Calculate the segment header, depending on if the segment is final or
    /// not.
    ///
    /// If it's the final segment, we're putting the length of the segment into
    /// the header, otherwise a static placeholder header is used.
    fn segment_header(plaintext_buffer_length: usize, is_final: bool) -> u32 {
        if is_final {
            // SAFETY: The FloeEncryptor::encrypt_segment method checks if the plaintext
            // length is too big and that the segment length fits into an usize.
            #[allow(clippy::expect_used)]
            let final_segment_length =
                plaintext_buffer_length.checked_add(SegmentMut::<A>::overhead()).expect(
                    "Adding the length of the encrypted segment overhead \
                    to the length of the final segment shouldn't overflow",
                );

            // SAFETY: The FloeEncryptor constructor panics if we can't encode the maximal
            // final segment length into a `u32`.
            #[allow(clippy::expect_used)]
            let final_segment_length: u32 = final_segment_length
                .try_into()
                .expect("The length of the final encrypted segment should fit into 32 bits");

            final_segment_length
        } else {
            // Non-final segments get u32::MAX as the header.
            NON_FINAL_SEGMENT_HEADER
        }
    }
}
