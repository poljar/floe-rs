// Copyright 2026 Damir Jelić
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

use aead::{
    AeadCore, AeadInOut, Nonce, Tag,
    array::{ArraySize, typenum::Unsigned},
};
use zerocopy::{BigEndian, FromBytes, Immutable, IntoBytes, KnownLayout, U32, Unaligned};

use crate::{
    EncryptionError,
    result::{ConfigurationError, SegmentDecodeError},
    types::SegmentSize,
};

/// The length of the segment header.
///
/// The segment header contains the length of a segment if the segment is the
/// final segment or a placeholder in case the segment is non-final, namely
/// [`NON_FINAL_SEGMENT_HEADER`].
///
/// Since this is 4 bytes long, this limits the encrypted segment size to
/// [u32::MAX]. This means that the ciphertext and consequently the plaintext
/// segment need to smaller than u32::MAX because the encrypted segment needs to
/// fit the header, nonce, and tag into the allocated buffer.
pub(crate) const SEGMENT_HEADER_LENGTH: usize = size_of::<u32>();

/// The segment header for any non-final encrypted segment.
pub(crate) const NON_FINAL_SEGMENT_HEADER: u32 = u32::MAX;

const fn segment_overhead<A: AeadCore>() -> usize {
    SEGMENT_HEADER_LENGTH + A::NonceSize::USIZE + A::TagSize::USIZE
}

/// The common inner type for the [Segment] and [SegmentMut] types.
///
/// Since those types only differ in their mutability, we can use this type to
/// parse the common parts of an encrypted segment.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct InnerSegment<A>
where
    A: AeadCore,
{
    header: U32<BigEndian>,
    nonce: Nonce<A>,
    ciphertext: [u8],
}

/// The encrypted segment of a Floe body.
///
/// Floe doesn't encrypt data as a whole, instead it splits out the data into
/// chunks and produces encrypted segments.
///
/// This struct represents one such segment.
///
/// This is the generic variant of this type, you might be looking for the
/// GCM-variant: [`crate::gcm::Segment`].
///
/// # Examples
#[cfg_attr(feature = "floe-gcm", doc = "```no_run")]
#[cfg_attr(not(feature = "floe-gcm"), doc = "```ignore")]
/// use floe_rs::types::Segment;
/// use aes_gcm::Aes256Gcm;
///
/// # let bytes: &[u8] = unimplemented!();
/// let segment = Segment::<Aes256Gcm, 1024>::from_bytes(bytes, true)?;
/// let buffer = vec![0u8; segment.plaintext_size()];
///
/// // Now you can attempt to decrypt the segment.
/// # Ok::<(), anyhow::Error>(())
/// ```
pub struct Segment<'a, A, const S: SegmentSize>
where
    A: AeadCore,
{
    header: &'a U32<BigEndian>,
    nonce: &'a Nonce<A>,
    ciphertext: &'a [u8],
    tag: &'a Tag<A>,
}

impl<'a, A, const S: SegmentSize> Segment<'a, A, S>
where
    A: AeadCore,
{
    /// Attempt to decode a slice of bytes as a Floe [`Segment`]
    ///
    /// *Note*: This only attempts to reinterpret the bytes as a valid
    /// [`Segment`], as such it does not copy any data.
    pub fn from_bytes(bytes: &'a [u8], is_final: bool) -> Result<Self, SegmentDecodeError>
    where
        A: 'a,
        <<A as AeadCore>::TagSize as ArraySize>::ArrayType<u8>: FromBytes + Immutable,
        <<A as AeadCore>::NonceSize as ArraySize>::ArrayType<u8>: FromBytes + Immutable,
    {
        let invalid_length_err = || SegmentDecodeError::InvalidSliceLength {
            expected: Segment::<A, S>::overhead(),
            got: bytes.len(),
        };

        let (rest, tag) = Tag::<A>::ref_from_suffix(bytes).map_err(|_| invalid_length_err())?;
        let InnerSegment { header, nonce, ciphertext } =
            InnerSegment::<A>::ref_from_bytes(rest).map_err(|_| invalid_length_err())?;

        let segment = Segment { header, nonce, ciphertext, tag };

        let segment_size: usize = S.try_into().map_err(|_| SegmentDecodeError::MalformedSegment)?;

        if is_final != segment.is_final() {
            return Err(SegmentDecodeError::MalformedSegment);
        }

        if segment.is_final() {
            let length: usize =
                segment.header().try_into().map_err(|_| SegmentDecodeError::MalformedSegment)?;

            if length != bytes.len() {
                return Err(SegmentDecodeError::MalformedSegment);
            }

            if bytes.len() > segment_size {
                return Err(SegmentDecodeError::MalformedSegment);
            }
        } else {
            if bytes.len() != segment_size {
                return Err(SegmentDecodeError::MalformedSegment);
            }
        }

        Ok(segment)
    }

    /// Get the header of this encrypted Floe segment.
    pub fn header(&self) -> u32 {
        self.header.get()
    }

    /// Get the AEAD nonce that was used to encrypt this segment.
    pub fn nonce(&self) -> &Nonce<A> {
        self.nonce
    }

    /// Get the AEAD tag which was created when the segment was encrypted.
    pub fn tag(&self) -> &Tag<A> {
        self.tag
    }

    /// Get the ciphertext of this segment.
    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext
    }

    /// Does this segment claim to be the final one.
    pub fn is_final(&self) -> bool {
        *self.header != NON_FINAL_SEGMENT_HEADER
    }

    /// Calculate how many more bytes an encrypted segment would contain in
    /// addition to the ciphertext bytes itself.
    pub const fn overhead() -> usize {
        segment_overhead::<A>()
    }

    /// Get the size of the plaintext once the segment is decrypted.
    ///
    /// This will be the same size as the length of the [`Segment::ciphertext`].
    ///
    /// This can be used to allocate a buffer where the plaintext will be put.
    pub const fn plaintext_size(&self) -> usize {
        self.ciphertext.len()
    }
}

/// The mutable variant of an encrypted segment.
///
/// This type is used to interpret the output buffer when a chunk of plaintext
/// data is encrypted.
pub(crate) struct SegmentMut<'a, A>
where
    A: AeadInOut,
{
    pub(crate) header: &'a mut U32<BigEndian>,
    pub(crate) nonce: &'a mut Nonce<A>,
    pub(crate) ciphertext: &'a mut [u8],
    pub(crate) tag: &'a mut Tag<A>,
}

impl<'a, A> SegmentMut<'a, A>
where
    A: AeadInOut + 'a,
{
    /// Get the size the output buffer of this encrypted segment should have.
    pub(crate) const fn output_size(plaintext: &[u8]) -> usize {
        plaintext.len() + segment_overhead::<A>()
    }

    /// Calculate how many more bytes an encrypted segment would contain in
    /// addition to the ciphertext bytes itself.
    pub(crate) const fn overhead() -> usize {
        segment_overhead::<A>()
    }

    /// Reinterpret a mutable buffer as a [`SegmentMut`] and copy the plaintext
    /// into the buffer.
    pub(crate) fn from_buffer_and_plaintext(
        plaintext: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<Self, EncryptionError>
    where
        <<A as AeadCore>::TagSize as ArraySize>::ArrayType<u8>: FromBytes + IntoBytes + Immutable,
        <<A as AeadCore>::NonceSize as ArraySize>::ArrayType<u8>:
            FromBytes + IntoBytes + Unaligned + Immutable,
    {
        let buffer_length = buffer.len();
        let invalid_length_err = || ConfigurationError::InvalidBuffer {
            expected: Self::output_size(plaintext),
            got: buffer_length,
        };

        let (rest, tag) = Tag::<A>::mut_from_suffix(buffer).map_err(|_| invalid_length_err())?;

        let InnerSegment { header, nonce, ciphertext } =
            InnerSegment::<A>::mut_from_bytes(rest).map_err(|_| invalid_length_err())?;

        let segment = SegmentMut { header, nonce, ciphertext, tag };

        // Now copy the plaintext into the ciphertext part of the output buffer, the
        // AEAD will later replace the plaintext bytes in-place with the
        // ciphertext bytes.
        segment.ciphertext.copy_from_slice(plaintext);

        Ok(segment)
    }
}
