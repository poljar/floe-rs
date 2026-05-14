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

pub(crate) mod parameters;
pub(crate) mod tag;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    FloeAead, FloeKdf,
    result::HeaderDecodeError,
    types::{FloeIv, HeaderTag, Parameters, SegmentSize},
};

/// The header of a Floe ciphertext.
///
/// The Floe ciphertext consists of a header and a body. This struct represents
/// the header which contains:
/// * parameter information
/// * the Floe initialization vector
/// * a tag
///
/// The header is created before the first segment is encrypted and is required
/// before any segment can be decrypted.
#[derive(Debug, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
#[repr(C)]
pub struct Header<const N: usize> {
    parameters: Parameters,
    floe_iv: FloeIv<N>,
    tag: HeaderTag,
}

impl<const N: usize> Header<N> {
    /// The length of the [`Header`] in bytes.
    ///
    /// This is the sum of the length of the parameters, the Floe IV, and the
    /// header tag.
    pub const LENGTH: usize = N + Parameters::LENGTH + HeaderTag::LENGTH;

    /// Create a new [`Header`] with the given [`FloeIv`] and [`HeaderTag`].
    ///
    /// The parameters will be generated implicitly from the generic arguments.
    pub(crate) fn new<A, K, const S: SegmentSize>(floe_iv: FloeIv<N>, header_tag: HeaderTag) -> Self
    where
        A: FloeAead,
        K: FloeKdf,
    {
        let parameters = Parameters::new::<A, K, N, S>();

        Self { parameters, floe_iv, tag: header_tag }
    }

    /// Attempt to parse a slice of bytes into a [`Header`].
    ///
    /// # Errors
    ///
    /// Returns an error if the given byte slice isn't of the correct length.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use floe_rs::types::Header;
    ///
    /// # let bytes: &[u8] = unimplemented!();
    /// let header = Header::<32>::from_bytes(bytes)?;
    ///
    /// // Now you can create a decryptor to attempt segment decryption.
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HeaderDecodeError> {
        Self::read_from_bytes(bytes).map_err(|_| HeaderDecodeError::InvalidLength {
            expected: Self::LENGTH,
            got: bytes.len(),
        })
    }

    /// Get the parameter information contained in this header.
    pub fn parameters(&self) -> &Parameters {
        &self.parameters
    }

    /// Get the Floe initialization vector contained in this header.
    pub fn iv(&self) -> &FloeIv<N> {
        &self.floe_iv
    }

    /// Get the tag of this header.
    pub fn tag(&self) -> &HeaderTag {
        &self.tag
    }
}
