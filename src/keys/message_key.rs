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

use core::marker::PhantomData;

use aead::Key;

use super::epoch_key::EpochKey;
use crate::{
    FloeAead, FloeKdf,
    keys::FloeKdfKey,
    types::{AeadRotationMask, FloeIv, SegmentSize},
    utils::floe_kdf,
};

/// The [`MessageKey`] of a Floe session.
///
/// The message key is used as the root key for deriving the per-segment
/// [`EpochKey`]s. The message key itself is derived from the
/// [`crate::keys::FloeKey`].
///
/// The length of this key is determined by the picked KDF and defined in the
/// `KDF_KEY_LEN` constant in the spec, or in the [`FloeKdf::KeySize`] type in
/// this implementation.
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub(crate) struct MessageKey<A, K>
where
    A: FloeAead,
    K: FloeKdf,
{
    pub(super) key: FloeKdfKey<K>,
    pub(super) _phantom_aead: PhantomData<A>,
    pub(super) _phantom: PhantomData<K>,
}

impl<A, K> MessageKey<A, K>
where
    A: FloeAead,
    K: FloeKdf,
{
    /// Create an [`EpochKey`] for the given segment.
    ///
    /// This implements the `DERIVE_KEY()` function from the [spec], defined as:
    ///
    /// ```text
    /// FLOE_KDF(key, iv, aad, "DEK:" || I2BE(MASK(segmentNumber, AEAD_ROTATION_MASK), 8), AEAD_KEY_LEN)
    /// ```
    ///
    /// [spec]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#internal-functions
    pub(crate) fn derive_epoch_key<const N: usize, const S: SegmentSize>(
        &self,
        floe_iv: &FloeIv<N>,
        associated_data: &[u8],
        segment_number: u64,
        rotation_mask: AeadRotationMask,
        is_final: bool,
    ) -> EpochKey<A> {
        const PURPOSE_PREFIX: &[u8] = b"DEK:";

        // The rotation mask decides how many segments will be encrypted using the same
        // epoch key.
        let masked_counter = segment_number & rotation_mask;

        // The purpose will include the segment number, this binds the key to this
        // specific segment.
        let mut purpose = [0u8; 12];
        purpose[..4].copy_from_slice(PURPOSE_PREFIX);
        purpose[4..].copy_from_slice(&masked_counter.to_be_bytes());

        let mut epoch_key = EpochKey { key: Key::<A>::default(), segment_number, is_final };
        floe_kdf::<A, K, N, S>(&self.key, floe_iv, associated_data, &purpose, &mut epoch_key.key);

        epoch_key
    }
}
