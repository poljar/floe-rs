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

//! Module for the Floe key, the main input key for a Floe session.

use core::marker::PhantomData;

use aead::Key;
use hybrid_array::Array;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use super::message_key::MessageKey;
use crate::{
    FloeAead, FloeKdf,
    types::{FloeIv, HeaderTag},
    utils::floe_kdf,
};

/// The main input key for a Floe session.
///
/// As per [spec], must be the same size as the AEAD key.
///
/// [spec]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#key-generation
pub(crate) struct FloeKey<'a, A, K>
where
    A: FloeAead,
    K: FloeKdf,
{
    /// The array of bytes containing the key.
    key: &'a Key<A>,

    /// Phantom data to bind this FloeKey to the generic [FloeAead].
    _phantom_aead: PhantomData<A>,

    /// Phantom data to bind this FloeKey to the generic [FloeKdf].
    _phantom: PhantomData<K>,
}

impl<'a, A, K> FloeKey<'a, A, K>
where
    A: FloeAead,
    K: FloeKdf,
{
    /// Create a new [`FloeKey`] from an array of bytes.
    pub(crate) fn new(key: &'a Key<A>) -> Self {
        Self { key, _phantom_aead: PhantomData, _phantom: PhantomData }
    }

    /// Derive the header tag using this [`FloeKey`] as the input key material
    /// of the `FLOE_KDF` operation.
    ///
    /// From the [spec]:
    ///
    /// ```text
    /// HeaderTag = FLOE_KDF(key, iv, aad, "HEADER_TAG:", 32)
    /// ```
    ///
    /// [spec]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#semi-public-functions-random-access
    pub(crate) fn derive_header_tag<const N: usize, const S: u32>(
        &self,
        floe_iv: &FloeIv<N>,
        associated_data: &[u8],
    ) -> HeaderTag {
        const PURPOSE: &[u8] = b"HEADER_TAG:";

        // XXX: We're using the HKDF-Expand function without the extract step.
        // The HKDF-Expand function requires the pseudorandom input key
        // to be the same size as the output size of the hash[1][2].
        //
        // Our input key material is the Floe key, which is defined to be as
        // long as the AEAD key. In the Floe-GCM case this will mean the
        // key will be 32 bytes while the output size is 48 bytes.
        //
        // To be able to use the `Hkdf::from_prk` method we're going to
        // replicate what HMAC does if the key isn't long enough, namely
        // we pad it with zeroes[3].
        //
        // We're padding the key to the output size of the hash, while HMAC will
        // pad it further to the block size. The end result is the same.
        //
        // [1]: https://datatracker.ietf.org/doc/html/rfc5869#section-2.3
        // [2]: https://docs.rs/hkdf/0.13.0/hkdf/type.Hkdf.html#method.from_prk
        // [3]: https://www.rfc-editor.org/rfc/rfc2104.html#section-2
        let mut key = Array::<u8, K::OutputSize>::default();
        key.as_mut_slice()[..self.key.len()].copy_from_slice(self.key);

        let mut tag = HeaderTag { inner: Default::default() };
        floe_kdf::<A, K, N, S>(&key, floe_iv, associated_data, PURPOSE, &mut tag.inner);

        #[cfg(feature = "zeroize")]
        key.zeroize();

        tag
    }

    /// Derive the [`MessageKey`] using this [`FloeKey`] as the input key
    /// material of the `FLOE_KDF` operation.
    ///
    /// From the [spec]:
    ///
    /// ```text
    /// MessageKey = FLOE_KDF(key, iv, aad, "MESSAGE_KEY:", KDF_KEY_LEN)
    /// ```
    ///
    /// [spec]: https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#semi-public-functions-random-access
    pub(crate) fn derive_message_key<const N: usize, const S: u32>(
        &self,
        floe_iv: &FloeIv<N>,
        associated_data: &[u8],
    ) -> MessageKey<A, K> {
        const PURPOSE: &[u8] = b"MESSAGE_KEY:";

        // XXX: Same as in the `FloeKey::derive_header_tag` method, we need to
        // pad the key to make Hkdf::from_prk happy.
        let mut key = Array::<u8, K::OutputSize>::default();
        key.as_mut_slice()[..self.key.len()].copy_from_slice(self.key);

        let mut message_key = MessageKey {
            key: Default::default(),
            _phantom_aead: PhantomData,
            _phantom: PhantomData,
        };

        floe_kdf::<A, K, N, S>(&key, floe_iv, associated_data, PURPOSE, &mut message_key.key);

        #[cfg(feature = "zeroize")]
        key.zeroize();

        message_key
    }
}
