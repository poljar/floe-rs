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

//! Module for the Floe initialization vector.
//!
//! See the documentation for [`FloeIv`] for more information.

use rand_core::CryptoRng;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

// TODO: We could use `const N: u16` for the generics here, this would be enough
// for any IV someone would like to configure and would have `Into`
// implementations for `usize` as well as `u32`. This would ensure at compile
// time that the IV isn't too big. Sadly this requires the `generic_const_exprs`
// feature which is only available on Rust nightly.

/// The initialization vector of a Floe session.
///
/// This initialization vector is randomly generated at the start of the
/// encryption operation.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct FloeIv<const N: usize> {
    /// The byte array containing the initialization vector.
    inner: [u8; N],
}

impl<const N: usize> FloeIv<N> {
    /// Generate a new random [`FloeIv`].
    pub(crate) fn generate<R: CryptoRng>(rng: &mut R) -> Result<Self, R::Error> {
        let mut floe_iv = [0u8; N];
        rng.try_fill_bytes(&mut floe_iv)?;

        Ok(Self { inner: floe_iv })
    }

    /// Get the underlying raw byte array of this [`FloeIv`].
    pub fn as_array(&self) -> &[u8; N] {
        &self.inner
    }
}
