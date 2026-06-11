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

//! Module for the Floe header tag.
//!
//! See the documentation for [`HeaderTag`] for more information.

use aead::{array::Array, consts::U32};
use digest::typenum::Unsigned;
use subtle::ConstantTimeEq;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[cfg(doc)]
use super::Header;

/// The size of the header tag.
pub(crate) type HeaderTagSize = U32;

/// The tag of a Floe [Header].
///
/// This tag is used to commit the key, Floe IV, and additional associated data
/// provided by the user.
#[derive(Debug, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct HeaderTag {
    /// The inner array containing the bytes of the tag.
    pub(crate) inner: Array<u8, HeaderTagSize>,
}

impl HeaderTag {
    /// The length of the header tag in bytes.
    pub const LENGTH: usize = HeaderTagSize::USIZE;

    /// Represent the [`HeaderTag`] as an array of bytes.
    pub fn as_array(&self) -> &[u8; HeaderTagSize::USIZE] {
        // SAFETY: This can't panic as we are guaranteed to have used the correct array
        // size.
        #[allow(clippy::expect_used, clippy::missing_panics_doc)]
        self.inner.as_array().expect("We should be able to convert the Array to a primitive array")
    }
}

impl ConstantTimeEq for HeaderTag {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.inner.ct_eq(&other.inner)
    }
}
