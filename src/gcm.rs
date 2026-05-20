// Copyright 2026 Damir Jelić.
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

//! Implementation of the Floe AES-GCM variant.
//!
//! The crate offers a generic Floe implementation. This module specializes it
//! by providing type aliases for the GCM-based variant.

use core::num::NonZero;

use aead::Key;
use aes_gcm::Aes256Gcm;
use sha2::Sha384;

use crate::{
    FloeAead, FloeKdf,
    types::{AeadRotationMask, SegmentSize},
};

/// The length of the Floe initialization vector for Floe-Gcm.
const FLOE_IV_LENGTH: usize = 32;

impl FloeKdf for Sha384 {
    // As per the Floe spec defined in the derived parameters part:
    // https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#derived-parameters
    const KDF_ID: u8 = 0;
}

impl FloeAead for Aes256Gcm {
    // As per the Floe spec defined in the derived parameters part:
    // https://github.com/Snowflake-Labs/floe-specification/blob/main/spec/README.md#derived-parameters
    const AEAD_ID: u8 = 0;

    const AEAD_ROTATION_MASK: AeadRotationMask = !((1u64 << 20) - 1);

    #[allow(clippy::expect_used)]
    const AEAD_MAX_SEGMENTS: NonZero<u64> = NonZero::new(1 << 40)
        .expect("should be able to create a non-zero value, as this clearly isn't zero");
}

/// The GCM implementation of the Floe random-access encryption APIs.
///  
/// This is a type alias over the generic implementation with [`Aes256Gcm`] and
/// [`Hmac<Sha384>`] picked as the AEAD and KDF implementation.
pub type FloeEncryptor<'a, const S: SegmentSize> =
    crate::random_access::FloeEncryptor<'a, Aes256Gcm, Sha384, FLOE_IV_LENGTH, S>;

/// The GCM implementation of the Floe random-access decryption APIs.
///  
/// This is a type alias over the generic implementation with [`Aes256Gcm`] and
/// [`Hmac<Sha384>`] picked as the AEAD and KDF implementation.
pub type FloeDecryptor<'a, const S: SegmentSize> =
    crate::random_access::FloeDecryptor<'a, Aes256Gcm, Sha384, FLOE_IV_LENGTH, S>;

/// The Floe-GCM key.
///
/// This is a type alias for the [`Aes256Gcm`] key type.
pub type FloeKey = Key<Aes256Gcm>;

/// The initialization vector of a Floe-Gcm session.
///
/// This variant of the initialization vector is 32 bytes long.
///
/// This initialization vector is randomly generated at the start of the
/// encryption operation.
pub type FloeIv = crate::types::FloeIv<FLOE_IV_LENGTH>;

/// The header of a Floe GCM ciphertext.
///
/// The Floe ciphertext consists of a header and a body. This struct represents
/// the header which contains:
/// * parameter information
/// * the 32-byte Floe initialization vector
/// * a tag
///
/// The header is created before the first segment is encrypted and is required
/// before any segment can be decrypted.
///
/// # Examples
///
/// ```no_run
/// use floe_rs::gcm::Header;
///
/// # let bytes: &[u8] = unimplemented!();
/// let header = Header::from_bytes(bytes)?;
///
/// // Now you can create a decryptor to attempt segment decryption.
/// # Ok::<(), anyhow::Error>(())
/// ```
pub type Header = crate::types::Header<FLOE_IV_LENGTH>;

/// Attempt to decode a slice of bytes as a Floe-Gcm [`Segment`]
///
/// *Note*: This only attempts to reinterpret the bytes as a valid
/// [`Segment`], as such it does not copy any data.
///
/// # Examples
///
/// ```no_run
/// use floe_rs::gcm::Segment;
///
/// # let bytes: &[u8] = unimplemented!();
/// let segment = Segment::<1024>::from_bytes(bytes, true)?;
/// let buffer = vec![0u8; segment.plaintext_size()];
///
/// // Now you can attempt to decrypt the segment.
/// # Ok::<(), anyhow::Error>(())
/// ```
pub type Segment<'a, const S: SegmentSize> = crate::types::segment::Segment<'a, Aes256Gcm, S>;
