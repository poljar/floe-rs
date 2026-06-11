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

//! Common utility functions used in Floe.

use aead::AeadCore;
use hkdf::Hkdf;
use zerocopy::IntoBytes;

use crate::{
    FloeAead, FloeKdf,
    result::ConfigurationError,
    types::{FloeIv, Parameters, Segment, SegmentSize},
};

/// Calculate the plaintext size a non-final segment, once decrypted, will have.
pub(crate) fn plaintext_size<A, const S: SegmentSize>() -> usize
where
    A: AeadCore,
{
    #[allow(clippy::expect_used)]
    (TryInto::<usize>::try_into(S).expect("The encrypted segment size should fit into a u32"))
        .checked_sub(Segment::<'static, A, S>::overhead())
        .expect("The encrypted segment size should be bigger than the segment overhead")
}

/// Check the user-provided encrypted segment size has left enough space for the
/// segment header an encrypted segment requires.
///
/// The size of an encrypted segment is limited by the fact that the length of
/// the final segment needs to put into the segment header. The length of the
/// final segment is converted into a `u32` and encoded into 4 bytes as a
/// big-endian value.
///
/// This limits the size of the plaintext segment into `u32::MAX -
/// segment_overhead()`.
///
/// # Panics
///
/// The function will panic if the segment size (S) doesn't fit into a usize,
/// i.e. if this is used on a architecture where [usize] is [u16] and a segment
/// size bigger than [u16::MAX] is picked.
///
/// The function also panics if the segment overhead doesn't fit into the
/// segment, i.e. if the segment size is smaller than the segment overhead.
pub(crate) fn check_segment_size<A, const S: SegmentSize>() -> Result<(), ConfigurationError>
where
    A: AeadCore,
{
    TryInto::<usize>::try_into(S).map_err(|_| ConfigurationError::TooBigSegmentSize)?;

    // SAFETY: This cast will always be fine, the overhead by definition needs
    // to fit into an `u32` which is used for the segment size.
    #[allow(clippy::cast_possible_truncation)]
    let overhead = Segment::<A, S>::overhead() as SegmentSize;

    if S < (overhead) {
        Err(ConfigurationError::TooSmallSegmentSize { minimal: overhead, got: S })
    } else {
        Ok(())
    }
}

/// The internal FLOE_KDF function.
///
/// From the spec:
///
/// ```text
/// FLOE_KDF(key, iv, aad, purpose, len) -> byte[len]
///
/// Defined as KDF(key, PARAM_ENCODE(params) || iv || purpose || aad, len) where params is implicit
/// from the context.
///  ```
pub(crate) fn floe_kdf<A, K, const N: usize, const S: SegmentSize>(
    key: &[u8],
    floe_iv: &FloeIv<N>,
    associated_data: &[u8],
    purpose: &[u8],
    output: &mut [u8],
) where
    A: FloeAead,
    K: FloeKdf,
{
    let params = Parameters::new::<A, K, N, S>();
    let info = [params.as_bytes(), floe_iv.as_array(), purpose, associated_data];

    #[allow(clippy::expect_used)]
    let hkdf = Hkdf::<K>::from_prk(key)
        .expect("should be able to create a Hkdf instance from the pseudo-random key");

    #[allow(clippy::expect_used)]
    hkdf.expand_multi_info(&info, output)
        .expect("should be able to expand enough output key material for Floe")
}
