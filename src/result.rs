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

//! Error types for Floe.

use thiserror::Error;

use crate::types::{Parameters, SegmentSize};

/// The given Floe configuration contains errors.
///
/// For example, this can occur when an invalid segment size is specified,
/// whether it is too large or too small.
#[derive(Debug, Error)]
pub enum ConfigurationError {
    /// The given output buffer was either too big or too small.
    #[error("the output buffer has an incorrect length, expected: {expected}, got {got}")]
    InvalidBuffer {
        /// The expected output buffer size.
        expected: usize,
        /// The size of the buffer which was given to the decrypt method.
        got: usize,
    },

    /// The maximum number of segments was reached for this Floe decryption
    /// session.
    #[error("we have reached the maximal number of segments the configured AEAD supports ({0})")]
    MaxSegmentsReached(u64),

    /// The configured segment size is too small.
    ///
    /// The segment size needs have at least enough place for the segment
    /// header, AEAD nonce and AEAD tag.
    #[error(
        "the given segment size is too small, the minimal segment size is {minimal}, got {got}"
    )]
    TooSmallSegmentSize {
        /// The lowest value the segment size could be.
        minimal: SegmentSize,
        /// The segment size that was configured,
        got: SegmentSize,
    },

    /// The configured segment size is too big.
    ///
    /// The error can happen segment size doesn't fit into a usize, i.e. if this
    /// is used on a architecture where [usize] is [u16] and a segment size
    /// bigger than [u16::MAX] is picked.
    #[error("the given segment size does not fit into an usize")]
    TooBigSegmentSize,
}

/// Error type for Floe decryption operations.
#[derive(Debug, Error)]
pub enum DecryptionError {
    /// The ciphertext couldn't be decrypted, most likely because the AEAD tag
    /// is invalid.
    #[error("the ciphertext couldn't be decrypted")]
    Aead(#[from] aead::Error),

    /// The header failed to be verified, the header tag is invalid.
    #[error("the Floe header contains an invalid tag")]
    InvalidHeaderTag,

    /// There was an issue with the configuration of the Floe decryptor.
    #[error(transparent)]
    ConfigurationError(#[from] ConfigurationError),

    /// The parameters of the decryptor and the parameters defined in the header
    /// of the Floe ciphertext don't match.
    #[error(
        "the given header has different Floe parameters compared to what was configured \
        in the decryptor, expected: {expected:?}, got: {got:?}"
    )]
    InvalidParameters {
        /// The expected parameters, the one the decryptor was configured with.
        expected: Parameters,
        /// The parameters contained in the header.
        got: Parameters,
    },
}

/// Error type for Floe encryption operations.
#[derive(Debug, Error)]
pub enum EncryptionError {
    /// The AEAD couldn't encrypt the plaintext.
    #[error("the ciphertext couldn't be encrypted")]
    Aead(#[from] aead::Error),

    /// There was an issue with the configuration of the Floe encryptor.
    #[error(transparent)]
    ConfigurationError(#[from] ConfigurationError),

    /// The given plaintext has an incorrect length.
    #[error("the plaintext has an incorrect length, expected: {expected}, got {got}")]
    InvalidPlaintextLength {
        /// The expected plaintext length, as configured by the segment size.
        expected: usize,
        /// The plaintext length the encrypt method received.
        got: usize,
    },

    /// Creating a Floe IV failed.
    #[error("the random Floe IV couldn't be generated")]
    FloeIvGenerationFailed,

    /// Encryption failed because a new random nonce for the segment couldn't be
    /// generated.
    #[error("the random nonce for the segment couldn't be generated")]
    NonceGenerationFailed,
}

/// Error type header decoding operations.
#[derive(Debug, Error)]
pub enum HeaderDecodeError {
    /// The given byte slice couldn't be decoded into a Floe header.
    ///
    /// The length of the byte-slice is invalid.
    #[error("the given header has an incorrect length, expected {expected}, got {got}")]
    InvalidLength {
        /// The expected size of slice containing a Floe header.
        expected: usize,
        /// The size of the slice we tried to decode.
        got: usize,
    },
}

/// Error type segment decoding operations.
#[derive(Debug, Error)]
pub enum SegmentDecodeError {
    /// The given byte slice couldn't be decoded into an encrypted segment.
    ///
    /// The length of the byte-slice is invalid.
    #[error(
        "the given slice is too small to be interpreted as a segment, expected at least {expected} bytes, got {got}"
    )]
    InvalidSliceLength {
        /// The minimal expected size of a segment.
        expected: usize,
        /// The size of the slice we tried to decode.
        got: usize,
    },

    /// The encrypted segment is malformed and couldn't be decoded.
    ///
    /// This may happen if the segment claims to be the final segment, but the
    /// length of the segment presented in the header is not correct.
    #[error("the given encrypted segment is malformed")]
    MalformedSegment,
}
