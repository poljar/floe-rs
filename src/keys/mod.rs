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

//! Module modeling the different key types Floe uses.

mod epoch_key;
mod floe_key;
mod message_key;

pub(crate) use floe_key::FloeKey;
pub(crate) use message_key::MessageKey;

/// The underlying byte [`hybrid_array::Array`] for a [`MessageKey`].
pub(crate) type FloeKdfKey<K> = hybrid_array::Array<u8, <K as digest::OutputSizeUser>::OutputSize>;
