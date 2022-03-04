// This file is part of Webb.

// Copyright (C) 2021 Webb Technologies Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
pub extern crate ark_std;

use ark_std::boxed::Box;

pub mod anchor;
pub mod basic;
pub mod mixer;
pub mod poseidon;
pub mod vanchor;

pub type Error = Box<dyn ark_std::error::Error>;

pub mod prelude {
	pub use ark_crypto_primitives;
	pub use ark_ff;
	pub use ark_std;
}
