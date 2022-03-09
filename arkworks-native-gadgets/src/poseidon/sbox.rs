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

use super::PoseidonError;
use ark_ff::PrimeField;

/// An S-Box that can be used with Poseidon.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PoseidonSbox(pub i8);

impl Default for PoseidonSbox {
	fn default() -> Self {
		PoseidonSbox(5)
	}
}

impl PoseidonSbox {
	pub fn apply_sbox<F: PrimeField>(&self, elem: F) -> Result<F, PoseidonError> {
		let res = match self.0 {
			3 => elem * elem * elem,
			5 => {
				let sqr = elem.square();
				sqr.square().mul(elem)
			}
			17 => {
				let sqr = elem * elem;
				let quad = sqr * sqr;
				let eighth = quad * quad;
				let sixteenth = eighth * eighth;
				sixteenth * elem
			}
			-1 => elem.inverse().ok_or(PoseidonError::ApplySboxFailed)?,
			// default to cubed
			n => return Err(PoseidonError::InvalidSboxSize(n)),
		};
		Ok(res)
	}
}
