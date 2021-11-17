use ark_ff::vec::Vec;
use ethabi::{encode, Token};
use tiny_keccak::{Hasher, Keccak};
#[derive(Clone)]
pub struct VAnchorArbitraryData {
	pub recipient: Token,
	pub ext_amount: Token,
	pub relayer: Token,
	pub fee: Token,
	pub encrypted_output1: Token,
	pub encrypted_output2: Token,
}

impl VAnchorArbitraryData {
	pub fn new(
		recipient: Token,
		ext_amount: Token,
		relayer: Token,
		fee: Token,
		encrypted_output1: Token,
		encrypted_output2: Token,
	) -> Self {
		VAnchorArbitraryData::check_inputs(
			&recipient,
			&ext_amount,
			&relayer,
			&fee,
			&encrypted_output1,
			&encrypted_output2,
		);
		Self {
			recipient,
			ext_amount,
			relayer,
			fee,
			encrypted_output1,
			encrypted_output2,
		}
	}

	pub fn hash_data(
		recipient: Token,
		ext_amount: Token,
		relayer: Token,
		fee: Token,
		encrypted_output1: Token,
		encrypted_output2: Token,
	) -> Vec<u8> {
		VAnchorArbitraryData::check_inputs(
			&recipient,
			&ext_amount,
			&relayer,
			&fee,
			&encrypted_output1,
			&encrypted_output2,
		);
		let tuple = [Token::Tuple(vec![
			recipient,
			ext_amount,
			relayer,
			fee,
			encrypted_output1,
			encrypted_output2,
		])];
		let encoded_input = encode(&tuple);
		let bytes: &[u8] = &encoded_input;
		let mut hasher = Keccak::v256();
		hasher.update(bytes);
		let mut res: [u8; 32] = [0; 32];
		hasher.finalize(&mut res);
		res.to_vec()
	}

	pub fn hash_data_self(&self) -> Vec<u8> {
		let tuple = [Token::Tuple(vec![
			self.recipient.clone(),
			self.ext_amount.clone(),
			self.relayer.clone(),
			self.fee.clone(),
			self.encrypted_output1.clone(),
			self.encrypted_output2.clone(),
		])];

		let encoded_input = encode(&tuple);
		let bytes: &[u8] = &encoded_input;
		let mut hasher = Keccak::v256();
		hasher.update(bytes);
		let mut res: [u8; 32] = [0; 32];
		hasher.finalize(&mut res);
		res.to_vec()
	}

	pub fn check_inputs(
		recipient: &Token,
		ext_amount: &Token,
		relayer: &Token,
		fee: &Token,
		encrypted_output1: &Token,
		encrypted_output2: &Token,
	) {
		match recipient {
			Token::Address(_address) => {}
			_ => {
				panic!("recipient address is not valid");
			}
		}
		match ext_amount {
			Token::Int(_u256) => {}
			_ => {
				panic!("the ext_amount is not valid");
			}
		}
		match relayer {
			Token::Address(_address) => {}
			_ => {
				panic!("relayer address is not valid");
			}
		}
		match fee {
			Token::Uint(_u256) => {}
			_ => {
				panic!("fee is not valid");
			}
		}
		match encrypted_output1 {
			Token::Bytes(_bytes) => {}
			_ => {
				panic!("encrypted_output1 is not valid");
			}
		}
		match encrypted_output2 {
			Token::Bytes(_bytes) => {}
			_ => {
				panic!("encrypted_output2 is not valid");
			}
		}
	}
}

#[cfg(test)]
mod test {

	use super::VAnchorArbitraryData;
	use crate::utils::decode_hex;
	use ethabi::Token;
	use hex_literal::hex;
	#[test]
	fn should_creat_arbitrary_data_hashes_same_as_circom() {
		let recipient = hex!("0000000000000000000000000000000000000000");
		let recipient = Token::Address(recipient.into());
		let ext_amount = hex!("0000000000000000000000000000000000000000000000000000000000a7d8c0");
		let ext_amount = Token::Int(ext_amount.into());

		let relayer = hex!("2111111111111111111111111111111111111111");
		let relayer = Token::Address(relayer.into());

		let fee = hex!("00000000000000000000000000000000000000000000000000000000000f4240");
		let fee = Token::Uint(fee.into());

		let encrypted_output1 =hex!(
			"ab4d70e711e295e9760a0465a8b155c989a10f2370833f8ca9163b1a57baba9396675f5810a64e044c5a16ac16318d9848bfecdf16f7c57bbef0cafcc4f7e8f3ee8f9c7af97699460a47004659e6d97df66eb3b7f538edccb0cded0f3116eb833ba05c396fa2f5f0793a16961a71c3f14bb175aaaecb6ae768bdb192cccc40ab623ba7c1d5c49aca1db2364c3b831bc5dc730d500e3e17e1960fdac8e82adec97731ac3ed2361038d541476ce825da21");
		let encrypted_output1 = Token::Bytes(encrypted_output1.into());

		let encrypted_output2 =hex!(
			"da0d95fd53a6c0f87f956b91838db7e4f95b43513e1b6c0ea5ef5e4855bde73dc4d20fd90ea3e201b977a39dbd0a791dd467a8d39dd64a0ea3f0ffe499aae2e82e17581fbf6a6607b7555b82551ed6c38080337a1d3cded750ef1318bc77388d0ed585811ac330eda6b3a3143019dbe29ffa9e67e4f7dda3dd7c1b2d60ea8516f546dfccfad2e3fb96eb1ad7e8839097e5107d3a9a17318d08c172199f3cda1683097d5a9ba88a635b31548aebd9aaca");
		let encrypted_output2 = Token::Bytes(encrypted_output2.into());

		let arbitrary = VAnchorArbitraryData::new(
			recipient.clone(),
			ext_amount.clone(),
			relayer.clone(),
			fee.clone(),
			encrypted_output1.clone(),
			encrypted_output2.clone(),
		);
		let res = arbitrary.hash_data_self();
		let expected_ext_data_hash =
			"0xaecceec52df7aa343dfbea873e1c984c26879df91d1ae3a7bcb641377669a79c";
		let expected_ext_data_hash = decode_hex(expected_ext_data_hash);

		let res2 = VAnchorArbitraryData::hash_data(
			recipient,
			ext_amount,
			relayer,
			fee,
			encrypted_output1,
			encrypted_output2,
		);
		assert_eq!(res, expected_ext_data_hash);
		assert_eq!(res2, expected_ext_data_hash);
	}
}
