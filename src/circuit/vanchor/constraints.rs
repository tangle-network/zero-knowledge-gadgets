
use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::{fields::PrimeField};
use ark_r1cs_std::prelude::*;

use ark_std::marker::PhantomData;

#[derive(Clone)]
pub struct KeypairsVar<F: PrimeField, H: CRH, HG: CRHGadget<H, F>> {
    pubkey_var: <HG as CRHGadget<H,F>>::OutputVar,
    data: PhantomData<F>,
}
impl<F: PrimeField, H: CRH, HG: CRHGadget<H, F>> KeypairsVar<F, H, HG> {

    pub fn compute_public_key(h: &HG::ParametersVar,
        privkey: &Vec<UInt8<F>>
    )-> Self
    {
        let pubkey_var = HG::evaluate(&h, &privkey).unwrap();
        KeypairsVar{
            pubkey_var,
            data: PhantomData,
        }
    }
}


#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::{ 
        leaf::{NewLeafCreation, newleaf::NewLeaf, }};
    use crate::{poseidon::{
            constraints::{CRHGadget, PoseidonParametersVar},
            sbox::PoseidonSbox,
            PoseidonParameters, Rounds, CRH,
        }, utils::{get_mds_poseidon_bls381_x5_5, get_rounds_poseidon_bls381_x5_5}};
    use ark_bls12_381::Fq;
    use ark_ff::to_bytes;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;
    use ark_crypto_primitives::crh::CRH as CRHTrait;
    use ark_crypto_primitives::crh::constraints::{CRHGadget as CRHGadgetTrait};
    use KeypairsVar;
    #[derive(Default, Clone)]
    struct PoseidonRounds3;

    impl Rounds for PoseidonRounds3 {
        const FULL_ROUNDS: usize = 8;
        const PARTIAL_ROUNDS: usize = 57;
        const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
        const WIDTH: usize = 4;
    }

    type PoseidonCRH3 = CRH<Fq, PoseidonRounds3>;
    type PoseidonCRH3Gadget = CRHGadget<Fq, PoseidonRounds3>;

    type Leaf = NewLeaf<Fq, PoseidonCRH3>;
  
    type Keypairs= KeypairsVar::<Fq, PoseidonCRH3,PoseidonCRH3Gadget>;

    #[test]
    fn should_crate_publik_key_constraints() {
        let rng = &mut test_rng();
        let cs = ConstraintSystem::<Fq>::new_ref();

        // Native version
        let rounds = get_rounds_poseidon_bls381_x5_5::<Fq>();
        let mds = get_mds_poseidon_bls381_x5_5::<Fq>();
        let params = PoseidonParameters::<Fq>::new(rounds, mds);
        let secrets = Leaf::generate_secrets(rng).unwrap();
        let privkey = to_bytes![secrets.priv_key].unwrap();
        let pubkey = PoseidonCRH3::evaluate(&params, &privkey).unwrap();

        // Constraints version
        let bytes = to_bytes![secrets.priv_key].unwrap();
        let privkey_var = Vec::<UInt8<Fq>>::new_witness(cs.clone(), || Ok(bytes)).unwrap();
        let params_var =
            PoseidonParametersVar::new_variable(cs, || Ok(&params), AllocationMode::Constant)
                .unwrap();
        let pubkey_var = PoseidonCRH3Gadget::evaluate(&params_var, &privkey_var).unwrap();    
        let keypair= Keypairs::compute_public_key(&params_var, &privkey_var);
        let new_pubkey_var = keypair.pubkey_var.value().unwrap();
        // Check equality
        let res = pubkey_var.value().unwrap();
        assert_eq!(res,pubkey);   
        assert_eq!(res,new_pubkey_var);   

    }
}
    

