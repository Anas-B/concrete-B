use concrete_shortint::parameters::*;
use concrete_shortint::{Ciphertext, Parameters, ServerKey};
use criterion::{criterion_group, criterion_main, Criterion};

use concrete_shortint::keycache::KEY_CACHE;
use rand::Rng;
use concrete_shortint::treepbs::TreepbsKey;
use concrete_shortint::parameters::PARAM_MESSAGE_3_CARRY_3;

fn main() {
    let (cks, sks) = KEY_CACHE.get_from_param(PARAM_MESSAGE_3_CARRY_3);

    let mut treepbs_key = TreepbsKey::new_tree_key(&cks);

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus.0 as u64;

    let clear_0 = rng.gen::<u64>() % modulus;
    let clear_1 = rng.gen::<u64>() % modulus;

    let ctxt_0 = cks.encrypt(clear_0);
    let ctxt_1 = cks.encrypt(clear_1);

    treepbs_key.mul_lsb_treepbs_with_multivalue_base(&sks, &ctxt_0, &ctxt_1);
}
