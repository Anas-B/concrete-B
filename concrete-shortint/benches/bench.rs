use concrete_shortint::parameters::*;
use concrete_shortint::{Ciphertext, Parameters, ServerKey};
use criterion::{criterion_group, criterion_main, Criterion};

use concrete_shortint::keycache::KEY_CACHE;
use rand::Rng;
use concrete_shortint::treepbs::TreepbsKey;

macro_rules! named_param {
    ($param:ident) => {
        (stringify!($param), $param)
    };
}

const SERVER_KEY_BENCH_PARAMS: [(&str, Parameters); 3] = [
    named_param!(PARAM_MESSAGE_1_CARRY_1),
    named_param!(PARAM_MESSAGE_2_CARRY_2),
    named_param!(PARAM_MESSAGE_3_CARRY_3)
    // named_param!(PARAM_MESSAGE_4_CARRY_4),
];

fn programmable_bootstrapping(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("programmable_bootstrapping");

    for (param_name, param) in SERVER_KEY_BENCH_PARAMS {
        let (cks, sks) = KEY_CACHE.get_from_param(param);

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters.message_modulus.0 as u64;

        let acc = sks.generate_accumulator(|x| x);

        let clear_0 = rng.gen::<u64>() % modulus;

        let ctxt = cks.encrypt(clear_0);

        let id = format!("ServerKey::programmable_bootstrapping::{}", param_name);

        bench_group.bench_function(&id, |b| {
            b.iter(|| {
                sks.keyswitch_programmable_bootstrap(&ctxt, &acc);
            })
        });
    }

    bench_group.finish();
}

fn mul_lsb_treepbs_with_multivalue(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("mul_lsb_treepbs_with_multivalue");

    for (param_name, param) in SERVER_KEY_BENCH_PARAMS {
        let (cks, sks) = KEY_CACHE.get_from_param(param);

        let mut treepbs_key = TreepbsKey::new_tree_key(&cks);

        let mut rng = rand::thread_rng();

        let modulus = cks.parameters.message_modulus.0 as u64;

        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        let id = format!("ServerKey::mul_lsb_treepbs_with_multivalue::{}", param_name);

        bench_group.bench_function(&id, |b| {
            b.iter(|| {
                treepbs_key.mul_lsb_treepbs_with_multivalue(&sks, &ctxt_0, &ctxt_1);
            })
        });
    }

    bench_group.finish();
}

// macro_rules! define_server_key_bench_fn (
//   ($server_key_method:ident) => {
//       fn $server_key_method(c: &mut Criterion) {
//           bench_server_key_binary_function(
//               c,
//               concat!("ServerKey::", stringify!($server_key_method)),
//               |server_key, lhs, rhs| {
//                 server_key.$server_key_method(lhs, rhs);
//           })
//       }
//   }
// );
//
// macro_rules! define_server_key_scalar_bench_fn (
//   ($server_key_method:ident) => {
//       fn $server_key_method(c: &mut Criterion) {
//           bench_server_key_binary_scalar_function(
//               c,
//               concat!("ServerKey::", stringify!($server_key_method)),
//               |server_key, lhs, rhs| {
//                 server_key.$server_key_method(lhs, rhs);
//           })
//       }
//   }
// );

criterion_group!(
    arithmetic_operation,
    programmable_bootstrapping,
    mul_lsb_treepbs_with_multivalue,
);

criterion_main!(arithmetic_operation,);
