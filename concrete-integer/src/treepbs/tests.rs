use crate::client_key::VecLength;
use crate::keycache::KEY_CACHE;
use crate::treepbs::TreepbsKey;
use concrete_shortint::parameters::*;
use concrete_shortint::Parameters;
use paste::paste;
use rand::Rng;

/// Number of loop iteration within randomized tests
const NB_TEST: usize = 30;

/// Smaller number of loop iteration within randomized test,
/// meant for test where the function tested is more expensive
const NB_TEST_SMALLER: usize = 10;
const NB_CTXT: usize = 4;

macro_rules! create_parametrized_test{
    ($name:ident { $($param:ident),* }) => {
        paste! {
            $(
            #[test]
            fn [<test_ $name _ $param:lower>]() {
                $name($param)
            }
            )*
        }
    };
     ($name:ident)=> {
        create_parametrized_test!($name
        {
            PARAM_MESSAGE_1_CARRY_1,
            PARAM_MESSAGE_2_CARRY_2
            // PARAM_MESSAGE_3_CARRY_3
            // PARAM_MESSAGE_4_CARRY_4
        });
    };
}


create_parametrized_test!(block_mul_treepbs_with_multivalue);
create_parametrized_test!(mul_treepbs_with_multivalue);


fn block_mul_treepbs_with_multivalue(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, VecLength(NB_CTXT));
    let treepbs_key = TreepbsKey::new(&cks);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    let block_modulus = param.message_modulus.0 as u64;

    for _ in 0..5 {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % block_modulus;

        // Encrypt the integers
        let ctxt_1 = cks.encrypt(clear1);
        let ctxt_2 = cks.encrypt_one_block(clear2);

        let mut res = ctxt_1.clone();
        let mut clear = clear1;

        res = treepbs_key.block_mul_treepbs_with_multivalue(&sks, &mut res, &ctxt_2, 0);
        clear = (clear * clear2) % modulus;
        for _ in 0..5 {
            res = treepbs_key.block_mul_treepbs_with_multivalue(&sks,&mut res, &ctxt_2, 0);
            clear = (clear * clear2) % modulus;

            let dec = cks.decrypt(&res);

            // Check the correctness
            assert_eq!(clear, dec);
        }
    }
}

fn mul_treepbs_with_multivalue(param: Parameters) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, VecLength(NB_CTXT));
    let treepbs_key = TreepbsKey::new(&cks);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = param.message_modulus.0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST_SMALLER {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // println!("clear1 = {}, clear2 = {}", clear1, clear2);

        // Encrypt the integers
        let ctxt_1 = cks.encrypt(clear1);
        let mut ctxt_2 = cks.encrypt(clear2);

        let mut res = ctxt_1.clone();
        let mut clear = clear1;

        res = treepbs_key.mul_treepbs_with_multivalue(&sks, &mut res, &mut ctxt_2);
        clear = (clear * clear2) % modulus;
        for _ in 0..5 {
            res = treepbs_key.mul_treepbs_with_multivalue(&sks, &mut res, &mut ctxt_2);

            clear = (clear * clear2) % modulus;
            let dec = cks.decrypt(&res);

            // Check the correctness
            assert_eq!(clear, dec);
        }
    }
}
