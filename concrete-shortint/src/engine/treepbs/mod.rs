use crate::ciphertext::Degree;
use crate::engine::{EngineResult, ShortintEngine};
use crate::treepbs::TreepbsKey;
use crate::{Ciphertext, ClientKey, ServerKey};
use concrete_core::backends::core::private::crypto::bootstrap::multivaluepbs::{generate_fourier_polynomial_multivalue, generate_fourier_polynomial_multivalue_base};
use concrete_core::backends::core::private::crypto::bootstrap::FourierBuffers;
use concrete_core::backends::core::private::crypto::lwe::LweCiphertext;
use concrete_core::backends::core::private::math::polynomial::Polynomial;
use concrete_core::prelude::{
    DispersionParameter, LweBootstrapKeyEntity, LweCiphertext64, PackingKeyswitchKeyCreationEngine,
    Variance,
};

impl ShortintEngine {
    pub(crate) fn new_treepbs_key(&mut self, cks: &ClientKey) -> EngineResult<TreepbsKey> {
        let decomp_log_base = cks.parameters.ks_base_log;
        let decomp_level_count = cks.parameters.ks_level;
        let noise = Variance(cks.parameters.glwe_modular_std_dev.get_variance());

        let pksk = self.engine.create_packing_keyswitch_key(
            &cks.lwe_secret_key,
            &cks.glwe_secret_key,
            decomp_level_count,
            decomp_log_base,
            noise,
        )?;
        let treepbs_key = TreepbsKey { pksk };
        Ok(treepbs_key)
    }

    pub fn mul_msb_treepbs_with_multivalue(
        &mut self,
        treepbskey: &TreepbsKey,
        sks: &ServerKey,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        // glwe_sk: &GlweSecretKey<BinaryKeyKind, Vec<u64>>,
        // lwe_sk: &LweSecretKey<BinaryKeyKind, Vec<u64>>,
    ) -> EngineResult<Ciphertext> {
        //Create the buffers
        //=======================================================================
        let mut lwe_out = LweCiphertext::allocate(
            0_u64,
            sks.bootstrapping_key.output_lwe_dimension().to_lwe_size(),
        );

        let mut buffers = FourierBuffers::new(
            sks.bootstrapping_key.polynomial_size(),
            sks.bootstrapping_key.glwe_dimension().to_glwe_size(),
        );
        //=======================================================================

        //Keyswitch the ciphertexts
        //=======================================================================
        let vec_lwe_in = vec![ct_left.ct.clone().0, ct_right.ct.clone().0];
        let empty_selector =
            LweCiphertext::allocate(0_u64, sks.bootstrapping_key.0.key_size().to_lwe_size());
        let mut selectors = vec![empty_selector; vec_lwe_in.len()];
        sks.key_switching_key
            .0
            .vector_keyswitch(&mut selectors, &vec_lwe_in);
        //=======================================================================

        //Create the polynomial to multiply the accumulator with
        //=======================================================================
        let mut poly_block_redundancy = vec![0_u64; sks.bootstrapping_key.polynomial_size().0];

        let modulus = sks.message_modulus.0 * sks.carry_modulus.0;
        let base = sks.message_modulus.0;

        // N/(p/2) = size of each block
        let box_size = sks.bootstrapping_key.polynomial_size().0 / modulus;

        let block_size = box_size * modulus;

        for block in poly_block_redundancy.chunks_exact_mut(block_size) {
            block[..box_size].fill(1);
        }

        let poly_redundancy = Polynomial::from_container(poly_block_redundancy);
        //=======================================================================

        //Generate accumulators
        //=========================================================
        let mut poly_acc = Vec::with_capacity(modulus);
        for i in 0..modulus {
            poly_acc.push(generate_fourier_polynomial_multivalue(
                |x| (i as u64 * x)/base as u64,
                modulus,
                sks.bootstrapping_key.polynomial_size(),
            ));
        }
        // println!("poly = {:?}", poly_acc);
        //=========================================================

        sks.bootstrapping_key.0.treepbs_with_multivalue(
            &treepbskey.pksk.0,
            &mut lwe_out,
            &selectors,
            &sks.key_switching_key.0,
            &mut buffers,
            modulus as u64,
            0,
            // &poly_redundancy,
            // &glwe_sk,
            // &lwe_sk,
            &poly_acc,
        );

        Ok(Ciphertext {
            ct: LweCiphertext64(lwe_out),
            degree: Degree(sks.message_modulus.0 - 1),
            message_modulus: sks.message_modulus,
            carry_modulus: sks.carry_modulus,
        })
    }

    pub fn mul_lsb_treepbs_with_multivalue(
        &mut self,
        treepbskey: &TreepbsKey,
        sks: &ServerKey,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        // glwe_sk: &GlweSecretKey<BinaryKeyKind, Vec<u64>>,
        // lwe_sk: &LweSecretKey<BinaryKeyKind, Vec<u64>>,
    ) -> EngineResult<Ciphertext> {
        //Create the buffers
        //=======================================================================
        let mut lwe_out = LweCiphertext::allocate(
            0_u64,
            sks.bootstrapping_key.output_lwe_dimension().to_lwe_size(),
        );

        let mut buffers = FourierBuffers::new(
            sks.bootstrapping_key.polynomial_size(),
            sks.bootstrapping_key.glwe_dimension().to_glwe_size(),
        );
        //=======================================================================

        //Keyswitch the ciphertexts
        //=======================================================================
        let vec_lwe_in = vec![ct_left.ct.clone().0, ct_right.ct.clone().0];
        let empty_selector =
            LweCiphertext::allocate(0_u64, sks.bootstrapping_key.0.key_size().to_lwe_size());
        let mut selectors = vec![empty_selector; vec_lwe_in.len()];
        sks.key_switching_key
            .0
            .vector_keyswitch(&mut selectors, &vec_lwe_in);
        //=======================================================================

        //Create the polynomial to multiply the accumulator with
        //=======================================================================
        let mut poly_block_redundancy = vec![0_u64; sks.bootstrapping_key.polynomial_size().0];

        let modulus = sks.message_modulus.0 * sks.carry_modulus.0;
        let base = sks.message_modulus.0;

        // N/(p/2) = size of each block
        let box_size = sks.bootstrapping_key.polynomial_size().0 / modulus;

        let block_size = box_size * modulus;

        for block in poly_block_redundancy.chunks_exact_mut(block_size) {
            block[..box_size].fill(1);
        }

        let poly_redundancy = Polynomial::from_container(poly_block_redundancy);
        //=======================================================================

        //Generate accumulators
        //=========================================================
        let mut poly_acc = Vec::with_capacity(modulus);
        for i in 0..modulus {
            poly_acc.push(generate_fourier_polynomial_multivalue(
                |x| (i as u64 * x) % base as u64,
                modulus,
                sks.bootstrapping_key.polynomial_size(),
            ));
        }
        // println!("poly = {:?}", poly_acc);
        //=========================================================

        sks.bootstrapping_key.0.treepbs_with_multivalue(
            &treepbskey.pksk.0,
            &mut lwe_out,
            &selectors,
            &sks.key_switching_key.0,
            &mut buffers,
            modulus as u64,
            0,
            // &poly_redundancy,
            // &glwe_sk,
            // &lwe_sk,
            &poly_acc,
        );

        Ok(Ciphertext {
            ct: LweCiphertext64(lwe_out),
            degree: Degree(sks.message_modulus.0 - 1),
            message_modulus: sks.message_modulus,
            carry_modulus: sks.carry_modulus,
        })
    }

    pub fn bivaluepbs<F1, F2>(
        &mut self,
        sks: &ServerKey,
        ct_in: &Ciphertext,
        f_1: F1,
        f_2: F2,
    ) -> EngineResult<Vec<Ciphertext>>
    where
        F1: Fn(u64) -> u64,
        F2: Fn(u64) -> u64,
    {
        //Keyswitch the ciphertext
        let mut selector =
            LweCiphertext::allocate(0_u64, sks.bootstrapping_key.0.key_size().to_lwe_size());
        sks.key_switching_key
            .0
            .keyswitch_ciphertext(&mut selector, &ct_in.ct.0);

        let mut buffers = FourierBuffers::new(
            sks.bootstrapping_key.polynomial_size(),
            sks.bootstrapping_key.glwe_dimension().to_glwe_size(),
        );

        let modulus = (sks.message_modulus.0 * sks.carry_modulus.0) as u64;
        //Generate accumulators
        //=========================================================
        let poly_acc = vec![
            generate_fourier_polynomial_multivalue(
                f_1,
                modulus as usize,
                sks.bootstrapping_key.polynomial_size(),
            ),
            generate_fourier_polynomial_multivalue(
                f_2,
                modulus as usize,
                sks.bootstrapping_key.polynomial_size(),
            ),
        ];
        //=========================================================

        let vec_lwe = sks.bootstrapping_key.0.multivalue_programmable_bootstrap(
            &selector,
            modulus,
            &poly_acc,
            &mut buffers,
        );

        let c_1 = Ciphertext {
            ct: LweCiphertext64(vec_lwe[0].clone()),
            degree: Degree(sks.message_modulus.0 - 1),
            message_modulus: sks.message_modulus,
            carry_modulus: sks.carry_modulus,
        };

        let c_2 = Ciphertext {
            ct: LweCiphertext64(vec_lwe[1].clone()),
            degree: Degree(sks.message_modulus.0 - 1),
            message_modulus: sks.message_modulus,
            carry_modulus: sks.carry_modulus,
        };

        Ok(vec![c_1, c_2])
    }

    pub fn message_and_carry_extract(
        &mut self,
        sks: &ServerKey,
        ct_in: &Ciphertext,
    ) -> EngineResult<Vec<Ciphertext>> {
        let base = sks.message_modulus.0;
        self.bivaluepbs(sks, ct_in, |x| (x % base as u64), |x| (x / base as u64))
    }
}
