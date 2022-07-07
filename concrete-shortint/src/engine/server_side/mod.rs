use super::ShortintEngine;
use crate::ciphertext::Degree;
use crate::engine::EngineResult;
use crate::server_key::MaxDegree;
use crate::{Ciphertext, ClientKey, ServerKey};
use concrete_core::prelude::*;
use std::cmp::min;

mod add;
mod bitwise_op;
mod comp_op;
mod div_mod;
mod mul;
mod neg;
mod scalar_add;
mod scalar_mul;
mod scalar_sub;
mod shift;
mod sub;

impl ShortintEngine {
    pub(crate) fn new_server_key(&mut self, cks: &ClientKey) -> EngineResult<ServerKey> {
        // Plaintext Max Value
        let max_value = cks.parameters.message_modulus.0 * cks.parameters.carry_modulus.0 - 1;

        // The maximum number of operations before we need to clean the carry buffer
        let max = MaxDegree(max_value);
        self.new_server_key_with_max_degree(cks, max)
    }

    pub(crate) fn new_server_key_with_max_degree(
        &mut self,
        cks: &ClientKey,
        max_degree: MaxDegree,
    ) -> EngineResult<ServerKey> {
        // Convert into a variance for rlwe context
        let var_rlwe = Variance(cks.parameters.glwe_modular_std_dev.get_variance());

        // Creation of the bootstrapping key in the Fourier domain
        let fourier_bsk: FourierLweBootstrapKey64 = self.engine.create_lwe_bootstrap_key(
            &cks.lwe_secret_key_after_ks,
            &cks.glwe_secret_key,
            cks.parameters.pbs_base_log,
            cks.parameters.pbs_level,
            var_rlwe,
        )?;

        // Convert into a variance for lwe context
        let var_lwe = Variance(cks.parameters.lwe_modular_std_dev.get_variance());

        // Creation of the key switching key
        let ksk = self.engine.create_lwe_keyswitch_key(
            &cks.lwe_secret_key,
            &cks.lwe_secret_key_after_ks,
            cks.parameters.ks_level,
            cks.parameters.ks_base_log,
            var_lwe,
        )?;

        // Pack the keys in the server key set:
        Ok(ServerKey {
            key_switching_key: ksk,
            bootstrapping_key: fourier_bsk,
            message_modulus: cks.parameters.message_modulus,
            carry_modulus: cks.parameters.carry_modulus,
            max_degree,
        })
    }

    pub(crate) fn generate_accumulator<F>(
        &mut self,
        server_key: &ServerKey,
        f: F,
    ) -> EngineResult<GlweCiphertext64>
    where
        F: Fn(u64) -> u64,
    {
        Self::generate_accumulator_with_engine(&mut self.engine, server_key, f)
    }

    pub(crate) fn keyswitch_bootstrap(
        &mut self,
        server_key: &ServerKey,
        ct: &Ciphertext,
    ) -> EngineResult<Ciphertext> {
        let mut ct_in = ct.clone();
        self.keyswitch_bootstrap_assign(server_key, &mut ct_in)?;
        Ok(ct_in)
    }

    pub(crate) fn keyswitch_bootstrap_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
    ) -> EngineResult<()> {
        // Compute the programmable bootstrapping with fixed test polynomial
        let (buffers, engine) = self.buffers_for_key(server_key);

        // Compute a keyswitch
        engine.discard_keyswitch_lwe_ciphertext(
            &mut buffers.buffer_lwe_after_ks,
            &ct.ct,
            &server_key.key_switching_key,
        )?;

        // Compute a bootstrap
        engine.discard_bootstrap_lwe_ciphertext(
            &mut ct.ct,
            &buffers.buffer_lwe_after_ks,
            &buffers.accumulator,
            &server_key.bootstrapping_key,
        )?;
        Ok(())
    }

    pub(crate) fn programmable_bootstrap_keyswitch(
        &mut self,
        server_key: &ServerKey,
        ct: &Ciphertext,
        acc: &GlweCiphertext64,
    ) -> EngineResult<Ciphertext> {
        let mut ct_res = ct.clone();
        self.programmable_bootstrap_keyswitch_assign(server_key, &mut ct_res, acc)?;
        Ok(ct_res)
    }

    pub(crate) fn programmable_bootstrap_keyswitch_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
        acc: &GlweCiphertext64,
    ) -> EngineResult<()> {
        // Compute the programmable bootstrapping with fixed test polynomial
        let (buffers, engine) = self.buffers_for_key(server_key);

        // Compute a key switch
        engine.discard_keyswitch_lwe_ciphertext(
            &mut buffers.buffer_lwe_after_ks,
            &ct.ct,
            &server_key.key_switching_key,
        )?;

        // Compute a bootstrap
        engine.discard_bootstrap_lwe_ciphertext(
            &mut ct.ct,
            &buffers.buffer_lwe_after_ks,
            acc,
            &server_key.bootstrapping_key,
        )?;
        Ok(())
    }

    pub(crate) fn unchecked_functional_bivariate_pbs<F>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        f: F,
    ) -> EngineResult<Ciphertext>
    where
        F: Fn(u64) -> u64,
    {
        let mut ct_res = ct_left.clone();
        self.unchecked_functional_bivariate_pbs_assign(server_key, &mut ct_res, ct_right, f)?;
        Ok(ct_res)
    }

    pub(crate) fn unchecked_functional_bivariate_pbs_assign<F>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        f: F,
    ) -> EngineResult<()>
    where
        F: Fn(u64) -> u64,
    {
        let modulus = (ct_right.degree.0 + 1) as u64;

        // Message 1 is shifted to the carry bits
        self.unchecked_scalar_mul_assign(ct_left, modulus as u8)?;

        // Message 2 is placed in the message bits
        self.unchecked_add_assign(ct_left, ct_right)?;

        // Generate the accumulator for the function
        let acc = self.generate_accumulator(server_key, f)?;

        // Compute the PBS
        self.programmable_bootstrap_keyswitch_assign(server_key, ct_left, &acc)?;
        Ok(())
    }

    pub(crate) fn carry_extract_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
    ) -> EngineResult<()> {
        let modulus = ct.message_modulus.0 as u64;

        let accumulator = self.generate_accumulator(server_key, |x| x / modulus)?;

        self.programmable_bootstrap_keyswitch_assign(server_key, ct, &accumulator)?;

        // The degree of the carry
        ct.degree = Degree(min(modulus - 1, ct.degree.0 as u64 / modulus) as usize);
        Ok(())
    }

    pub(crate) fn carry_extract(
        &mut self,
        server_key: &ServerKey,
        ct: &Ciphertext,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct.clone();
        self.carry_extract_assign(server_key, &mut result)?;
        Ok(result)
    }

    pub(crate) fn message_extract_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
    ) -> EngineResult<()> {
        let modulus = ct.message_modulus.0 as u64;

        let acc = self.generate_accumulator(server_key, |x| x % modulus)?;

        self.programmable_bootstrap_keyswitch_assign(server_key, ct, &acc)?;

        ct.degree = Degree(ct.message_modulus.0 - 1);
        Ok(())
    }

    pub(crate) fn message_extract(
        &mut self,
        server_key: &ServerKey,
        ct: &Ciphertext,
    ) -> EngineResult<Ciphertext> {
        let mut result = ct.clone();
        self.message_extract_assign(server_key, &mut result)?;
        Ok(result)
    }

    // Impossible to call the assign function in this case
    pub(crate) fn create_trivial(
        &mut self,
        server_key: &ServerKey,
        value: u8,
    ) -> EngineResult<Ciphertext> {
        let lwe_size = server_key
            .bootstrapping_key
            .output_lwe_dimension()
            .to_lwe_size();

        let modular_value = value as usize % server_key.message_modulus.0;

        let delta =
            (1_u64 << 63) / (server_key.message_modulus.0 * server_key.carry_modulus.0) as u64;

        let shifted_value = (modular_value as u64) * delta;

        let plaintext = self.engine.create_plaintext(&shifted_value).unwrap();

        let ct = self
            .engine
            .trivially_encrypt_lwe_ciphertext(lwe_size, &plaintext)
            .unwrap();

        let degree = Degree(modular_value);

        Ok(Ciphertext {
            ct,
            degree,
            message_modulus: server_key.message_modulus,
            carry_modulus: server_key.carry_modulus,
        })
    }

    pub(crate) fn create_trivial_assign(
        &mut self,
        server_key: &ServerKey,
        ct: &mut Ciphertext,
        value: u8,
    ) -> EngineResult<()> {
        let lwe_size = server_key
            .bootstrapping_key
            .input_lwe_dimension()
            .to_lwe_size();

        let modular_value = value as usize % server_key.message_modulus.0;

        let delta =
            (1_u64 << 63) / (server_key.message_modulus.0 * server_key.carry_modulus.0) as u64;

        let shifted_value = (modular_value as u64) * delta;

        let plaintext = self.engine.create_plaintext(&shifted_value).unwrap();

        ct.ct = self
            .engine
            .trivially_encrypt_lwe_ciphertext(lwe_size, &plaintext)
            .unwrap();
        ct.degree = Degree(modular_value);
        Ok(())
    }
}