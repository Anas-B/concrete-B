//! The secret key of the client.
//!
//! This module implements the generation of the client' secret keys, together with the
//! encryption and decryption methods.

use crate::ciphertext::Ciphertext;
use crate::parameters::BooleanParameters;
use crate::{PLAINTEXT_FALSE, PLAINTEXT_TRUE};
use concrete_core::prelude::*;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::fmt::{Debug, Formatter};

thread_local! {
    static ENGINE: RefCell<CoreEngine> = RefCell::new(crate::default_engine());
}

/// A structure containing the client key, which must be kept secret.
///
/// In more details, it contains:
/// * `lwe_secret_key` - an LWE secret key, used to encrypt the inputs and decrypt the outputs.
/// This secret key is also used in the generation of bootstrapping and key switching keys.
/// * `glwe_secret_key` - a GLWE secret key, used to generate the bootstrapping keys and key
/// switching keys.
/// * `parameters` - the cryptographic parameter set.
#[derive(Serialize, Deserialize, Clone)]
pub struct ClientKey {
    pub(crate) lwe_secret_key: LweSecretKey32,
    pub(crate) glwe_secret_key: GlweSecretKey32,
    pub(crate) parameters: BooleanParameters,
}

impl PartialEq for ClientKey {
    fn eq(&self, other: &Self) -> bool {
        self.parameters == other.parameters
            && self.lwe_secret_key == other.lwe_secret_key
            && self.glwe_secret_key == other.glwe_secret_key
    }
}

impl Debug for ClientKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClientKey {{ ")?;
        write!(f, "lwe_secret_key: {:?}, ", self.lwe_secret_key)?;
        write!(f, "glwe_secret_key: {:?}, ", self.glwe_secret_key)?;
        write!(f, "parameters: {:?}, ", self.parameters)?;
        write!(f, "engine: CoreEngine, ")?;
        write!(f, "}}")?;
        Ok(())
    }
}

impl ClientKey {
    /// Encrypts a Boolean message using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_boolean::prelude::*;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, mut sks) = gen_keys();
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(true);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(true, dec);
    /// ```
    pub fn encrypt(&self, message: bool) -> Ciphertext {
        ENGINE.with(|engine_cell| {
            let engine = &mut engine_cell.borrow_mut();

            // encode the boolean message
            let plain: Plaintext32 = if message {
                engine.create_plaintext(&PLAINTEXT_TRUE).unwrap()
            } else {
                engine.create_plaintext(&PLAINTEXT_FALSE).unwrap()
            };

            // convert into a variance
            let var = Variance(self.parameters.lwe_modular_std_dev.get_variance());

            // encryption
            let ct = engine
                .encrypt_lwe_ciphertext(&self.lwe_secret_key, &plain, var)
                .unwrap();

            Ciphertext::Encrypted(ct)
        })
    }

    /// Decrypts a ciphertext encrypting a Boolean message using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_boolean::prelude::*;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, mut sks) = gen_keys();
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(true);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(true, dec);
    /// ```
    pub fn decrypt(&self, ct: &Ciphertext) -> bool {
        match ct {
            // in case of a trivial ciphertext (i.e. unencrypted)
            Ciphertext::Trivial(b) => *b,
            Ciphertext::Encrypted(ciphertext) => {
                ENGINE.with(|engine_cell| {
                    let engine = &mut engine_cell.borrow_mut();

                    // decryption
                    let decrypted = engine
                        .decrypt_lwe_ciphertext(&self.lwe_secret_key, ciphertext)
                        .unwrap();

                    // cast as a u32
                    let mut decrypted_u32: u32 = 0;
                    engine
                        .discard_retrieve_plaintext(&mut decrypted_u32, &decrypted)
                        .unwrap();

                    // return
                    decrypted_u32 < (1 << 31)
                })
            }
        }
    }

    /// Allocates and generates a client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_boolean::client_key::ClientKey;
    /// use concrete_boolean::parameters::DEFAULT_PARAMETERS;
    /// use concrete_boolean::prelude::*;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(DEFAULT_PARAMETERS);
    /// ```
    pub fn new(parameter_set: BooleanParameters) -> ClientKey {
        ENGINE.with(|engine_cell| {
            let engine = &mut engine_cell.borrow_mut();
            // generate the lwe secret key
            let lwe_secret_key: LweSecretKey32 = engine
                .create_lwe_secret_key(parameter_set.lwe_dimension)
                .unwrap();

            // generate the rlwe secret key
            let glwe_secret_key: GlweSecretKey32 = engine
                .create_glwe_secret_key(parameter_set.glwe_dimension, parameter_set.polynomial_size)
                .unwrap();

            // pack the keys in the client key set
            let cks: ClientKey = ClientKey {
                lwe_secret_key,
                glwe_secret_key,
                parameters: parameter_set,
            };
            cks
        })
    }
}
