//! Mock types for use in examples.
//!
//! These represent APIs from crates that themselves depend on this crate, and
//! which are useful for illustrating the examples for APIs in this crate.
//!
//! Directly depending on these crates though would cause problematic circular
//! dependencies, so instead they are mocked out here in a way that allows
//! examples to appear to use crates that this crate must not depend on.
//!
//! Each mod here has the name of a crate, so that examples can be structured to
//! appear to import from that crate.

#![doc(hidden)]
#![allow(clippy::new_without_default)]
pub mod solana_client {
    pub mod nonce_utils {
        use super::super::solana_sdk::{
            account::ReadableAccount, account_utils::StateMut, hash::Hash, pubkey::Pubkey,
        };
        use crate::nonce::state::{Data, Versions};
        use core::fmt::Formatter;

        pub enum Error {}

        impl core::fmt::Display for Error {
            fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}", self)
            }
        }

        impl core::fmt::Debug for Error {
            fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
                f.debug_tuple("").field(self).finish()
            }
        }

        impl std::error::Error for Error {}

        pub fn data_from_account<T: ReadableAccount + StateMut<Versions>>(
            _account: &T,
        ) -> Result<Data, Error> {
            Ok(Data::new(Pubkey::new_unique(), Hash::default(), 5000))
        }
    }

    pub mod client_error {
        use thiserror::Error;

        #[derive(Error, Debug)]
        #[error("mock-error")]
        pub struct ClientError;
        pub type Result<T> = std::result::Result<T, ClientError>;
    }

    pub mod rpc_client {
        use super::super::solana_sdk::{
            account::Account, hash::Hash, pubkey::Pubkey, signature::Signature,
            transaction::Transaction,
        };
        use super::client_error::ClientError;
        use super::client_error::Result as ClientResult;

        pub struct RpcClient;

        impl RpcClient {
            pub fn new(_url: String) -> Self {
                RpcClient
            }

            pub fn get_latest_blockhash(&self) -> ClientResult<Hash> {
                Ok(Hash::default())
            }

            pub fn send_and_confirm_transaction(
                &self,
                _transaction: &Transaction,
            ) -> ClientResult<Signature> {
                Ok(Signature::default())
            }

            pub fn get_minimum_balance_for_rent_exemption(
                &self,
                _data_len: usize,
            ) -> ClientResult<u64> {
                Ok(0)
            }

            pub fn get_account(&self, _pubkey: &Pubkey) -> Result<Account, ClientError> {
                Ok(Account {})
            }
        }
    }
}

/// Re-exports and mocks of solana-program modules that mirror those from
/// solana-program.
///
/// This lets examples in solana-program appear to be written as client
/// programs.
pub mod solana_sdk {
    pub use crate::hash;
    pub use crate::instruction;
    pub use crate::message;
    pub use crate::nonce;
    pub use crate::pubkey::{self, Pubkey};
    pub use crate::system_instruction;

    pub mod account {
        pub struct Account;

        pub trait ReadableAccount: Sized {
            fn data(&self) -> &[u8];
        }

        impl ReadableAccount for Account {
            fn data(&self) -> &[u8] {
                &[0]
            }
        }
    }

    pub mod account_utils {
        use super::account::Account;

        pub trait StateMut<T> {}

        impl<T> StateMut<T> for Account {}
    }

    pub mod signature {
        use crate::pubkey::Pubkey;

        #[derive(Default)]
        pub struct Signature;

        pub struct Keypair;

        impl Keypair {
            pub fn new() -> Keypair {
                Keypair
            }

            pub fn pubkey(&self) -> Pubkey {
                Pubkey::default()
            }
        }

        impl Signer for Keypair {}

        pub trait Signer {}
    }

    pub mod signers {
        use super::signature::Signer;
        use core::fmt::Debug;
        use thiserror::Error;

        #[derive(Debug, Error, PartialEq)]
        pub enum SignerError {}

        pub trait Signers {}

        impl<T: Signer> Signers for [&T; 1] {}
        impl<T: Signer> Signers for [&T; 2] {}
    }

    pub mod transaction {
        use super::signers::{SignerError, Signers};
        use crate::hash::Hash;
        use crate::instruction::Instruction;
        use crate::message::Message;
        use crate::pubkey::Pubkey;
        use serde::Serialize;

        #[derive(Serialize)]
        pub struct Transaction {
            pub message: Message,
        }

        impl Transaction {
            pub fn new<T: Signers>(
                _from_keypairs: &T,
                _message: Message,
                _recent_blockhash: Hash,
            ) -> Transaction {
                Transaction {
                    message: Message::new(&[], None),
                }
            }

            pub fn new_unsigned(_message: Message) -> Self {
                Transaction {
                    message: Message::new(&[], None),
                }
            }

            pub fn new_with_payer(_instructions: &[Instruction], _payer: Option<&Pubkey>) -> Self {
                Transaction {
                    message: Message::new(&[], None),
                }
            }

            pub fn sign<T: Signers>(&mut self, _keypairs: &T, _recent_blockhash: Hash) {}

            pub fn try_sign<T: Signers>(
                &mut self,
                _keypairs: &T,
                _recent_blockhash: Hash,
            ) -> Result<(), SignerError> {
                Ok(())
            }
        }
    }
}
