//! This account contains the current cluster rent
//!
//! # Examples
//!
//! Calling via on-chain program directly:
//!
//! ```no_run
//! # use solana_program::{
//! #    account_info::{AccountInfo, next_account_info},
//! #    entrypoint::ProgramResult,
//! #    msg,
//! #    pubkey::Pubkey,
//! #    sysvar::rent::{self, Rent},
//! #    sysvar::Sysvar,
//! # };
//! # use solana_program::program_error::ProgramError;
//! #
//! fn process_instruction(
//!     program_id: &Pubkey,
//!     accounts: &[AccountInfo],
//!     instruction_data: &[u8],
//! ) -> ProgramResult {
//!     // do stuff ...
//!
//!     let rent = Rent::get()?;
//!     msg!("rent: {:#?}", rent);
//!
//!     // do stuff ...
//!
//!     Ok(())
//! }
//! #
//! # use solana_program::sysvar::SysvarId;
//! # let p = Rent::id();
//! # let l = &mut 1009200;
//! # let d = &mut vec![152, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 100];
//! # let a = AccountInfo::new(&p, false, false, l, d, &p, false, 0);
//! # let accounts = &[a.clone(), a];
//! # process_instruction(
//! #     &Pubkey::new_unique(),
//! #     accounts,
//! #     &[],
//! # )?;
//! # Ok::<(), ProgramError>(())
//! ```
//!
//! Calling via on-chain program's parameters:
//!
//! ```
//! # use solana_program::{
//! #    account_info::{AccountInfo, next_account_info},
//! #    entrypoint::ProgramResult,
//! #    msg,
//! #    pubkey::Pubkey,
//! #    sysvar::rent::{self, Rent},
//! #    sysvar::Sysvar,
//! # };
//! # use solana_program::program_error::ProgramError;
//! #
//! fn process_instruction(
//!     program_id: &Pubkey,
//!     accounts: &[AccountInfo],
//!     instruction_data: &[u8],
//! ) -> ProgramResult {
//!     let account_info_iter = &mut accounts.iter();
//!     let rent_account_info = next_account_info(account_info_iter)?;
//!
//!     assert!(rent::check_id(rent_account_info.key));
//!
//!     let rent = Rent::from_account_info(rent_account_info)?;
//!     msg!("rent: {:#?}", rent);
//!
//!     // other account_info ...
//!
//!     Ok(())
//! }
//! #
//! # use solana_program::sysvar::SysvarId;
//! # let p = Rent::id();
//! # let l = &mut 1009200;
//! # let d = &mut vec![152, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 100];
//! # let a = AccountInfo::new(&p, false, false, l, d, &p, false, 0);
//! # let accounts = &[a.clone(), a];
//! # process_instruction(
//! #     &Pubkey::new_unique(),
//! #     accounts,
//! #     &[],
//! # )?;
//! # Ok::<(), ProgramError>(())
//! ```
//!
//! Calling via the RPC client:
//!
//! ```
//! # use solana_program::example_mocks::solana_sdk;
//! # use solana_program::example_mocks::solana_client;
//! # use solana_sdk::account::Account;
//! # use solana_client::rpc_client::RpcClient;
//! # use solana_sdk::sysvar::rent::{self, Rent};
//! # use anyhow::Result;
//! #
//! fn print_sysvar_rent(client: &RpcClient) -> Result<()> {
//! #   client.set_get_account_response(rent::ID, Account {
//! #       lamports: 1009200,
//! #       data: vec![152, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 100],
//! #       owner: solana_sdk::system_program::ID,
//! #       executable: false,
//! #       rent_epoch: 307,
//! # });
//! #
//!     let rent = client.get_account(&rent::ID)?;
//!     let data: Rent = bincode::deserialize(&rent.data)?;
//!     println!("rent account data: {:#?}", data);
//!
//!     Ok(())
//! }
//! #
//! # let client = RpcClient::new(String::new());
//! # print_sysvar_rent(&client)?;
//! #
//! # Ok::<(), anyhow::Error>(())
//! ```
pub use crate::rent::Rent;
use crate::{impl_sysvar_get, program_error::ProgramError, sysvar::Sysvar};

crate::declare_sysvar_id!("SysvarRent111111111111111111111111111111111", Rent);

impl Sysvar for Rent {
    impl_sysvar_get!(sol_get_rent_sysvar);
}
