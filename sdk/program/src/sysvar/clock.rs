//! This account contains the clock slot, epoch, and leader_schedule_epoch
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
//! #    sysvar::clock::{self, Clock},
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
//!     let clock = Clock::get()?;
//!     msg!("clock: {:#?}", clock);
//!
//!     // do stuff ...
//!
//!     Ok(())
//! }
//! #
//! # use solana_program::sysvar::SysvarId;
//! # let p = Clock::id();
//! # let l = &mut 1169280;
//! # let d = &mut vec![240, 153, 233, 7, 0, 0, 0, 0, 11, 115, 118, 98, 0, 0, 0, 0, 51, 1, 0, 0, 0, 0, 0, 0, 52, 1, 0, 0, 0, 0, 0, 0, 121, 50, 119, 98, 0, 0, 0, 0];
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
//! #    sysvar::clock::{self, Clock},
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
//!     let clock_account_info = next_account_info(account_info_iter)?;
//!
//!     assert!(clock::check_id(clock_account_info.key));
//!
//!     let clock = Clock::from_account_info(clock_account_info)?;
//!     msg!("clock: {:#?}", clock);
//!
//!     // other account_info ...
//!
//!     Ok(())
//! }
//! #
//! # use solana_program::sysvar::SysvarId;
//! # let p = Clock::id();
//! # let l = &mut 1169280;
//! # let d = &mut vec![240, 153, 233, 7, 0, 0, 0, 0, 11, 115, 118, 98, 0, 0, 0, 0, 51, 1, 0, 0, 0, 0, 0, 0, 52, 1, 0, 0, 0, 0, 0, 0, 121, 50, 119, 98, 0, 0, 0, 0];
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
//! # use solana_sdk::sysvar::clock::{self, Clock};
//! # use anyhow::Result;
//! #
//! fn print_sysvar_clock(client: &RpcClient) -> Result<()> {
//! #   client.set_get_account_response(clock::ID, Account {
//! #       lamports: 1169280,
//! #       data: vec![240, 153, 233, 7, 0, 0, 0, 0, 11, 115, 118, 98, 0, 0, 0, 0, 51, 1, 0, 0, 0, 0, 0, 0, 52, 1, 0, 0, 0, 0, 0, 0, 121, 50, 119, 98, 0, 0, 0, 0],
//! #       owner: solana_sdk::system_program::ID,
//! #       executable: false,
//! #       rent_epoch: 307,
//! # });
//! #
//!     let clock = client.get_account(&clock::ID)?;
//!     let data: Clock = bincode::deserialize(&clock.data)?;
//!     println!("clock account data: {:#?}", data);
//!
//!     Ok(())
//! }
//! #
//! # let client = RpcClient::new(String::new());
//! # print_sysvar_clock(&client)?;
//! #
//! # Ok::<(), anyhow::Error>(())
//! ```
pub use crate::clock::Clock;
use crate::{impl_sysvar_get, program_error::ProgramError, sysvar::Sysvar};

crate::declare_sysvar_id!("SysvarC1ock11111111111111111111111111111111", Clock);

impl Sysvar for Clock {
    impl_sysvar_get!(sol_get_clock_sysvar);
}
