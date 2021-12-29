use crate::{
    account_info::AccountInfo, entrypoint::ProgramResult, instruction::Instruction, pubkey::Pubkey,
};

/// Invoke a cross-program instruction.
///
/// Notes:
/// - RefCell checking can be compute unit expensive, to avoid that expense use
///   `invoke_unchecked` instead, but at your own risk.
///
/// # Examples
///
/// ```
/// # use solana_program::{
/// #     pubkey::Pubkey,
/// #     entrypoint::ProgramResult,
/// #     account_info::{
/// #         AccountInfo,
/// #         next_account_info,
/// #     },
/// #     program::invoke,
/// # };
/// # use borsh::{BorshSerialize, BorshDeserialize};
/// #[derive(Debug, BorshSerialize, BorshDeserialize)]
/// pub enum MyInstruction {
///     DepositSol { lamports: u64 },
///     // other fields ...
/// }
///
/// // The entrypoint of the on-chain program, as provided to the
/// // `entrypoint!` macro.
/// fn process_instruction(
///     program_id: &Pubkey,
///     accounts: &[AccountInfo],
///     instruction: &[u8],
/// ) -> ProgramResult {
///     let mut instruction = instruction;
///     let instr = MyInstruction::deserialize(&mut instruction)?;
///
///     match instr {
///         MyInstruction::DepositSol { lamports } => {
///             let account_info_iter = &mut accounts.iter();
///             let tx_from = next_account_info(account_info_iter)?;
///             let tx_destination = next_account_info(account_info_iter)?;
///             let system_program = next_account_info(account_info_iter)?;
///
///             // do security check ...
///
///             invoke(
///                 &solana_program::system_instruction::transfer(
///                     tx_from.key,
///                     tx_destination.key,
///                     lamports,
///                 ),
///                 &[
///                     tx_from.clone(),
///                     tx_destination.clone(),
///                     system_program.clone(),
///                 ],
///             )
///         }
///         // other instruction options ...
///     }
/// }
/// ```
pub fn invoke(instruction: &Instruction, account_infos: &[AccountInfo]) -> ProgramResult {
    invoke_signed(instruction, account_infos, &[])
}

/// Invoke a cross-program instruction but don't enforce RefCell handling.
///
/// Notes:
/// - The missing checks ensured that the invocation doesn't violate the borrow
///   rules of the `AccountInfo` fields that are wrapped in `RefCell`s.  To
///   include the checks call `invoke` instead.
pub fn invoke_unchecked(instruction: &Instruction, account_infos: &[AccountInfo]) -> ProgramResult {
    invoke_signed_unchecked(instruction, account_infos, &[])
}

/// Invoke a cross-program instruction with program signatures
///
/// Notes:
/// - RefCell checking can be compute unit expensive, to avoid that expense use
///   `invoke_signed_unchecked` instead, but at your own risk.
///
/// # Examples
///
/// ```
/// # use solana_program::{
/// #     pubkey::Pubkey,
/// #     account_info::{
/// #         AccountInfo,
/// #         next_account_info,
/// #     },
/// #     system_instruction,
/// #     entrypoint::ProgramResult,
/// #     program::invoke_signed,
/// # };
/// # use borsh::{BorshSerialize, BorshDeserialize};
/// #[derive(BorshSerialize, BorshDeserialize, Debug)]
/// pub struct InstructionData {
///     pub vault_bump_seed: u8,
///     pub lamports: u64,
/// }
///
/// # pub static VAULT_ACCOUNT_SIZE: u64 = 1024;
/// // The entrypoint of the on-chain program, as provided to the
/// // `entrypoint!` macro.
/// fn process_instruction(
///     program_id: &Pubkey,
///     accounts: &[AccountInfo],
///     instruction_data: &[u8],
/// ) -> ProgramResult {
///     let account_info_iter = &mut accounts.iter();
///     let payer = next_account_info(account_info_iter)?;
///     // The vault PDA, derived from the payer's address
///     let vault = next_account_info(account_info_iter)?;
///
///     let mut instruction_data = instruction_data;
///     let instr = InstructionData::deserialize(&mut instruction_data)?;
///     let vault_bump_seed = instr.vault_bump_seed;
///     let lamports = instr.lamports;
///     let vault_size = VAULT_ACCOUNT_SIZE;
///
///     // do security check ...
///
///     // Invoke the system program to create an account while virtually
///     // signing with the vault PDA, which is owned by this caller program.
///     invoke_signed(
///         &system_instruction::create_account(
///             &payer.key,
///             &vault.key,
///             lamports,
///             vault_size,
///             &program_id,
///         ),
///         &[
///             payer.clone(),
///             vault.clone(),
///         ],
///         // A slice of seed slices, each seed slice being the set
///         // of seeds used to generate one of the PDAs required by the
///         // callee program, the final seed being a single-element slice
///         // containing the `u8` bump seed.
///         &[
///             &[
///                 b"vault",
///                 payer.key.as_ref(),
///                 &[vault_bump_seed],
///             ],
///         ]
///     )?;
///
///     Ok(())
/// }
/// ```
pub fn invoke_signed(
    instruction: &Instruction,
    account_infos: &[AccountInfo],
    signers_seeds: &[&[&[u8]]],
) -> ProgramResult {
    // Check that the account RefCells are consistent with the request
    for account_meta in instruction.accounts.iter() {
        for account_info in account_infos.iter() {
            if account_meta.pubkey == *account_info.key {
                if account_meta.is_writable {
                    let _ = account_info.try_borrow_mut_lamports()?;
                    let _ = account_info.try_borrow_mut_data()?;
                } else {
                    let _ = account_info.try_borrow_lamports()?;
                    let _ = account_info.try_borrow_data()?;
                }
                break;
            }
        }
    }

    invoke_signed_unchecked(instruction, account_infos, signers_seeds)
}

/// Invoke a cross-program instruction with program signatures but don't check
/// RefCell handling.
///
/// Note:
/// - The missing checks ensured that the invocation doesn't violate the borrow
///   rules of the `AccountInfo` fields that are wrapped in `RefCell`s.  To
///   include the checks call `invoke_signed` instead.
pub fn invoke_signed_unchecked(
    instruction: &Instruction,
    account_infos: &[AccountInfo],
    signers_seeds: &[&[&[u8]]],
) -> ProgramResult {
    #[cfg(target_arch = "bpf")]
    {
        extern "C" {
            fn sol_invoke_signed_rust(
                instruction_addr: *const u8,
                account_infos_addr: *const u8,
                account_infos_len: u64,
                signers_seeds_addr: *const u8,
                signers_seeds_len: u64,
            ) -> u64;
        }

        let result = unsafe {
            sol_invoke_signed_rust(
                instruction as *const _ as *const u8,
                account_infos as *const _ as *const u8,
                account_infos.len() as u64,
                signers_seeds as *const _ as *const u8,
                signers_seeds.len() as u64,
            )
        };
        match result {
            crate::entrypoint::SUCCESS => Ok(()),
            _ => Err(result.into()),
        }
    }

    #[cfg(not(target_arch = "bpf"))]
    crate::program_stubs::sol_invoke_signed(instruction, account_infos, signers_seeds)
}

/// Maximum size that can be set using sol_set_return_data()
pub const MAX_RETURN_DATA: usize = 1024;

/// Set a program's return data
pub fn set_return_data(data: &[u8]) {
    #[cfg(target_arch = "bpf")]
    {
        extern "C" {
            fn sol_set_return_data(data: *const u8, length: u64);
        }

        unsafe { sol_set_return_data(data.as_ptr(), data.len() as u64) };
    }

    #[cfg(not(target_arch = "bpf"))]
    crate::program_stubs::sol_set_return_data(data)
}

/// Get the return data from invoked program
pub fn get_return_data() -> Option<(Pubkey, Vec<u8>)> {
    #[cfg(target_arch = "bpf")]
    {
        use std::cmp::min;

        extern "C" {
            fn sol_get_return_data(data: *mut u8, length: u64, program_id: *mut Pubkey) -> u64;
        }

        let mut buf = [0u8; MAX_RETURN_DATA];
        let mut program_id = Pubkey::default();

        let size =
            unsafe { sol_get_return_data(buf.as_mut_ptr(), buf.len() as u64, &mut program_id) };

        if size == 0 {
            None
        } else {
            let size = min(size as usize, MAX_RETURN_DATA);
            Some((program_id, buf[..size as usize].to_vec()))
        }
    }

    #[cfg(not(target_arch = "bpf"))]
    crate::program_stubs::sol_get_return_data()
}
