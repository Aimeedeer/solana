use {
    borsh::{BorshDeserialize, BorshSerialize},
    solana_program_test::{processor, ProgramTest},
    solana_sdk::{
        account_info::{next_account_info, AccountInfo},
        entrypoint::ProgramResult,
        instruction::{AccountMeta, Instruction},
        msg,
        program::invoke_signed,
        pubkey::Pubkey,
        signature::Signer,
        system_instruction, system_program,
        transaction::Transaction,
    },
};

#[derive(BorshSerialize, BorshDeserialize, Debug)]
struct InstructionData {
    pub vault_bump_seed: u8,
    pub lamports: u64,
}

fn invoked_process_instruction_find_program_address(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Before processing!");
    let account_info_iter = &mut accounts.iter();
    let payer = next_account_info(account_info_iter)?;
    let vault = next_account_info(account_info_iter)?;
    let sys_program = next_account_info(account_info_iter)?;

    let mut instruction_data = instruction_data;
    let instr = InstructionData::deserialize(&mut instruction_data)?;
    let vault_bump_seed = instr.vault_bump_seed;
    let lamports = instr.lamports;

    msg!("Before invoke_signed");

    invoke_signed(
        &system_instruction::create_account(&payer.key, &vault.key, lamports, 0, &program_id),
        &[payer.clone(), vault.clone(), sys_program.clone()],
        &[&[b"vault", payer.key.as_ref(), &[vault_bump_seed]]],
    )?;

    msg!("Processed invoked instruction");
    Ok(())
}

pub fn vault_pda(program_id: &Pubkey, payer: &Pubkey) -> (Pubkey, u8) {
    let vault_seeds = &[b"vault", payer.as_ref()];
    let (vault, vault_bump_seed) = Pubkey::find_program_address(vault_seeds, program_id);

    (vault, vault_bump_seed)
}

#[tokio::test]
async fn invoke_program() {
    let invoked_program_id = Pubkey::new_unique();
    let program_test = ProgramTest::new(
        "invoked",
        invoked_program_id,
        processor!(invoked_process_instruction_find_program_address),
    );

    let mut context = program_test.start_with_context().await;
    let (vault_pubkey, vault_bump_seed) = vault_pda(&invoked_program_id, &context.payer.pubkey());

    let instruction_data = InstructionData {
        vault_bump_seed,
        lamports: 1000,
    };
    let mut instr_buffer: Vec<u8> = Vec::new();
    instruction_data.serialize(&mut instr_buffer).unwrap();

    let instructions = vec![Instruction::new_with_bytes(
        invoked_program_id,
        &instr_buffer,
        vec![
            AccountMeta::new(context.payer.pubkey().clone(), true),
            AccountMeta::new(vault_pubkey, false),
            AccountMeta::new(system_program::ID, false),
        ],
    )];

    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );

    context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap();
}
