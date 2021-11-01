use {
    solana_program_test::{processor, ProgramTest},
    solana_sdk::{
        account_info::{next_account_info, AccountInfo},
        entrypoint::ProgramResult,
        instruction::{AccountMeta, Instruction},
        msg,
        pubkey::Pubkey,
        signature::Signer,
        transaction::Transaction,
        program::invoke_signed,
        system_instruction,
    },
};
    
// Process instruction to invoke into another program
fn invoker_process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _input: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let payer = next_account_info(account_info_iter)?;
    let vault = next_account_info(account_info_iter)?;

    let lamports = 1000;
    invoke_signed(
        &system_instruction::create_account(
            &payer.key,
            &vault.key,
            lamports,
            0,
            &_program_id,
        ),
        &[
            payer.clone(),
            vault.clone(),
        ],
        &[
            &[
                b"vault",
                payer.key.as_ref(),
            ],
        ]
    )?;
    
    Ok(())
}

// Process instruction to be invoked by another program
#[allow(clippy::unnecessary_wraps)]
fn invoked_process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    _input: &[u8],
) -> ProgramResult {
    // if we can call `msg!` successfully, then InvokeContext exists as required
    msg!("Processing invoked instruction");
    Ok(())
}

#[tokio::test]
async fn cpi() {
    let invoker_program_id = Pubkey::new_unique();
    let mut program_test = ProgramTest::new(
        "invoker",
        invoker_program_id,
        processor!(invoker_process_instruction),
    );
    let invoked_program_id = Pubkey::new_unique();
    program_test.add_program(
        "invoked",
        invoked_program_id,
        processor!(invoked_process_instruction),
    );

    let mut context = program_test.start_with_context().await;
    let instructions = vec![Instruction::new_with_bincode(
        invoker_program_id,
        &[0],
        vec![AccountMeta::new_readonly(invoked_program_id, false)],
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
