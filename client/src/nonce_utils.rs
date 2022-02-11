use {
    crate::rpc_client::RpcClient,
    solana_sdk::{
        account::{Account, ReadableAccount},
        account_utils::StateMut,
        commitment_config::CommitmentConfig,
        hash::Hash,
        nonce::{
            state::{Data, Versions},
            State,
        },
        pubkey::Pubkey,
        system_program,
    },
};

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    #[error("invalid account owner")]
    InvalidAccountOwner,
    #[error("invalid account data")]
    InvalidAccountData,
    #[error("unexpected account data size")]
    UnexpectedDataSize,
    #[error("provided hash ({provided}) does not match nonce hash ({expected})")]
    InvalidHash { provided: Hash, expected: Hash },
    #[error("provided authority ({provided}) does not match nonce authority ({expected})")]
    InvalidAuthority { provided: Pubkey, expected: Pubkey },
    #[error("invalid state for requested operation")]
    InvalidStateForOperation,
    #[error("client error: {0}")]
    Client(String),
}

pub fn get_account(rpc_client: &RpcClient, nonce_pubkey: &Pubkey) -> Result<Account, Error> {
    get_account_with_commitment(rpc_client, nonce_pubkey, CommitmentConfig::default())
}

pub fn get_account_with_commitment(
    rpc_client: &RpcClient,
    nonce_pubkey: &Pubkey,
    commitment: CommitmentConfig,
) -> Result<Account, Error> {
    rpc_client
        .get_account_with_commitment(nonce_pubkey, commitment)
        .map_err(|e| Error::Client(format!("{}", e)))
        .and_then(|result| {
            result
                .value
                .ok_or_else(|| Error::Client(format!("AccountNotFound: pubkey={}", nonce_pubkey)))
        })
        .and_then(|a| account_identity_ok(&a).map(|()| a))
}

pub fn account_identity_ok<T: ReadableAccount>(account: &T) -> Result<(), Error> {
    if account.owner() != &system_program::id() {
        Err(Error::InvalidAccountOwner)
    } else if account.data().is_empty() {
        Err(Error::UnexpectedDataSize)
    } else {
        Ok(())
    }
}

pub fn state_from_account<T: ReadableAccount + StateMut<Versions>>(
    account: &T,
) -> Result<State, Error> {
    account_identity_ok(account)?;
    StateMut::<Versions>::state(account)
        .map_err(|_| Error::InvalidAccountData)
        .map(|v| v.convert_to_current())
}

/// # Examples
///
/// ```
/// use solana_client::{
///     rpc_client::RpcClient,
///     nonce_utils::data_from_account,
/// };
/// use solana_sdk::{
///     message::Message,
///     pubkey::Pubkey,
///     signature::Keypair,
///     signature::Signer,
///     system_instruction,
///     transaction::Transaction,
///     nonce::State,
/// #   account::Account,
/// #   nonce::state::Versions,
/// #   nonce::state::Data,
/// #   hash::Hash,
/// #   nonce_account,
/// #   account_utils::StateMut,
/// };
/// # use std::fs;
/// # use std::fs::File;
/// # use std::io::BufWriter;
/// use std::path::PathBuf;
/// use anyhow::Result;
/// # use anyhow::anyhow;
///
/// fn create_tx_with_nonce(
///     client: &RpcClient,
///     nonce_account_pubkey: &Pubkey,
///     payer: &Keypair,
///     receiver: &Pubkey,
///     amount: u64,
///     path: PathBuf,
/// ) -> Result<()> {
///
///     let instr = system_instruction::transfer(
///         &payer.pubkey(),
///         receiver,
///         amount,
///     );
///
///     let message = Message::new_with_nonce(
///         vec![instr],
///         Some(&payer.pubkey()),
///         nonce_account_pubkey,
///         &payer.pubkey(),
///     );
///
///     let mut tx = Transaction::new_unsigned(message);
///
///     // sign the tx with nonce_account's `blockhash` instead of the Solana network's `latest_blockhash`
///     let nonce_account = client.get_account(nonce_account_pubkey)?;
/// #   let mut nonce_account = nonce_account::create_account(1).into_inner();
/// #   let data = Data::new(Pubkey::new(&[1u8; 32]), Hash::new(&[42u8; 32]), 42);
/// #   nonce_account
/// #       .set_state(&Versions::new_current(State::Initialized(data.clone())))
/// #       .unwrap();
///     let nonce_data = data_from_account(&nonce_account)?;
///     let blockhash = nonce_data.blockhash;
///
///     tx.try_sign(&[payer], blockhash)?;
///
///     // save the signed tx locally
///     save_tx_to_file(&path, &tx)?;
/// #   fs::remove_file(&path)?;
///
///     Ok(())
/// }
/// #
/// # fn save_tx_to_file(path: &PathBuf, tx: &Transaction) -> Result<()> {
/// #    let file = File::create(&path)?;
/// #    let mut writer = BufWriter::new(file);
/// #
/// #    serde_json::to_writer(&mut writer, tx).map_err(|e| anyhow!("{}", e))
/// # }
/// #
/// # let client = RpcClient::new_mock("succeeds".to_string());
/// # let nonce_account_pubkey = Pubkey::new_unique();
/// # let payer = Keypair::new();
/// # let receiver = Pubkey::new_unique();
/// # create_tx_with_nonce(&client, &nonce_account_pubkey, &payer, &receiver, 1024, PathBuf::from("new_tx"))?;
/// #
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn data_from_account<T: ReadableAccount + StateMut<Versions>>(
    account: &T,
) -> Result<Data, Error> {
    account_identity_ok(account)?;
    state_from_account(account).and_then(|ref s| data_from_state(s).map(|d| d.clone()))
}

pub fn data_from_state(state: &State) -> Result<&Data, Error> {
    match state {
        State::Uninitialized => Err(Error::InvalidStateForOperation),
        State::Initialized(data) => Ok(data),
    }
}
