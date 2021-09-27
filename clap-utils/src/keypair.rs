use {
    crate::{
        input_parsers::{pubkeys_sigs_of, STDOUT_OUTFILE_TOKEN},
        offline::{SIGNER_ARG, SIGN_ONLY_ARG},
        ArgConstant,
    },
    bip39::{Language, Mnemonic, Seed},
    clap::ArgMatches,
    rpassword::prompt_password_stderr,
    solana_remote_wallet::{
        locator::{Locator as RemoteWalletLocator, LocatorError as RemoteWalletLocatorError},
        remote_keypair::generate_remote_keypair,
        remote_wallet::{maybe_wallet_manager, RemoteWalletError, RemoteWalletManager},
    },
    solana_sdk::{
        derivation_path::{DerivationPath, DerivationPathError},
        hash::Hash,
        message::Message,
        pubkey::Pubkey,
        signature::{
            generate_seed_from_seed_phrase_and_passphrase, keypair_from_seed,
            keypair_from_seed_and_derivation_path, keypair_from_seed_phrase_and_passphrase,
            read_keypair, read_keypair_file, Keypair, NullSigner, Presigner, Signature, Signer,
        },
    },
    std::{
        cell::RefCell,
        convert::TryFrom,
        error,
        io::{stdin, stdout, Write},
        ops::Deref,
        process::exit,
        str::FromStr,
        sync::Arc,
    },
    thiserror::Error,
};

pub struct SignOnly {
    pub blockhash: Hash,
    pub message: Option<String>,
    pub present_signers: Vec<(Pubkey, Signature)>,
    pub absent_signers: Vec<Pubkey>,
    pub bad_signers: Vec<Pubkey>,
}

impl SignOnly {
    // todo: need data for constructing `SignOnly`
    // or there is a method
    // `let sign_only = parse_sign_only_reply_string(&res);`
    // in the cli_output.rs file
    /// # Examples
    ///
    /// ```
    /// # use solana_clap_utils::keypair::SignOnly;
    /// # use solana_sdk::hash::Hash;
    /// let sign_only = SignOnly {
    ///     blockhash: Hash::default(),
    ///     message: Some(String::from("Test Message")),
    ///     present_signers: vec![],
    ///     absent_signers: vec![],
    ///     bad_signers: vec![],
    /// };
    /// let has_signers = sign_only.has_all_signers();
    /// assert!(has_signers);
    /// ```
    pub fn has_all_signers(&self) -> bool {
        self.absent_signers.is_empty() && self.bad_signers.is_empty()
    }

    // todo: need data for constructing `SignOnly`
    /// # Examples
    ///
    /// ```
    /// # use solana_clap_utils::keypair::SignOnly;
    /// # use solana_sdk::hash::Hash;
    /// # use solana_sdk::signature::{Signer, Keypair};
    /// # let pubkey = Keypair::new().pubkey();
    /// let sign_only = SignOnly {
    ///     blockhash: Hash::default(),
    ///     message: Some(String::from("Test Message")),
    ///     present_signers: vec![],
    ///     absent_signers: vec![],
    ///     bad_signers: vec![],
    /// };
    /// let presigner = sign_only.presigner_of(&pubkey).ok_or(format!("Error when get presigner of pubkey {}", pubkey));
    /// ```
    pub fn presigner_of(&self, pubkey: &Pubkey) -> Option<Presigner> {
        presigner_from_pubkey_sigs(pubkey, &self.present_signers)
    }
}
pub type CliSigners = Vec<Box<dyn Signer>>;
pub type SignerIndex = usize;
pub struct CliSignerInfo {
    pub signers: CliSigners,
}

impl CliSignerInfo {
    /// # Examples
    ///
    /// ```
    /// # use solana_clap_utils::keypair::{CliSigners, CliSignerInfo};
    /// # use solana_sdk::signer::keypair::keypair_from_seed;
    /// # use solana_sdk::signature::Signer;
    /// # let keypair = keypair_from_seed(&[0u8; 32]).unwrap();
    /// let pubkey = keypair.pubkey();
    /// let signers: CliSigners = vec![Box::new(keypair)];
    /// let signer_info = CliSignerInfo { signers };
    /// let index = signer_info.index_of(Some(pubkey));
    /// # assert!(index.is_some());
    /// # let index = signer_info.index_of(None);
    /// # assert_eq!(index, Some(0));
    /// ```
    pub fn index_of(&self, pubkey: Option<Pubkey>) -> Option<usize> {
        if let Some(pubkey) = pubkey {
            self.signers
                .iter()
                .position(|signer| signer.pubkey() == pubkey)
        } else {
            Some(0)
        }
    }

    /// # Examples
    ///
    /// ```
    /// # use solana_clap_utils::keypair::{CliSigners, CliSignerInfo};
    /// # use solana_sdk::signer::keypair::keypair_from_seed;
    /// # use solana_sdk::signature::Signer;
    /// # let keypair = keypair_from_seed(&[0u8; 32]).unwrap();
    /// let pubkey = keypair.pubkey();
    /// let signers: CliSigners = vec![Box::new(keypair)];
    /// let signer_info = CliSignerInfo { signers };
    /// let index = signer_info.index_of_or_none(Some(pubkey));
    /// # assert!(index.is_some());
    /// # let index = signer_info.index_of_or_none(None);
    /// # assert_eq!(index, None);
    /// ```
    pub fn index_of_or_none(&self, pubkey: Option<Pubkey>) -> Option<usize> {
        if let Some(pubkey) = pubkey {
            self.signers
                .iter()
                .position(|signer| signer.pubkey() == pubkey)
        } else {
            None
        }
    }

    /// # Examples
    ///
    /// ```
    /// # use solana_clap_utils::keypair::{CliSigners, CliSignerInfo};
    /// # use solana_sdk::signer::keypair::keypair_from_seed;
    /// # use solana_sdk::signature::Signer;
    /// # use solana_sdk::pubkey::Pubkey;
    /// # use solana_sdk::message::Message;
    /// # use solana_sdk::instruction::{Instruction, AccountMeta};
    /// # let keypair = keypair_from_seed(&[0u8; 32]).unwrap();
    /// # let signers: CliSigners = vec![Box::new(keypair)];
    /// # let signer_info = CliSignerInfo { signers };
    /// # // Construct a message as the parameter
    /// # let program_id0 = Pubkey::new_unique();
    /// # let program_id1 = Pubkey::new_unique();
    /// # let id0 = Pubkey::default();
    /// # let id1 = Pubkey::new_unique();
    /// # let message = Message::new(
    /// #     &[
    /// #         Instruction::new_with_bincode(program_id0, &0, vec![AccountMeta::new(id0, false)]),
    /// #         Instruction::new_with_bincode(program_id1, &0, vec![AccountMeta::new(id1, true)]),
    /// #         Instruction::new_with_bincode(program_id0, &0, vec![AccountMeta::new(id1, false)]),
    /// #     ],
    /// #     Some(&id1),
    /// # );
    /// let signers_for_msg = signer_info.signers_for_message(&message);
    /// # assert_eq!(signers_for_msg.len(), 0);
    /// ```
    pub fn signers_for_message(&self, message: &Message) -> Vec<&dyn Signer> {
        self.signers
            .iter()
            .filter_map(|k| {
                if message.signer_keys().contains(&&k.pubkey()) {
                    Some(k.as_ref())
                } else {
                    None
                }
            })
            .collect()
    }
}

#[derive(Debug, Default)]
pub struct DefaultSigner {
    pub arg_name: String,
    pub path: String,
    is_path_checked: RefCell<bool>,
}

impl DefaultSigner {
    /// # Examples
    ///
    /// ```
    /// # use solana_sdk::signature::{Signer, Keypair};
    /// # use solana_clap_utils::keypair::DefaultSigner;
    /// # use solana_sdk::signer::keypair::write_keypair_file;
    /// # use tempfile::TempDir;
    /// # let dir = TempDir::new()?;
    /// # let dir = dir.path();
    /// let keypair_path = dir.join("payer-keypair-file");
    /// let keypair_path_str = keypair_path.to_str().expect("uft-8");
    /// # let keypair = Keypair::new();
    /// write_keypair_file(&keypair, &keypair_path)?;
    ///
    /// let signer = DefaultSigner::new("keypair", &keypair_path_str);
    /// # assert!(signer.arg_name.len() > 0);
    /// assert_eq!(signer.path, keypair_path_str);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new<AN: AsRef<str>, P: AsRef<str>>(arg_name: AN, path: P) -> Self {
        let arg_name = arg_name.as_ref().to_string();
        let path = path.as_ref().to_string();
        Self {
            arg_name,
            path,
            ..Self::default()
        }
    }

    fn path(&self) -> Result<&str, Box<dyn std::error::Error>> {
        if !self.is_path_checked.borrow().deref() {
            parse_signer_source(&self.path)
                .and_then(|s| {
                    if let SignerSourceKind::Filepath(path) = &s.kind {
                        std::fs::metadata(path).map(|_| ()).map_err(|e| e.into())
                    } else {
                        Ok(())
                    }
                })
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                        "No default signer found, run \"solana-keygen new -o {}\" to create a new one",
                        self.path
                    ),
                    )
                })?;
            *self.is_path_checked.borrow_mut() = true;
        }
        Ok(&self.path)
    }

    /// # Examples
    ///
    /// ```
    /// # use solana_remote_wallet::remote_wallet::initialize_wallet_manager;
    /// # use solana_sdk::signature::Keypair;
    /// # use solana_sdk::signer::{keypair::write_keypair_file, Signer};
    /// # use solana_clap_utils::keypair::DefaultSigner;
    /// # use clap::{App, Arg};
    /// # use tempfile::TempDir;;
    /// # let dir = TempDir::new()?;
    /// # let dir = dir.path();
    /// # let keypair_path = dir.join("payer-keypair-file");
    /// # let keypair_path_str = keypair_path.to_str().expect("uft-8");
    /// # let keypair = Keypair::new();
    /// # write_keypair_file(&keypair, &keypair_path)?;
    /// # let signer = DefaultSigner::new("keypair", &keypair_path_str);
    /// let args = vec![
    ///     "program",
    ///     keypair_path_str,
    /// ];
    ///
    /// let clap_app = App::new("my-program")
    ///     .arg(
    ///         Arg::with_name("keypair")
    ///             .required(true)
    ///             .help("The signing keypair")
    /// );
    ///
    /// let clap_matches = clap_app.get_matches_from(args);
    /// let bulk_signers = vec![Some(Box::new(keypair) as Box<dyn Signer>)];
    /// let wallet_manager = initialize_wallet_manager()?;
    ///
    /// let unique_signers = signer.generate_unique_signers(
    ///     bulk_signers,
    ///     &clap_matches,
    ///     &mut Some(wallet_manager),
    /// )?;
    /// assert!(unique_signers.signers.len() == 1);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate_unique_signers(
        &self,
        bulk_signers: Vec<Option<Box<dyn Signer>>>,
        matches: &ArgMatches<'_>,
        wallet_manager: &mut Option<Arc<RemoteWalletManager>>,
    ) -> Result<CliSignerInfo, Box<dyn error::Error>> {
        let mut unique_signers = vec![];

        // Determine if the default signer is needed
        if bulk_signers.iter().any(|signer| signer.is_none()) {
            let default_signer = self.signer_from_path(matches, wallet_manager)?;
            unique_signers.push(default_signer);
        }

        for signer in bulk_signers.into_iter().flatten() {
            if !unique_signers.iter().any(|s| s == &signer) {
                unique_signers.push(signer);
            }
        }
        Ok(CliSignerInfo {
            signers: unique_signers,
        })
    }

    /// # Examples
    ///
    /// ```
    /// # use solana_remote_wallet::remote_wallet::initialize_wallet_manager;
    /// # use solana_sdk::signature::Keypair;
    /// # use solana_sdk::signer::keypair::write_keypair_file;
    /// # use solana_clap_utils::keypair::DefaultSigner;
    /// # use clap::{App, Arg};
    /// # use tempfile::TempDir;;
    /// # let dir = TempDir::new()?;
    /// # let dir = dir.path();
    /// # let keypair_path = dir.join("payer-keypair-file");
    /// # let keypair_path_str = keypair_path.to_str().expect("uft-8");
    /// # let keypair = Keypair::new();
    /// # write_keypair_file(&keypair, &keypair_path)?;
    /// # let signer = DefaultSigner::new("keypair", &keypair_path_str);
    /// let args = vec![
    ///     "program",
    ///     keypair_path_str,
    /// ];
    ///
    /// let clap_app = App::new("my-program")
    ///     .arg(
    ///         Arg::with_name("keypair")
    ///             .required(true)
    ///             .help("The signing keypair")
    /// );
    ///
    /// let clap_matches = clap_app.get_matches_from(args);
    /// let wallet_manager = initialize_wallet_manager()?;
    ///
    /// let get_signer = signer.signer_from_path(
    ///     &clap_matches,
    ///     &mut Some(wallet_manager),
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn signer_from_path(
        &self,
        matches: &ArgMatches,
        wallet_manager: &mut Option<Arc<RemoteWalletManager>>,
    ) -> Result<Box<dyn Signer>, Box<dyn std::error::Error>> {
        signer_from_path(matches, self.path()?, &self.arg_name, wallet_manager)
    }

    /// # Examples
    ///
    /// ```
    /// # use solana_remote_wallet::remote_wallet::initialize_wallet_manager;
    /// # use solana_sdk::signature::Keypair;
    /// # use solana_sdk::signer::keypair::write_keypair_file;
    /// # use solana_clap_utils::keypair::{DefaultSigner, SignerFromPathConfig};
    /// # use clap::{App, Arg};
    /// # use tempfile::TempDir;;
    /// # let dir = TempDir::new()?;
    /// # let dir = dir.path();
    /// # let keypair_path = dir.join("payer-keypair-file");
    /// # let keypair_path_str = keypair_path.to_str().expect("uft-8");
    /// # let keypair = Keypair::new();
    /// # write_keypair_file(&keypair, &keypair_path)?;
    /// # let signer = DefaultSigner::new("keypair", &keypair_path_str);
    /// let args = vec![
    ///     "program",
    ///     keypair_path_str,
    /// ];
    ///
    /// let clap_app = App::new("my-program")
    ///     .arg(
    ///         Arg::with_name("keypair")
    ///             .required(true)
    ///             .help("The signing keypair")
    /// );
    ///
    /// let clap_matches = clap_app.get_matches_from(args);
    /// let wallet_manager = initialize_wallet_manager()?;
    /// let config = SignerFromPathConfig {
    ///     allow_null_signer: false,
    /// };
    ///
    /// let get_signer = signer.signer_from_path_with_config(
    ///     &clap_matches,
    ///     &mut Some(wallet_manager),
    ///     &config,
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn signer_from_path_with_config(
        &self,
        matches: &ArgMatches,
        wallet_manager: &mut Option<Arc<RemoteWalletManager>>,
        config: &SignerFromPathConfig,
    ) -> Result<Box<dyn Signer>, Box<dyn std::error::Error>> {
        signer_from_path_with_config(
            matches,
            self.path()?,
            &self.arg_name,
            wallet_manager,
            config,
        )
    }
}

pub(crate) struct SignerSource {
    pub kind: SignerSourceKind,
    pub derivation_path: Option<DerivationPath>,
    pub legacy: bool,
}

impl SignerSource {
    fn new(kind: SignerSourceKind) -> Self {
        Self {
            kind,
            derivation_path: None,
            legacy: false,
        }
    }

    fn new_legacy(kind: SignerSourceKind) -> Self {
        Self {
            kind,
            derivation_path: None,
            legacy: true,
        }
    }
}

const SIGNER_SOURCE_PROMPT: &str = "prompt";
const SIGNER_SOURCE_FILEPATH: &str = "file";
const SIGNER_SOURCE_USB: &str = "usb";
const SIGNER_SOURCE_STDIN: &str = "stdin";
const SIGNER_SOURCE_PUBKEY: &str = "pubkey";

pub(crate) enum SignerSourceKind {
    Prompt,
    Filepath(String),
    Usb(RemoteWalletLocator),
    Stdin,
    Pubkey(Pubkey),
}

impl AsRef<str> for SignerSourceKind {
    fn as_ref(&self) -> &str {
        match self {
            Self::Prompt => SIGNER_SOURCE_PROMPT,
            Self::Filepath(_) => SIGNER_SOURCE_FILEPATH,
            Self::Usb(_) => SIGNER_SOURCE_USB,
            Self::Stdin => SIGNER_SOURCE_STDIN,
            Self::Pubkey(_) => SIGNER_SOURCE_PUBKEY,
        }
    }
}

impl std::fmt::Debug for SignerSourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s: &str = self.as_ref();
        write!(f, "{}", s)
    }
}

#[derive(Debug, Error)]
pub(crate) enum SignerSourceError {
    #[error("unrecognized signer source")]
    UnrecognizedSource,
    #[error(transparent)]
    RemoteWalletLocatorError(#[from] RemoteWalletLocatorError),
    #[error(transparent)]
    DerivationPathError(#[from] DerivationPathError),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

pub(crate) fn parse_signer_source<S: AsRef<str>>(
    source: S,
) -> Result<SignerSource, SignerSourceError> {
    let source = source.as_ref();
    let source = {
        #[cfg(target_family = "windows")]
        {
            source.replace("\\", "/")
        }
        #[cfg(not(target_family = "windows"))]
        {
            source.to_string()
        }
    };
    match uriparse::URIReference::try_from(source.as_str()) {
        Err(_) => Err(SignerSourceError::UnrecognizedSource),
        Ok(uri) => {
            if let Some(scheme) = uri.scheme() {
                let scheme = scheme.as_str().to_ascii_lowercase();
                match scheme.as_str() {
                    SIGNER_SOURCE_PROMPT => Ok(SignerSource {
                        kind: SignerSourceKind::Prompt,
                        derivation_path: DerivationPath::from_uri_any_query(&uri)?,
                        legacy: false,
                    }),
                    SIGNER_SOURCE_FILEPATH => Ok(SignerSource::new(SignerSourceKind::Filepath(
                        uri.path().to_string(),
                    ))),
                    SIGNER_SOURCE_USB => Ok(SignerSource {
                        kind: SignerSourceKind::Usb(RemoteWalletLocator::new_from_uri(&uri)?),
                        derivation_path: DerivationPath::from_uri_key_query(&uri)?,
                        legacy: false,
                    }),
                    SIGNER_SOURCE_STDIN => Ok(SignerSource::new(SignerSourceKind::Stdin)),
                    _ => {
                        #[cfg(target_family = "windows")]
                        // On Windows, an absolute path's drive letter will be parsed as the URI
                        // scheme. Assume a filepath source in case of a single character shceme.
                        if scheme.len() == 1 {
                            return Ok(SignerSource::new(SignerSourceKind::Filepath(source)));
                        }
                        Err(SignerSourceError::UnrecognizedSource)
                    }
                }
            } else {
                match source.as_str() {
                    STDOUT_OUTFILE_TOKEN => Ok(SignerSource::new(SignerSourceKind::Stdin)),
                    ASK_KEYWORD => Ok(SignerSource::new_legacy(SignerSourceKind::Prompt)),
                    _ => match Pubkey::from_str(source.as_str()) {
                        Ok(pubkey) => Ok(SignerSource::new(SignerSourceKind::Pubkey(pubkey))),
                        Err(_) => std::fs::metadata(source.as_str())
                            .map(|_| SignerSource::new(SignerSourceKind::Filepath(source)))
                            .map_err(|err| err.into()),
                    },
                }
            }
        }
    }
}

pub fn presigner_from_pubkey_sigs(
    pubkey: &Pubkey,
    signers: &[(Pubkey, Signature)],
) -> Option<Presigner> {
    signers.iter().find_map(|(signer, sig)| {
        if *signer == *pubkey {
            Some(Presigner::new(signer, sig))
        } else {
            None
        }
    })
}

#[derive(Debug, Default)]
pub struct SignerFromPathConfig {
    pub allow_null_signer: bool,
}

/// # Examples
///
/// ```
/// # use solana_remote_wallet::remote_wallet::initialize_wallet_manager;
/// # use solana_sdk::signature::Keypair;
/// # use solana_sdk::signer::keypair::write_keypair_file;
/// # use solana_clap_utils::keypair::{DefaultSigner, signer_from_path};
/// # use clap::{App, Arg, value_t_or_exit};
/// # use tempfile::TempDir;;
/// # let dir = TempDir::new()?;
/// # let dir = dir.path();
/// let keypair_path = dir.join("payer-keypair-file");
/// let keypair_path_str = keypair_path.to_str().expect("uft-8");
/// # let keypair = Keypair::new();
/// write_keypair_file(&keypair, &keypair_path)?;
///
/// let args = vec![
///     "program",
///     keypair_path_str,
/// ];
///
/// let clap_app = App::new("my-program")
///     .arg(
///         Arg::with_name("keypair")
///             .required(true)
///             .help("The signing keypair")
/// );
///
/// let clap_matches = clap_app.get_matches_from(args);
/// let keypair_str = value_t_or_exit!(clap_matches, "keypair", String);
/// let wallet_manager = initialize_wallet_manager()?;
/// let signer = signer_from_path(
///     &clap_matches,
///     &keypair_str,
///     "keypair",
///     &mut Some(wallet_manager),
/// )?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn signer_from_path(
    matches: &ArgMatches,
    path: &str,
    keypair_name: &str,
    wallet_manager: &mut Option<Arc<RemoteWalletManager>>,
) -> Result<Box<dyn Signer>, Box<dyn error::Error>> {
    let config = SignerFromPathConfig::default();
    signer_from_path_with_config(matches, path, keypair_name, wallet_manager, &config)
}

/// # Examples
///
/// ```
/// # use solana_remote_wallet::remote_wallet::initialize_wallet_manager;
/// # use solana_sdk::signature::Keypair;
/// # use solana_sdk::signer::keypair::write_keypair_file;
/// # use solana_clap_utils::keypair::{DefaultSigner, SignerFromPathConfig, signer_from_path_with_config};
/// # use clap::{App, Arg, value_t_or_exit};
/// # use tempfile::TempDir;;
/// # let dir = TempDir::new()?;
/// # let dir = dir.path();
/// let keypair_path = dir.join("payer-keypair-file");
/// let keypair_path_str = keypair_path.to_str().expect("uft-8");
/// # let keypair = Keypair::new();
/// write_keypair_file(&keypair, &keypair_path)?;
///
/// let args = vec![
///     "program",
///     keypair_path_str,
/// ];
///
/// let clap_app = App::new("my-program")
///     .arg(
///         Arg::with_name("keypair")
///             .required(true)
///             .help("The signing keypair")
/// );
///
/// let clap_matches = clap_app.get_matches_from(args);
/// let keypair_str = value_t_or_exit!(clap_matches, "keypair", String);
/// let wallet_manager = initialize_wallet_manager()?;
/// let config = SignerFromPathConfig {
///     allow_null_signer: false,
/// };
///
/// let signer = signer_from_path_with_config(
///     &clap_matches,
///     &keypair_str,
///     "keypair",
///     &mut Some(wallet_manager),
///     &config,
/// )?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn signer_from_path_with_config(
    matches: &ArgMatches,
    path: &str,
    keypair_name: &str,
    wallet_manager: &mut Option<Arc<RemoteWalletManager>>,
    config: &SignerFromPathConfig,
) -> Result<Box<dyn Signer>, Box<dyn error::Error>> {
    let SignerSource {
        kind,
        derivation_path,
        legacy,
    } = parse_signer_source(path)?;
    match kind {
        SignerSourceKind::Prompt => {
            let skip_validation = matches.is_present(SKIP_SEED_PHRASE_VALIDATION_ARG.name);
            Ok(Box::new(keypair_from_seed_phrase(
                keypair_name,
                skip_validation,
                false,
                derivation_path,
                legacy,
            )?))
        }
        SignerSourceKind::Filepath(path) => match read_keypair_file(&path) {
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("could not read keypair file \"{}\". Run \"solana-keygen new\" to create a keypair file: {}", path, e),
            )
            .into()),
            Ok(file) => Ok(Box::new(file)),
        },
        SignerSourceKind::Stdin => {
            let mut stdin = std::io::stdin();
            Ok(Box::new(read_keypair(&mut stdin)?))
        }
        SignerSourceKind::Usb(locator) => {
            if wallet_manager.is_none() {
                *wallet_manager = maybe_wallet_manager()?;
            }
            if let Some(wallet_manager) = wallet_manager {
                Ok(Box::new(generate_remote_keypair(
                    locator,
                    derivation_path.unwrap_or_default(),
                    wallet_manager,
                    matches.is_present("confirm_key"),
                    keypair_name,
                )?))
            } else {
                Err(RemoteWalletError::NoDeviceFound.into())
            }
        }
        SignerSourceKind::Pubkey(pubkey) => {
            let presigner = pubkeys_sigs_of(matches, SIGNER_ARG.name)
                .as_ref()
                .and_then(|presigners| presigner_from_pubkey_sigs(&pubkey, presigners));
            if let Some(presigner) = presigner {
                Ok(Box::new(presigner))
            } else if config.allow_null_signer || matches.is_present(SIGN_ONLY_ARG.name) {
                Ok(Box::new(NullSigner::new(&pubkey)))
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("missing signature for supplied pubkey: {}", pubkey),
                )
                .into())
            }
        }
    }
}

pub fn pubkey_from_path(
    matches: &ArgMatches,
    path: &str,
    keypair_name: &str,
    wallet_manager: &mut Option<Arc<RemoteWalletManager>>,
) -> Result<Pubkey, Box<dyn error::Error>> {
    let SignerSource { kind, .. } = parse_signer_source(path)?;
    match kind {
        SignerSourceKind::Pubkey(pubkey) => Ok(pubkey),
        _ => Ok(signer_from_path(matches, path, keypair_name, wallet_manager)?.pubkey()),
    }
}

pub fn resolve_signer_from_path(
    matches: &ArgMatches,
    path: &str,
    keypair_name: &str,
    wallet_manager: &mut Option<Arc<RemoteWalletManager>>,
) -> Result<Option<String>, Box<dyn error::Error>> {
    let SignerSource {
        kind,
        derivation_path,
        legacy,
    } = parse_signer_source(path)?;
    match kind {
        SignerSourceKind::Prompt => {
            let skip_validation = matches.is_present(SKIP_SEED_PHRASE_VALIDATION_ARG.name);
            // This method validates the seed phrase, but returns `None` because there is no path
            // on disk or to a device
            keypair_from_seed_phrase(
                keypair_name,
                skip_validation,
                false,
                derivation_path,
                legacy,
            )
            .map(|_| None)
        }
        SignerSourceKind::Filepath(path) => match read_keypair_file(&path) {
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "could not read keypair file \"{}\". \
                    Run \"solana-keygen new\" to create a keypair file: {}",
                    path, e
                ),
            )
            .into()),
            Ok(_) => Ok(Some(path.to_string())),
        },
        SignerSourceKind::Stdin => {
            let mut stdin = std::io::stdin();
            // This method validates the keypair from stdin, but returns `None` because there is no
            // path on disk or to a device
            read_keypair(&mut stdin).map(|_| None)
        }
        SignerSourceKind::Usb(locator) => {
            if wallet_manager.is_none() {
                *wallet_manager = maybe_wallet_manager()?;
            }
            if let Some(wallet_manager) = wallet_manager {
                let path = generate_remote_keypair(
                    locator,
                    derivation_path.unwrap_or_default(),
                    wallet_manager,
                    matches.is_present("confirm_key"),
                    keypair_name,
                )
                .map(|keypair| keypair.path)?;
                Ok(Some(path))
            } else {
                Err(RemoteWalletError::NoDeviceFound.into())
            }
        }
        _ => Ok(Some(path.to_string())),
    }
}

// Keyword used to indicate that the user should be prompted for a keypair seed phrase
pub const ASK_KEYWORD: &str = "ASK";

pub const SKIP_SEED_PHRASE_VALIDATION_ARG: ArgConstant<'static> = ArgConstant {
    long: "skip-seed-phrase-validation",
    name: "skip_seed_phrase_validation",
    help: "Skip validation of seed phrases. Use this if your phrase does not use the BIP39 official English word list",
};

/// Prompts user for a passphrase and then asks for confirmirmation to check for mistakes
pub fn prompt_passphrase(prompt: &str) -> Result<String, Box<dyn error::Error>> {
    let passphrase = prompt_password_stderr(prompt)?;
    if !passphrase.is_empty() {
        let confirmed = rpassword::prompt_password_stderr("Enter same passphrase again: ")?;
        if confirmed != passphrase {
            return Err("Passphrases did not match".into());
        }
    }
    Ok(passphrase)
}

/// Parses a path into a SignerSource and returns a Keypair for supporting SignerSourceKinds
pub fn keypair_from_path(
    matches: &ArgMatches,
    path: &str,
    keypair_name: &str,
    confirm_pubkey: bool,
) -> Result<Keypair, Box<dyn error::Error>> {
    let SignerSource {
        kind,
        derivation_path,
        legacy,
    } = parse_signer_source(path)?;
    match kind {
        SignerSourceKind::Prompt => {
            let skip_validation = matches.is_present(SKIP_SEED_PHRASE_VALIDATION_ARG.name);
            Ok(keypair_from_seed_phrase(
                keypair_name,
                skip_validation,
                confirm_pubkey,
                derivation_path,
                legacy,
            )?)
        }
        SignerSourceKind::Filepath(path) => match read_keypair_file(&path) {
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "could not read keypair file \"{}\". \
                    Run \"solana-keygen new\" to create a keypair file: {}",
                    path, e
                ),
            )
            .into()),
            Ok(file) => Ok(file),
        },
        SignerSourceKind::Stdin => {
            let mut stdin = std::io::stdin();
            Ok(read_keypair(&mut stdin)?)
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "signer of type `{:?}` does not support Keypair output",
                kind
            ),
        )
        .into()),
    }
}

/// Reads user input from stdin to retrieve a seed phrase and passphrase for keypair derivation
/// Optionally skips validation of seed phrase
/// Optionally confirms recovered public key
pub fn keypair_from_seed_phrase(
    keypair_name: &str,
    skip_validation: bool,
    confirm_pubkey: bool,
    derivation_path: Option<DerivationPath>,
    legacy: bool,
) -> Result<Keypair, Box<dyn error::Error>> {
    let seed_phrase = prompt_password_stderr(&format!("[{}] seed phrase: ", keypair_name))?;
    let seed_phrase = seed_phrase.trim();
    let passphrase_prompt = format!(
        "[{}] If this seed phrase has an associated passphrase, enter it now. Otherwise, press ENTER to continue: ",
        keypair_name,
    );

    let keypair = if skip_validation {
        let passphrase = prompt_passphrase(&passphrase_prompt)?;
        if legacy {
            keypair_from_seed_phrase_and_passphrase(seed_phrase, &passphrase)?
        } else {
            let seed = generate_seed_from_seed_phrase_and_passphrase(seed_phrase, &passphrase);
            keypair_from_seed_and_derivation_path(&seed, derivation_path)?
        }
    } else {
        let sanitized = sanitize_seed_phrase(seed_phrase);
        let parse_language_fn = || {
            for language in &[
                Language::English,
                Language::ChineseSimplified,
                Language::ChineseTraditional,
                Language::Japanese,
                Language::Spanish,
                Language::Korean,
                Language::French,
                Language::Italian,
            ] {
                if let Ok(mnemonic) = Mnemonic::from_phrase(&sanitized, *language) {
                    return Ok(mnemonic);
                }
            }
            Err("Can't get mnemonic from seed phrases")
        };
        let mnemonic = parse_language_fn()?;
        let passphrase = prompt_passphrase(&passphrase_prompt)?;
        let seed = Seed::new(&mnemonic, &passphrase);
        if legacy {
            keypair_from_seed(seed.as_bytes())?
        } else {
            keypair_from_seed_and_derivation_path(seed.as_bytes(), derivation_path)?
        }
    };

    if confirm_pubkey {
        let pubkey = keypair.pubkey();
        print!("Recovered pubkey `{:?}`. Continue? (y/n): ", pubkey);
        let _ignored = stdout().flush();
        let mut input = String::new();
        stdin().read_line(&mut input).expect("Unexpected input");
        if input.to_lowercase().trim() != "y" {
            println!("Exiting");
            exit(1);
        }
    }

    Ok(keypair)
}

fn sanitize_seed_phrase(seed_phrase: &str) -> String {
    seed_phrase
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_remote_wallet::locator::Manufacturer;
    use solana_sdk::system_instruction;
    use tempfile::NamedTempFile;

    #[test]
    fn test_sanitize_seed_phrase() {
        let seed_phrase = " Mary   had\ta\u{2009}little  \n\t lamb";
        assert_eq!(
            "Mary had a little lamb".to_owned(),
            sanitize_seed_phrase(seed_phrase)
        );
    }

    #[test]
    fn test_signer_info_signers_for_message() {
        let source = Keypair::new();
        let fee_payer = Keypair::new();
        let nonsigner1 = Keypair::new();
        let nonsigner2 = Keypair::new();
        let recipient = Pubkey::new_unique();
        let message = Message::new(
            &[system_instruction::transfer(
                &source.pubkey(),
                &recipient,
                42,
            )],
            Some(&fee_payer.pubkey()),
        );
        let signers = vec![
            Box::new(fee_payer) as Box<dyn Signer>,
            Box::new(source) as Box<dyn Signer>,
            Box::new(nonsigner1) as Box<dyn Signer>,
            Box::new(nonsigner2) as Box<dyn Signer>,
        ];
        let signer_info = CliSignerInfo { signers };
        let msg_signers = signer_info.signers_for_message(&message);
        let signer_pubkeys = msg_signers.iter().map(|s| s.pubkey()).collect::<Vec<_>>();
        let expect = vec![
            signer_info.signers[0].pubkey(),
            signer_info.signers[1].pubkey(),
        ];
        assert_eq!(signer_pubkeys, expect);
    }

    #[test]
    fn test_parse_signer_source() {
        assert!(matches!(
            parse_signer_source(STDOUT_OUTFILE_TOKEN).unwrap(),
            SignerSource {
                kind: SignerSourceKind::Stdin,
                derivation_path: None,
                legacy: false,
            }
        ));
        let stdin = "stdin:".to_string();
        assert!(matches!(
            parse_signer_source(&stdin).unwrap(),
            SignerSource {
                kind: SignerSourceKind::Stdin,
                derivation_path: None,
                legacy: false,
            }
        ));
        assert!(matches!(
            parse_signer_source(ASK_KEYWORD).unwrap(),
            SignerSource {
                kind: SignerSourceKind::Prompt,
                derivation_path: None,
                legacy: true,
            }
        ));
        let pubkey = Pubkey::new_unique();
        assert!(
            matches!(parse_signer_source(&pubkey.to_string()).unwrap(), SignerSource {
                kind: SignerSourceKind::Pubkey(p),
                derivation_path: None,
                legacy: false,
            }
            if p == pubkey)
        );

        // Set up absolute and relative path strs
        let file0 = NamedTempFile::new().unwrap();
        let path = file0.path();
        assert!(path.is_absolute());
        let absolute_path_str = path.to_str().unwrap();

        let file1 = NamedTempFile::new_in(std::env::current_dir().unwrap()).unwrap();
        let path = file1.path().file_name().unwrap().to_str().unwrap();
        let path = std::path::Path::new(path);
        assert!(path.is_relative());
        let relative_path_str = path.to_str().unwrap();

        assert!(
            matches!(parse_signer_source(absolute_path_str).unwrap(), SignerSource {
                kind: SignerSourceKind::Filepath(p),
                derivation_path: None,
                legacy: false,
            } if p == absolute_path_str)
        );
        assert!(
            matches!(parse_signer_source(&relative_path_str).unwrap(), SignerSource {
                kind: SignerSourceKind::Filepath(p),
                derivation_path: None,
                legacy: false,
            } if p == relative_path_str)
        );

        let usb = "usb://ledger".to_string();
        let expected_locator = RemoteWalletLocator {
            manufacturer: Manufacturer::Ledger,
            pubkey: None,
        };
        assert!(matches!(parse_signer_source(&usb).unwrap(), SignerSource {
                kind: SignerSourceKind::Usb(u),
                derivation_path: None,
                legacy: false,
            } if u == expected_locator));
        let usb = "usb://ledger?key=0/0".to_string();
        let expected_locator = RemoteWalletLocator {
            manufacturer: Manufacturer::Ledger,
            pubkey: None,
        };
        let expected_derivation_path = Some(DerivationPath::new_bip44(Some(0), Some(0)));
        assert!(matches!(parse_signer_source(&usb).unwrap(), SignerSource {
                kind: SignerSourceKind::Usb(u),
                derivation_path: d,
                legacy: false,
            } if u == expected_locator && d == expected_derivation_path));
        // Catchall into SignerSource::Filepath fails
        let junk = "sometextthatisnotapubkeyorfile".to_string();
        assert!(Pubkey::from_str(&junk).is_err());
        assert!(matches!(
            parse_signer_source(&junk),
            Err(SignerSourceError::IoError(_))
        ));

        let prompt = "prompt:".to_string();
        assert!(matches!(
            parse_signer_source(&prompt).unwrap(),
            SignerSource {
                kind: SignerSourceKind::Prompt,
                derivation_path: None,
                legacy: false,
            }
        ));
        assert!(
            matches!(parse_signer_source(&format!("file:{}", absolute_path_str)).unwrap(), SignerSource {
                kind: SignerSourceKind::Filepath(p),
                derivation_path: None,
                legacy: false,
            } if p == absolute_path_str)
        );
        assert!(
            matches!(parse_signer_source(&format!("file:{}", relative_path_str)).unwrap(), SignerSource {
                kind: SignerSourceKind::Filepath(p),
                derivation_path: None,
                legacy: false,
            } if p == relative_path_str)
        );
    }

    #[test]
    fn signer_from_path_with_file() -> Result<(), Box<dyn std::error::Error>> {
        use crate::keypair::signer_from_path;
        use clap::{value_t_or_exit, App, Arg};
        use solana_remote_wallet::remote_wallet::initialize_wallet_manager;
        use solana_sdk::signature::Keypair;
        use solana_sdk::signer::keypair::write_keypair_file;
        use tempfile::TempDir;

        let dir = TempDir::new()?;
        let dir = dir.path();
        let keypair_path = dir.join("payer-keypair-file");
        let keypair_path_str = keypair_path.to_str().expect("utf-8");

        let keypair = Keypair::new();
        write_keypair_file(&keypair, &keypair_path)?;

        let args = vec!["program", keypair_path_str];

        let clap_app = App::new("my-program").arg(
            Arg::with_name("keypair")
                .required(true)
                .help("The signing keypair"),
        );

        let clap_matches = clap_app.get_matches_from(args);
        let keypair_str = value_t_or_exit!(clap_matches, "keypair", String);

        let wallet_manager = initialize_wallet_manager()?;

        let signer = signer_from_path(
            &clap_matches,
            &keypair_str,
            "keypair",
            &mut Some(wallet_manager),
        )?;

        assert_eq!(keypair.pubkey(), signer.pubkey());

        Ok(())
    }
}
