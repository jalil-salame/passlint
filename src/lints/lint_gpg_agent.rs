#[cfg(feature = "access-secret-key")]
use std::str::FromStr;
use std::{
    collections::{btree_map::Entry, BTreeMap},
    fmt::Display,
    io::Read,
    path::Path,
};

use indicatif::{ProgressFinish, ProgressIterator};
use key::{PublicParts, UnspecifiedRole};
use miette::{bail, miette, Context, IntoDiagnostic};
use sequoia_gpg_agent::Error as AgentError;
use sequoia_openpgp::{
    crypto::{KeyPair, SessionKey},
    packet::prelude::*,
    parse::{
        stream::{DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper},
        PacketParser, PacketParserResult, Parse,
    },
    policy::StandardPolicy,
    types::SymmetricAlgorithm,
    Cert, Fingerprint, KeyHandle, KeyID,
};

use crate::{
    either::Either,
    lints::{bar_style, lint_entry, Secret},
};

macro_rules! parse_packet {
    ($packet:ident, $parser:expr) => {
        $parser
            .recurse()
            .map_err_to_diagnostic()
            .and_then(|(packet, ppr)| {
                if let Packet::$packet(packet) = packet {
                    Ok((packet, ppr))
                } else {
                    bail!("expected {}", stringify!($packet))
                }
            })
    };
}

pub type PubKey<R = UnspecifiedRole> = Key<PublicParts, R>;

pub fn lint_all_secrets_no_fork(
    store: &Path,
    secrets: Vec<Secret>,
    results: &mut BTreeMap<Box<Path>, Vec<super::Lint>>,
    no_gui: bool,
) -> miette::Result<()> {
    let context = sequoia_gpg_agent::gnupg::Context::new().into_diagnostic()?;
    let cert = match get_cert(store) {
        Ok(val) => val,
        Err(err) => return Err(err),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .into_diagnostic()?;
    let keys: BTreeMap<KeyID, PubKey> = cert
        .keys()
        .map(|key| (key.keyid(), key.key().clone()))
        .collect();
    let mut agent = runtime.block_on(async {
        let mut agent = sequoia_gpg_agent::Agent::connect(&context)
            .await
            .into_diagnostic()
            .wrap_err("connecting to gpg-agent")?;
        send_options_to_agent(&mut agent, no_gui)
            .await
            .into_diagnostic()?;
        Ok::<_, miette::Report>(agent)
    })?;
    let mut key = if let Some(secret) = secrets.first() {
        let keyid = recipient_for_secret(secret).wrap_err("retrieving recipient for secret")?;
        let Some(pubkey) = keys.get(&keyid) else {
            bail!("secret key for {keyid} not available")
        };
        runtime.block_on(async {
            agent
                .export(pubkey.clone())
                .await
                .into_diagnostic()?
                .into_keypair()
                .map_err(|err| miette!("{err}"))
        })?
    } else {
        unreachable!("secrets must not be empty by now");
    };
    let now = std::time::Instant::now();
    for secret in secrets
        .into_iter()
        .progress_with_style(bar_style())
        .with_finish(ProgressFinish::AndLeave)
        .with_message("retrieving secrets")
    {
        let data = decrypt_secret(&secret, &mut key, &cert)?;
        let contents = String::from_utf8(data).unwrap();
        if let Some(lints) = lint_entry(&contents, &secret.store_path) {
            match results.entry(secret.store_path.clone()) {
                Entry::Occupied(entry) => {
                    entry.into_mut().extend(lints);
                }
                Entry::Vacant(entry) => {
                    entry.insert(lints);
                }
            };
        };
    }
    let (unit, amount) = crate::macros::human_time(now.elapsed());
    println!("Analyzing secrets: took {amount:.3}{unit}");
    Ok(())
}

trait ErrToStringDiagnostic<T> {
    fn map_err_to_diagnostic(self) -> miette::Result<T>;
}

impl<T, E: Display> ErrToStringDiagnostic<T> for Result<T, E> {
    fn map_err_to_diagnostic(self) -> miette::Result<T> {
        self.map_err(|err| miette!("{err}"))
    }
}

trait PacketParserResultOk<T> {
    type Error;
    fn ok(self) -> Result<T, Self::Error>;
}

impl<'parser> PacketParserResultOk<PacketParser<'parser>> for PacketParserResult<'parser> {
    type Error = miette::Report;

    fn ok(self) -> Result<PacketParser<'parser>, Self::Error> {
        match self {
            PacketParserResult::Some(pp) => Ok(pp),
            PacketParserResult::EOF(_) => bail!("unexpected eof"),
        }
    }
}

pub fn recipient_for_secret(secret: &Secret) -> miette::Result<KeyID> {
    let data = std::fs::read(&secret.path).into_diagnostic()?;
    let data = data.as_slice();
    let pp = PacketParser::from_bytes(data)
        .map_err_to_diagnostic()?
        .ok()?;
    let (pkesk, _) = parse_packet!(PKESK, pp)?;
    Ok(pkesk.recipient().clone())
}

struct KeyDecryptor<'a> {
    keypair: &'a mut KeyPair,
    cert: &'a Cert,
}

impl DecryptionHelper for KeyDecryptor<'_> {
    fn decrypt<D>(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> sequoia_openpgp::Result<Option<Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        pkesks
            .iter()
            .find_map(|pkesk| pkesk.decrypt(self.keypair, sym_algo))
            .map(|(algo, ref sk)| decrypt(algo, sk));
        Ok(None)
    }
}

impl VerificationHelper for KeyDecryptor<'_> {
    fn get_certs(&mut self, ids: &[KeyHandle]) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(if ids.contains(&self.cert.key_handle()) {
            vec![self.cert.clone()]
        } else {
            vec![]
        })
    }

    fn check(&mut self, _structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        Ok(())
    }
}

pub fn decrypt_secret(
    secret: &Secret,
    keypair: &mut KeyPair,
    cert: &Cert,
) -> miette::Result<Vec<u8>> {
    let data = std::fs::read(&secret.path).into_diagnostic()?;
    let data = data.as_slice();
    let policy = StandardPolicy::new();
    let mut decryptor = DecryptorBuilder::from_bytes(data)
        .map_err_to_diagnostic()
        .context("failed to build decryptor")?
        .with_policy(&policy, None, KeyDecryptor { keypair, cert })
        .map_err_to_diagnostic()
        .context("failed to set the decryptor's policy")?;
    let mut data = vec![];
    decryptor
        .read_to_end(&mut data)
        .into_diagnostic()
        .context("failed to read secret from decryptor")?;
    Ok(data)
}

#[derive(Debug, Clone, Copy)]
enum GpgAgentOption<'a> {
    Env { key: &'a str },
    Normal { key: &'a str, option: &'a str },
}

#[derive(Debug, Clone, Copy)]
enum GpgGUIOption {
    No,
    Yes,
}

impl<'a> Display for GpgAgentOption<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let var = match *self {
            GpgAgentOption::Normal { key, option: _ } | GpgAgentOption::Env { key } => {
                std::env::var(key)
            }
        };
        // Cannot print env var, do not send option
        let Ok(value) = var else {
            return Ok(());
        };
        match *self {
            GpgAgentOption::Normal { key: _, option } => write!(f, "OPTION {option}={value}"),
            GpgAgentOption::Env { key } => write!(f, "OPTION putenv={key}={value}"),
        }
    }
}

const AGENT_OPTIONS: &[(GpgAgentOption, GpgGUIOption)] = &[
    (
        GpgAgentOption::Normal {
            key: "GPG_TTY",
            option: "ttyname",
        },
        GpgGUIOption::No,
    ),
    (
        GpgAgentOption::Normal {
            key: "TERM",
            option: "ttytype",
        },
        GpgGUIOption::No,
    ),
    (
        GpgAgentOption::Normal {
            key: "DISPLAY",
            option: "display",
        },
        GpgGUIOption::Yes,
    ),
    (
        GpgAgentOption::Normal {
            key: "XAUTHORITY",
            option: "xauthority",
        },
        GpgGUIOption::No,
    ),
    (
        GpgAgentOption::Env {
            key: "DBUS_SESSION_BUS_ADDRESS",
        },
        GpgGUIOption::No,
    ),
    (
        GpgAgentOption::Env {
            key: "WAYLAND_DISPLAY",
        },
        GpgGUIOption::Yes,
    ),
];

async fn send_options_to_agent(
    agent: &mut sequoia_gpg_agent::Agent,
    no_gui: bool,
) -> Result<(), AgentError> {
    use std::fmt::Write;
    let mut buf = String::new();
    for &(option, is_gui) in AGENT_OPTIONS {
        if no_gui && matches!(is_gui, GpgGUIOption::Yes) {
            continue;
        }
        write!(buf, "{option}").expect("write to string is infallible");
        // Env var was not set (or errored, see `std::env::var()`)
        if buf.is_empty() {
            continue;
        }
        agent.send_simple(&buf).await?;
        buf.clear();
    }
    Ok(())
}

fn get_keyid(store: &Path) -> miette::Result<KeyID> {
    let keyid_file = store.join(".gpg-id");
    let keyids = std::fs::read_to_string(keyid_file)
        .into_diagnostic()
        .wrap_err("failed to read `/.gpg-id`")?;
    let (keyids, errors): (Vec<_>, Vec<_>) = keyids
        .lines()
        .map(KeyID::from_str)
        .map(Either::from)
        .collect();
    if let Some(keyid) = keyids.into_iter().next() {
        Ok(keyid)
    } else if errors.is_empty() {
        Err(miette!("`/.gpg-id` was empty"))
    } else {
        Err(miette!(
            "`/.gpg-id` contained only invalid keyids: {errors:?}"
        ))
    }
}

fn get_cert(store: &Path) -> miette::Result<Cert> {
    let keyid = get_keyid(store)?;
    let pubkey = store.join(format!(".public-keys/0x{keyid}"));
    let data = std::fs::read(pubkey).into_diagnostic()?;
    sequoia_openpgp::Cert::from_bytes(&data).map_err(|err| miette!("{err}"))
}
