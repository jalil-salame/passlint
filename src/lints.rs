#[cfg(feature = "access-secrets")]
use std::process::Output;
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    path::{Path, PathBuf, StripPrefixError},
};

use indicatif::{ProgressBar, ProgressFinish, ProgressIterator, ProgressStyle};
use miette::{miette, Diagnostic};
use thiserror::Error;

#[cfg(feature = "access-secret-key")]
mod lint_gpg_agent;
#[cfg(feature = "access-secret-key")]
pub use lint_gpg_agent::lint_all_secrets_no_fork;

use crate::warn;

pub const PROGRESS_TEMPLATE: &str = "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>3}/{len:3} {msg}";

#[inline]
#[cfg(feature = "access-secrets")]
fn bar_style() -> ProgressStyle {
    ProgressStyle::with_template(PROGRESS_TEMPLATE).expect("valid style template")
}

#[derive(Debug)]
pub struct Secret {
    pub name: Box<OsStr>,
    #[cfg(feature = "access-secrets")]
    pub path: Box<Path>,
    pub store_path: Box<Path>,
}

impl Secret {
    pub fn new(store: &Path, path: &Path) -> Self {
        Self::try_new(store, path).expect("path should be inside the password store")
    }

    pub fn try_new(store: &Path, path: &Path) -> Result<Self, StripPrefixError> {
        let name = path.file_stem().unwrap_or(OsStr::new("")).into();
        let path: Box<Path> = path.into();
        let store_path = clean_path(store, &path)?.into_boxed_path();
        Ok(Self {
            name,
            #[cfg(feature = "access-secrets")]
            path,
            store_path,
        })
    }
}

pub fn all_secrets(store: &Path) -> Vec<Secret> {
    let spinner = ProgressBar::new_spinner()
        .with_message("searching entries")
        .with_finish(ProgressFinish::AndLeave);
    let walker = ignore::WalkBuilder::new(store)
        .filter_entry(|entry| {
            if let Some(ftype) = entry.file_type() {
                if ftype.is_dir() {
                    return true;
                }
                if ftype.is_file() {
                    return entry.path().extension() == Some(OsStr::new("gpg"));
                }
            }
            false
        })
        .build();
    walker
        .filter_map(|entry| {
            spinner.inc(1);
            let entry = warn!(entry; else return None => "failed to retrieve store entry: {err}");
            if entry.file_type()?.is_dir() {
                return None;
            }
            Some(Secret::new(store, entry.path()))
        })
        .collect()
}

#[derive(Debug, Error, Diagnostic)]
#[error("entry `{}` is the only entry in `{}`", store_path.display(), recommended.display())]
#[diagnostic(
    code("directory::single_entry"),
    help("consider renaming `{}` to `{}` and adding `login: {name:?}` to the entry", store_path.display(), recommended.display())
)]
pub struct OnlySecretInDir {
    pub name: Box<OsStr>,
    pub store_path: Box<Path>,
    pub recommended: Box<Path>,
}

pub fn lint_dir_tree(secrets: &[Secret]) -> Vec<OnlySecretInDir> {
    let mut single_entry = BTreeMap::new();
    for secret in secrets
        .iter()
        .progress_with_style(
            ProgressStyle::with_template(PROGRESS_TEMPLATE).expect("valid template"),
        )
        .with_message("analyzing store tree")
        .with_finish(ProgressFinish::AndLeave)
    {
        let parent = secret
            .store_path
            .parent()
            .ok_or_else(|| miette!("no parent for secret's store_path: {secret:?}"))
            .unwrap();
        // not at the root
        if parent != Path::new("") {
            single_entry
                .entry(parent)
                .and_modify(|e: &mut (bool, &Secret)| e.0 = false)
                .or_insert((true, secret));
        }
    }
    single_entry
        .into_iter()
        .filter(|&(_recommended, (single, _secret))| single)
        .map(|(recommended, (_single, secret))| OnlySecretInDir {
            name: secret.name.clone(),
            store_path: secret.store_path.clone(),
            recommended: recommended.into(),
        })
        .collect()
}

/// Remove extension and make relative to the password store dir as expected by `pass show`
pub fn clean_path(store: &Path, entry: &Path) -> Result<PathBuf, StripPrefixError> {
    entry
        .strip_prefix(store)
        .map(|path| path.with_extension(""))
}

#[cfg(feature = "access-secrets")]
pub fn lint_all_secrets(
    secrets: Vec<Secret>,
    results: &mut BTreeMap<Box<Path>, Vec<Lint>>,
    real_path: bool,
    cmd: &'static [&'static str],
) {
    use std::collections::btree_map::Entry;

    for secret in secrets
        .into_iter()
        .progress_with_style(bar_style())
        .with_finish(ProgressFinish::AndLeave)
        .with_message("retrieving secrets")
    {
        let lint = warn!(get_and_lint_entry(&secret, real_path, cmd); else continue "failed to lint secret: {err}");
        if let Some(lints) = lint {
            match results.entry(secret.store_path.clone()) {
                Entry::Occupied(entry) => {
                    entry.into_mut().extend(lints);
                }
                Entry::Vacant(entry) => {
                    entry.insert(lints);
                }
            };
        }
    }
}

#[derive(Debug, Error, Diagnostic)]
#[cfg(feature = "access-secrets")]
pub enum LintError {
    #[error("failed to parse contents for {} as UTF-8", entry.display())]
    BadEncoding {
        #[source]
        error: std::str::Utf8Error,
        entry: Box<Path>,
    },
    #[error("could not run pass_cmd because it was empty")]
    EmptyPassCommand,
    #[error("failed to decrypt `{}`: {cmd:?} exited with status {status}\nstdout:\n{stdout}\nstderr:\n{stderr}", entry.display())]
    DecryptFailed {
        cmd: &'static [&'static str],
        entry: Box<Path>,
        stdout: Box<str>,
        stderr: Box<str>,
        status: std::process::ExitStatus,
    },
    #[error("failed run {cmd:?}")]
    PassCmdFailed {
        #[source]
        err: std::io::Error,
        cmd: &'static [&'static str],
    },
}

#[derive(Debug, Error, Diagnostic)]
#[error("`{field}` should be `{expected}`")]
#[diagnostic(severity(Advice), code("secret::key_name"))]
pub struct WrongKeyName {
    pub field: Box<str>,
    pub expected: &'static str,
    #[label("should be `{expected}` instead")]
    pub span: (usize, usize),
    #[source_code]
    pub contents: &'static str,
}

#[derive(Debug, Error, Diagnostic)]
#[error("no url field found")]
#[diagnostic(
    severity(Warning),
    code("secret::no_url"),
    help("add url field to secret (autodetected url: {})", autodetected.display()),
)]
pub struct MissingURL {
    pub autodetected: Box<Path>,
}

#[derive(Debug, Error, Diagnostic)]
#[error("no login field found")]
#[diagnostic(
    severity(Error),
    code("secret::no_login"),
    help("add login field to secret (autodetected login: {})", autodetected.display()),
)]
pub struct MissingLogin {
    pub autodetected: Box<Path>,
}

#[derive(Debug, Error, Diagnostic)]
#[error("field `{field}` should be lowercase instead")]
#[diagnostic(severity(Advice), code("secret::key_format::case"))]
pub struct FieldBadCase {
    pub field: Box<str>,
    #[label("should be `{}` instead", field.to_lowercase())]
    pub span: (usize, usize),
    #[source_code]
    pub contents: &'static str,
}

#[derive(Debug, Error, Diagnostic)]
pub enum Lint {
    #[error(transparent)]
    #[diagnostic(transparent)]
    OnlySecretInDir(#[from] OnlySecretInDir),
    #[error(transparent)]
    #[diagnostic(transparent)]
    WrongKeyName(#[from] WrongKeyName),
    #[error(transparent)]
    #[diagnostic(transparent)]
    MissingURL(#[from] MissingURL),
    #[error(transparent)]
    #[diagnostic(transparent)]
    MissingLogin(#[from] MissingLogin),
    #[error(transparent)]
    #[diagnostic(transparent)]
    FieldBadCase(#[from] FieldBadCase),
}

#[derive(Debug, Error, Diagnostic)]
#[error("found issues in {}", entry.display())]
pub struct Lints {
    pub entry: Box<Path>,
    #[related]
    pub lints: Vec<Lint>,
}

#[cfg(feature = "access-secrets")]
pub fn get_and_lint_entry(
    secret: &Secret,
    real_path: bool,
    cmd: &'static [&'static str],
) -> Result<Option<Vec<Lint>>, LintError> {
    let contents = get_entry(secret, real_path, cmd)?;
    let contents = std::str::from_utf8(&contents).map_err(|error| LintError::BadEncoding {
        error,
        entry: secret.store_path.clone(),
    })?;
    Ok(lint_entry(contents, &secret.store_path))
}

/// Run lints that need access to the contents
#[allow(clippy::too_many_lines)]
#[cfg(feature = "access-secrets")]
pub fn lint_entry(contents: &str, entry: &Path) -> Option<Vec<Lint>> {
    let replace_pass: Vec<_> = std::iter::once("*****")
        .chain(contents.lines().skip(1))
        .collect();
    let contents = replace_pass.join("\n");
    // it's okay, we are just a CLI, we can wait for the OS to clean this up
    let contents: &'static str = contents.leak();
    let mut has_login = false;
    let mut has_url = false;
    let mut lints = Vec::new();
    for line in contents.lines().skip(1) {
        let Some((key, _value)) = line.split_once(": ") else {
            continue;
        };
        let key_lower = key.to_lowercase();
        let key_lower = key_lower.as_str();
        // Safety: key points into contents and contents' length is less than `isize::MAX`
        let offset = unsafe { key.as_ptr().offset_from(contents.as_ptr()) }
            .try_into()
            .expect("key should be a ptr into contents and thus have a positive offset");
        let span = (offset, key.len());
        if key != key_lower {
            lints.push(Lint::from(FieldBadCase {
                field: key.into(),
                span,
                contents,
            }));
        }
        match key_lower {
            "login" | "username" | "user" => {
                has_login = true;
                let expected = "login";
                if key_lower != expected {
                    lints.push(Lint::from(WrongKeyName {
                        field: key.into(),
                        expected,
                        span,
                        contents,
                    }));
                }
            }
            "url" | "site" | "uri" | "website" | "link" => {
                has_url = true;
                let expected = "url";
                if key_lower != expected {
                    lints.push(Lint::from(WrongKeyName {
                        field: key.into(),
                        expected,
                        span,
                        contents,
                    }));
                }
            }
            _ => {}
        }
    }
    if !has_url {
        lints.push(Lint::from(MissingURL {
            autodetected: entry
                .parent()
                .filter(|&parent| parent != Path::new(""))
                .unwrap_or(entry)
                .into(),
        }));
    }
    if !has_login {
        lints.push(Lint::from(MissingLogin {
            autodetected: entry.file_name().map_or(entry, Path::new).into(),
        }));
    }
    if lints.is_empty() {
        return None;
    }
    Some(lints)
}

/// Return the contents of the entry as fetched by `pass_cmd`
#[cfg(feature = "access-secrets")]
fn get_entry(
    entry: &Secret,
    real_path: bool,
    cmd: &'static [&'static str],
) -> Result<Vec<u8>, LintError> {
    let Secret {
        name: _,
        path,
        store_path,
    } = entry;
    let (prog, args) = match cmd {
        &[prog, ..] => (prog, &cmd[1..]),
        _ => return Err(LintError::EmptyPassCommand),
    };
    let path: &Path = if real_path { path } else { store_path };
    let Output {
        status,
        stdout,
        stderr,
    } = std::process::Command::new(prog)
        .args(args)
        .arg(path)
        .output()
        .map_err(|err| LintError::PassCmdFailed { err, cmd })?;
    if !status.success() {
        return Err(LintError::DecryptFailed {
            cmd,
            status,
            entry: store_path.clone(),
            stdout: String::from_utf8_lossy(&stdout).into(),
            stderr: String::from_utf8_lossy(&stderr).into(),
        });
    }
    Ok(stdout)
}
