#![warn(clippy::pedantic)]
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

mod either;
mod lints;
mod macros;

use clap::Parser;
use dialoguer::theme::ColorfulTheme;
#[cfg(feature = "access-secrets")]
use lints::lint_all_secrets;
#[cfg(feature = "access-secret-key")]
use lints::lint_all_secrets_no_fork;
use lints::{all_secrets, lint_dir_tree, Lint, Lints};
use miette::Diagnostic;
use thiserror::Error;

#[derive(Debug, Diagnostic, Error)]
#[error("found problems with password store")]
struct LintFailure {
    #[related]
    lint_results: Vec<Lints>,
}

fn main() -> miette::Result<()> {
    miette::set_panic_hook();
    Opts::parse().run().map_err(Into::into)
}

#[derive(Debug, Parser)]
#[allow(clippy::struct_excessive_bools)]
struct Opts {
    /// The password store directory
    #[arg(env = "PASSWORD_STORE_DIR", default_value = "~/.password-store")]
    dir: PathBuf,
    /// Path to the pass binary (e.g. set to `gopass` to use that instead)
    #[arg(long, default_value = "pass")]
    #[cfg(feature = "access-secrets")]
    pass_bin: String,
    /// The subcommand/arg to use to decrypt a secret (e.g. use `--decrypt` with gpg to bypass
    /// pass)
    #[arg(long, default_value = "show")]
    #[cfg(feature = "access-secrets")]
    show_cmd: String,
    /// Extra arguments to the pass cmd (e.g. `--no-sync` for gopass)
    #[arg(long)]
    #[cfg(feature = "access-secrets")]
    extra_args: Option<String>,
    /// Pass the full path instead of a path relative to the password store without the `.gpg`
    /// extension (as expected by `pass show`)
    ///
    /// By default `$pass_cmd path/to/file` is used, but with this option `$pass_cmd
    /// $PASSWORD_STORE_DIR/path/to/file.gpg` is used instead.
    #[arg(short, long)]
    #[cfg(feature = "access-secrets")]
    real_path: bool,
    /// Show one error at a time.
    ///
    /// Useful for fixing them on a different pane
    #[arg(short = '1', long)]
    one_at_a_time: bool,
    /// Do not read the password files.
    ///
    /// Only runs linters that don't access the files (never decrypts passwords).
    #[arg(short, long)]
    #[cfg(feature = "access-secrets")]
    no_read_passwords: bool,
    /// Do analysis but don't report results to stderr
    ///
    /// Useful for benchmarking
    #[arg(long)]
    no_report: bool,
    /// Try to force pintentry through the terminal (will be done automatically when outside a
    /// graphical session).
    #[arg(long)]
    #[cfg(feature = "access-secret-key")]
    no_gui: bool,
    /// Instead of running the provided command, retrieve the private key from the agent and use it
    /// to decrypt the secrets.
    #[arg(long)]
    #[cfg(feature = "access-secret-key")]
    retrieve_key: bool,
}

impl Opts {
    fn run(self) -> Result<(), LintFailure> {
        let Self {
            dir,
            #[cfg(feature = "access-secrets")]
            pass_bin,
            #[cfg(feature = "access-secrets")]
            show_cmd,
            #[cfg(feature = "access-secrets")]
            extra_args,
            #[cfg(feature = "access-secrets")]
            real_path,
            #[cfg(feature = "access-secrets")]
            no_read_passwords,
            no_report,
            #[cfg(feature = "access-secret-key")]
            no_gui,
            #[cfg(feature = "access-secret-key")]
            retrieve_key,
            one_at_a_time,
        } = self;
        #[cfg(feature = "access-secrets")]
        let show_cmd: &[&str] = if no_read_passwords {
            // No need to parse the cmd if we don't use it c:
            &[]
        } else if let Some(extra_args) = extra_args {
            let mut args: Vec<&str> = vec![pass_bin.leak(), show_cmd.leak()];
            args.extend(shlex::Shlex::new(&extra_args).map(|s| &*s.leak()));
            &*args.leak()
        } else {
            &*vec![&*pass_bin.leak(), show_cmd.leak()].leak()
        };
        let store = dir.as_path(); // borrow (makes it Copy and prevents moves)
        let secrets = timeit!("Scanning password store"; all_secrets(store));
        let results: BTreeMap<Box<Path>, Vec<Lint>> = timeit!("Analyzing store tree"; lint_dir_tree(&secrets)
            .into_iter()
            .map(|lint| (lint.store_path.clone(), vec![lint.into()]))
            .collect());
        #[cfg(feature = "access-secrets")]
        let mut results = results;
        #[cfg(feature = "access-secrets")]
        if no_read_passwords || secrets.is_empty() {
            return if no_report || results.is_empty() {
                Ok(())
            } else if one_at_a_time {
                show_one_at_a_time(results);
                Ok(())
            } else {
                Err(LintFailure {
                    lint_results: results
                        .into_iter()
                        .map(|(entry, lints)| Lints { entry, lints })
                        .collect(),
                })
            };
        }
        #[cfg(not(feature = "access-secret-key"))]
        let retrieve_key = false; // horrible hack
        if retrieve_key {
            #[cfg(feature = "access-secret-key")]
            lint_all_secrets_no_fork(store, secrets, &mut results, no_gui)
                .expect("failed to lint secrets");
        } else {
            #[cfg(feature = "access-secrets")]
            lint_all_secrets(secrets, &mut results, real_path, show_cmd);
        }
        if no_report || results.is_empty() {
            Ok(())
        } else if one_at_a_time {
            show_one_at_a_time(results);
            Ok(())
        } else {
            Err(LintFailure {
                lint_results: results
                    .into_iter()
                    .map(|(entry, lints)| Lints { entry, lints })
                    .collect(),
            })
        }
    }
}

fn show_one_at_a_time(results: BTreeMap<Box<Path>, Vec<Lint>>) {
    let theme = ColorfulTheme::default();
    let prompt = dialoguer::Select::with_theme(&theme)
        .items(&["show", "skip", "exit"])
        .default(0);
    for (entry, lints) in results {
        let ix = prompt
            .clone()
            .with_prompt(format!("`{}` has issues", entry.display()))
            .interact_opt()
            .ok()
            .flatten();
        let Some(ix) = ix else { break };
        match ix {
            0 => {} // show lints
            1 => continue,
            2 => break,
            _ => unreachable!("invalid option"),
        }
        for lint in lints {
            let lint = miette::Report::from(lint);
            print!("{lint:?}");
        }
    }
}
