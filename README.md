# passlint

A linter for the password store managed by [`pass`][1], the unix password manager.

[1]: https://www.passwordstore.org

## Available lints

- Single file in directory:

  Instead of using `mywebsite.net/usename` use `mywebsite.net` with a `login: username` field

### Reads secrets

- Missing fields:

  Example: `url:` and `login:` fields are missing

- Wrong casing in fields:

  Example: `Login:`, `URL:` and `Code:` should instead be `login:`, `url:` and `code:`

- Wrong field name:

  Example: `username` should be `login` and `website` should be `url`

## Usage

Run `passlint` in the terminal. For more information see the help message (`--help`):

```console
$ passlint --help
Usage: passlint [OPTIONS] [DIR]

Arguments:
  [DIR]
          The password store directory

          [env: PASSWORD_STORE_DIR=/home/jalil/.local/share/pass]
          [default: ~/.password-store]

Options:
      --pass-bin <PASS_BIN>
          Path to the pass binary (e.g. set to `gopass` to use that instead)

          [default: pass]

      --show-cmd <SHOW_CMD>
          The subcommand/arg to use to decrypt a secret (e.g. use `--decrypt` with gpg to bypass pass)

          [default: show]

      --extra-args <EXTRA_ARGS>
          Extra arguments to the pass cmd (e.g. `--no-sync` for gopass)

  -r, --real-path
          Pass the full path instead of a path relative to the password store without the `.gpg` extension (as expected by `pass show`)

          By default `$pass_cmd path/to/file` is used, but with this option `$pass_cmd $PASSWORD_STORE_DIR/path/to/file.gpg` is used instead.

  -1, --one-at-a-time
          Show one error at a time.

          Useful for fixing them on a different pane

  -n, --no-read-passwords
          Do not read the password files.

          Only runs linters that don't access the files (never decrypts passwords).

      --no-report
          Do analysis but don't report results to stderr

          Useful for benchmarking

      --no-gui
          Try to force pintentry through the terminal (will be done automatically when outside a graphical session)

      --retrieve-key
          Instead of running the provided command, retrieve the private key from the agent and use it to decrypt the secrets

  -h, --help
          Print help (see a summary with '-h')
```

## Building

1. Ensure `openssl-dev` is available (the devshell using `nix develop` will do this for you).
2. Build with `cargo build --release`

### Turn off features

1. Build without access to the passwords: `cargo build --release --no-default-features`
2. Build without access to the secret key: `cargo build --release --no-default-features --features access-secrets`
