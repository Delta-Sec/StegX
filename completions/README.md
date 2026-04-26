# Shell completions for `stegx`

Static completion files for bash, zsh, and fish, covering the five
subcommands (`encode`, `decode`, `shamir-split`, `shamir-combine`,
`benchmark`) and every flag documented in `stegx --help`.

## Install

### Bash

```bash
# System-wide (needs sudo):
sudo install -Dm0644 stegx.bash /usr/share/bash-completion/completions/stegx

# Per-user:
install -Dm0644 stegx.bash ~/.local/share/bash-completion/completions/stegx
```

Then open a new shell, or `source` the file directly.

### Zsh

```bash
# System-wide (needs sudo):
sudo install -Dm0644 _stegx /usr/share/zsh/site-functions/_stegx

# Per-user: drop it anywhere on $fpath before compinit runs. Example:
install -Dm0644 _stegx ~/.zsh/completions/_stegx
# In ~/.zshrc, before `compinit`:
#   fpath=(~/.zsh/completions $fpath)
```

Run `compinit` (or start a new shell) to pick it up.

### Fish

```bash
install -Dm0644 stegx.fish ~/.config/fish/completions/stegx.fish
```

Fish loads completion files lazily; the completion is available
immediately on the next command line.

## Notes

* File/directory arguments (`-i`, `-f`, `-o`, `-c`, `-d`, `-O`,
  `--keyfile`, `--decoy-file`) complete against filesystem paths.
* `--kdf` completes to `{argon2id, pbkdf2}`.
* `--compression` completes to `{fast, best}`.
* Password flags intentionally do not expand from any source — they
  accept a free-form string.
