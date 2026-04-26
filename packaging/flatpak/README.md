# Flatpak packaging

This manifest is intended for submission to **Flathub**.

## Submission flow

1. Publish `stegx-cli` to PyPI (so `stegx_cli-2.0.0.tar.gz` exists on `files.pythonhosted.org`).
2. Run `flatpak-pip-generator stegx-cli --output flatpak-stegx-deps` to generate
   the full pinned dependency list with sha256 hashes; replace the manual
   `REPLACE_WITH_*` placeholders or include the generated yaml.
3. Fork <https://github.com/flathub/flathub>, branch `new-pr`, and create a
   directory `io.github.deltasec.StegX/` with this manifest inside it.
4. Open a PR — Flathub maintainers review and merge.

After Flathub accepts, ongoing updates are done in
`https://github.com/flathub/io.github.deltasec.StegX` (a fresh repo created
when the initial PR is merged).
