# Homebrew packaging

## Recommended path: own tap

Homebrew core has strict acceptance criteria (notable userbase, stable
releases, no GUI deps).  Easier and faster: ship via your own tap.

### Create the tap (one-time)

1. Create a new GitHub repository **`homebrew-stegx`** under `Delta-Sec`.
2. Copy `stegx.rb` (this directory) to its `Formula/stegx.rb`.
3. After publishing the PyPI sdist, run:

```bash
brew install --build-from-source ./Formula/stegx.rb
brew audit --strict --new ./Formula/stegx.rb
```

4. Generate concrete sha256 values for `stegx.rb` and every `resource` block
   using:

```bash
poet -f Formula/stegx.rb stegx
```

(or use `homebrew-pypi-poet`).  Replace each `REPLACE_WITH_*_SHA256`.

### User install

```bash
brew tap Delta-Sec/stegx
brew install stegx
```

## Submitting to homebrew/core (optional, later)

Wait for `pip install stegx-cli` weekly downloads to be in the **3-figure range**
for several months (Homebrew's notability bar), then open a PR against
<https://github.com/Homebrew/homebrew-core>.
