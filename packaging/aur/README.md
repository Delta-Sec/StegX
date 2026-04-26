# Arch User Repository (AUR) packaging

## One-time setup

1. Create AUR account at <https://aur.archlinux.org/register>.
2. Add SSH public key to AUR profile.
3. Clone the empty AUR repo:
   ```
   git clone ssh://aur@aur.archlinux.org/stegx.git stegx-aur
   ```

## Initial publish

1. Copy `PKGBUILD` (this directory) into `stegx-aur/`.
2. Update `pkgver` and `sha256sums` (run `updpkgsums` to compute hashes).
3. Generate `.SRCINFO`:
   ```
   makepkg --printsrcinfo > .SRCINFO
   ```
4. Test build locally: `makepkg -si`.
5. Commit + push:
   ```
   git add PKGBUILD .SRCINFO
   git commit -m "stegx 2.0.0-1: initial release"
   git push
   ```

## Subsequent updates

The workflow `.github/workflows/aur.yml` (added separately) automates step 2-5
on every `v*.*.*` tag push, using an SSH key stored in the repo secret
`AUR_SSH_PRIVATE_KEY`.
