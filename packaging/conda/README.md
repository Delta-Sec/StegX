# conda-forge packaging

This recipe is intended for submission to **conda-forge**.

## Submission flow

1. Wait until `stegx-cli` is published on PyPI (so `stegx_cli-2.0.0.tar.gz` is on
   `files.pythonhosted.org`).
2. Compute the sha256 of the sdist:
   ```
   curl -sL https://files.pythonhosted.org/packages/source/s/stegx-cli/stegx_cli-2.0.0.tar.gz | sha256sum
   ```
   Replace `REPLACE_WITH_SDIST_SHA256_AFTER_PYPI_RELEASE` in `meta.yaml`.
3. Fork <https://github.com/conda-forge/staged-recipes>.
4. Create a directory `recipes/stegx/` inside it, copy `meta.yaml` there, and
   add the standard conda-forge license headers (no comments allowed in the
   recipe — it's already comment-free).
5. Open a PR — conda-forge maintainers review (typically 1-3 weeks for first
   submission).
6. Once merged, conda-forge bot creates a new repo
   `conda-forge/stegx-feedstock`. Future updates happen there.

## After acceptance

Users install via:

```bash
mamba install -c conda-forge stegx-cli
```

`conda-forge`'s `regro-cf-autotick-bot` will automatically open PRs for new
PyPI releases — usually within a day.
