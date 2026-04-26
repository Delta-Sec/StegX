# Packaging

StegX ships as three artefacts, all produced from a single source tree.

## PyPI wheel + sdist

```shell
python -m build
python -m twine check dist/*
```

The wheel layout is the standard `src/` convention: `src/stegx/` is the
single public top-level package, the console script is wired by
`[project.scripts] stegx = "stegx.cli:main"`.

## Debian source package

Build from the debian/ tree (tested on Debian trixie and Parrot 6):

```shell
sudo apt install debhelper-compat=13 dh-python python3-all \
                 pybuild-plugin-pyproject
debuild -us -uc -b
lintian --pedantic ../stegx_2.0.0-1_all.deb
```

`debian/rules` drives everything through `dh $@ --with python3 --buildsystem=pybuild`.

## Docker image

Multi-stage, uid 10001, tini as PID 1, HEALTHCHECK on `stegx --version`:

```shell
docker build \
    --build-arg STEGX_VERSION=2.0.0 \
    --build-arg GIT_SHA=$(git rev-parse HEAD) \
    --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
    -t stegx:2.0.0 -t stegx:latest .

docker run --rm stegx:2.0.0 --version
```
