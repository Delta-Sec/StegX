
ARG PYTHON_VERSION=3.12

ARG PYTHON_DIGEST=sha256:aef5b94feb42e700e7b26d55546c81786bfab5a4150b6598e5f6a81abe97ceac

ARG STEGX_VERSION=2.0.0
ARG GIT_SHA=unknown
ARG BUILD_DATE=unknown

FROM python:${PYTHON_VERSION}-slim@${PYTHON_DIGEST} AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        build-essential \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY pyproject.toml README.md requirements.txt LICENSE ./
COPY src ./src

ENV PREFIX=/install
RUN pip install --prefix="${PREFIX}" --no-warn-script-location ".[all]"

FROM python:${PYTHON_VERSION}-slim@${PYTHON_DIGEST} AS runtime

ARG STEGX_VERSION
ARG GIT_SHA
ARG BUILD_DATE

LABEL org.opencontainers.image.title="StegX" \
      org.opencontainers.image.description="Authenticated LSB steganography with Argon2id, AES-GCM/ChaCha20-Poly1305, v3 container format, Shamir quorum and plausible-deniability panic mode" \
      org.opencontainers.image.version="${STEGX_VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="Delta-Sec <ayhamasfoor1@gmail.com>" \
      org.opencontainers.image.url="https://github.com/Delta-Sec/StegX" \
      org.opencontainers.image.source="https://github.com/Delta-Sec/StegX" \
      org.opencontainers.image.documentation="https://delta-sec.github.io/StegX/" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="Delta-Sec"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    STEGX_IN_DOCKER=1

RUN apt-get update \
    && apt-get install --no-install-recommends -y tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

RUN groupadd --system --gid 10001 stegx \
    && useradd  --system --uid 10001 --gid 10001 \
                --home-dir /home/stegx --create-home --shell /usr/sbin/nologin stegx \
    && mkdir /work \
    && chown stegx:stegx /work

USER stegx
WORKDIR /work

HEALTHCHECK --interval=1m --timeout=10s --start-period=10s --retries=3 \
    CMD ["stegx", "--version"]

ENTRYPOINT ["/usr/bin/tini", "--", "stegx"]
CMD ["--help"]
