# cognee API image for the aslamel home lab: the upstream image (built from
# this fork's Dockerfile, which carries the OIDC patch) plus the FalkorDB
# community adapter.
#
# The adapter pins cognee==1.6.1; installing it with --no-deps keeps the
# image's own cognee. 0.4.1 (the cognee 1.6 line) is not on PyPI, whose last
# release (0.4.0) targets cognee 1.4: it comes from the repository, pinned to a
# commit. Its import and a FalkorDB round trip run in CI
# (falkor_roundtrip.py), so API drift fails the build rather than production.
ARG BASE_IMAGE=cognee-base:local
FROM ${BASE_IMAGE}

COPY --from=ghcr.io/astral-sh/uv:python3.12-bookworm-slim@sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58 /usr/local/bin/uv /usr/local/bin/uv

USER root
RUN uv pip install --python /app/.venv/bin/python --no-cache \
        "falkordb==1.2.0" \
    && uv pip install --python /app/.venv/bin/python --no-cache --no-deps \
        "cognee-community-hybrid-adapter-falkor @ git+https://github.com/topoteretes/cognee-community@5e78950e408d66cbb3787ed9af6a7f5a37d6e20a#subdirectory=packages/hybrid/falkordb" \
    && rm /usr/local/bin/uv
USER cognee

COPY --chown=cognee:cognee deploy/aslamel/falkor_roundtrip.py /app/deploy/aslamel/falkor_roundtrip.py

RUN python -c "import cognee, cognee_community_hybrid_adapter_falkor.register"
