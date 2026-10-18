# Base images pinned by digest: a tag can be moved, a digest can't. Dependabot
# keeps them up to date (.github/dependabot.yml); it only reads FROM lines.

# uv's image, only for its binary.
FROM ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 AS uv

# Build stage: uv installs the locked dependencies, without the dev group, into /app/.venv.
FROM python:3.14.8-slim-trixie@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170 AS build
COPY --from=uv /uv /bin/uv
# Compile the packages to bytecode now: at run time the app's user can't write to /app.
# Copy files out of the cache mount instead of linking them, and use the image's
# Python, which is the same one the final stage has.
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=0
WORKDIR /app
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-dev --no-install-project

# Final stage: the same Python, the environment and the code. No uv, no dev tools.
FROM python:3.14.8-slim-trixie@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170
# An unprivileged user. UID 1000 is usually your user on the host, so it can read
# the config.toml mounted from there.
RUN groupadd --system --gid 1000 app \
 && useradd --system --gid 1000 --uid 1000 --create-home app
WORKDIR /app
# Owned by root: the app can read its code, not change it.
COPY --from=build /app/.venv /app/.venv
COPY alembic.ini ./
COPY src ./src
# uvicorn reads its settings from UVICORN_* variables, so these can be changed
# when the container starts. The config.toml is mounted then too (CONFIG_PATH).
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8000
USER app
EXPOSE 8000
# Bring the schema up to date (a no-op when it already is), then serve. exec makes
# uvicorn the main process, so it gets docker stop's SIGTERM and shuts down cleanly.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn auth_backend_api:app --app-dir src"]
