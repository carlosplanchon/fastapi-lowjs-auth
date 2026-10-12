# fastapi_lowjs_auth
[![Tests](https://github.com/carlosplanchon/fastapi-lowjs-auth/actions/workflows/tests.yml/badge.svg)](https://github.com/carlosplanchon/fastapi-lowjs-auth/actions/workflows/tests.yml)

FastAPI LowJS auth system with backend and frontend. FastAPI + fastapi-users + fastapi-sso / HTML + TailwindCSS + AlpineJS

## Quick start

1. `cp src/config_template.toml src/config.toml` and fill it in.
2. `cp src/web/db/docker-compose_template.yaml src/web/db/docker-compose.yml` and set the same Postgres credentials. `DB_PORT` in `config.toml` must match the published port.
3. From the repository root: `bash tmux_start_service.sh`. It starts Postgres, runs the database migrations (`uv run alembic upgrade head`) and starts the API (`uv run src/main_api.py`).
4. Open `http://127.0.0.1:8000/login` (`http://127.0.0.1:8000/<ROOT_PATH>/login` if `ROOT_PATH` is set).

To run it all in Docker instead, see [Docker](#docker).

## Docker

The `Dockerfile` builds an image with the API. It has the locked dependencies without the dev group and runs as an unprivileged user (UID 1000). On start it brings the database up to date (`alembic upgrade head`) and then serves on port 8000. Your `config.toml` isn't in the image: it's mounted when the container starts (`CONFIG_PATH`).

To run Postgres and the API with Docker Compose:

1. `cp docker-compose_template.yaml docker-compose.yml` and fill in the Postgres credentials.
2. In `src/config.toml`, set `DB_HOST = "postgres"` (the service name), `DB_PORT = 5432` and the same credentials.
3. `docker compose -p yourproject up -d --build`.

- The API is published on `127.0.0.1:8000` only, and Postgres isn't published at all. Put a reverse proxy with HTTPS in front, and make `PUBLIC_URL` https.
- The container's user (UID 1000) must be able to read the mounted `config.toml`. On most Linux machines that's your own user (check with `id -u`); otherwise make the file readable by UID 1000.
- A reverse proxy reaches the container from a Docker network address, not from `127.0.0.1`, so the template sets `FORWARDED_ALLOW_IPS` to Docker's default ranges. Without it, every request would seem to come from the proxy and share the per-IP limits: 30 sign-in attempts per 15 minutes for the whole site, and five wrong passwords would lock an account for everyone. If you publish the port beyond `127.0.0.1`, or changed Docker's `default-address-pools`, set it to your proxy's address instead.
- Other commands run without starting the server, e.g. `docker compose -p yourproject run --rm api alembic current`.
- uvicorn takes its settings from `UVICORN_*` variables (`UVICORN_PORT`, ...). More workers (`WEB_CONCURRENCY`) need a shared store for the rate limits (`STORAGE_URI`, see [Rate limiting](#rate-limiting)).
- The Python and uv images are pinned by digest. To update one, change its tag and use the digest from `docker buildx imagetools inspect <image>:<tag>`.

## Database migrations

The schema is managed with Alembic (`src/migrations/`): the app doesn't create tables on startup.

- `uv run alembic upgrade head` brings the database up to date. `tmux_start_service.sh` runs it before starting the API.
- After changing the models in `src/models.py`, run `uv run alembic revision --autogenerate -m "describe the change"`, review the file it creates in `src/migrations/versions/` and commit it. The tests, and so CI, fail if a model change has no migration.
- A database created before migrations existed (the app used to create its tables itself) already has the tables: run `uv run alembic stamp head` once instead, to mark it as up to date.

## Sessions

- Browsers sign in through `/auth/cookie/login`. The session lives in an HttpOnly cookie, so JavaScript (and an XSS) can't read it. It is SameSite=Lax, Secure when `PUBLIC_URL` is https, and scoped to `ROOT_PATH`.
- Each session is a row in the database that stores only a hash of the cookie's token. Signing out ends it for real, and resetting or changing the password ends every session of the account. Sessions last 14 days (`SESSION_LIFETIME_SECONDS` in `src/sessions.py`).
- API clients (scripts, mobile apps, Swagger's "Authorize") can use Bearer JWTs from `/auth/jwt/login`. Those can't be revoked, so they last one hour.
- State-changing requests that a browser sends from another site are rejected with `403`: their `Origin` must be `PUBLIC_URL` or the host the request went to. This adds to SameSite and also covers sign-in.

## Google sign-in

Google only returns verified emails, so signing in with Google marks the account as verified. If an unverified email/password account already uses that email, Google wins: the user gets into that account and its old password stops working, since whoever set it never proved they own the email. Accounts that verified their email keep their password.

## Email: verification and password reset

- Signing up sends a verification link; users can sign in before verifying, and the account page lets them ask for a new link. Routes that need a verified email can use `fastapi_users.current_user(active=True, verified=True)`.
- "Forgot your password?" emails a reset link. Using it also verifies the account, since the link went to that address.
- Links are built from `[app] PUBLIC_URL`, never from the request's Host header, so a forged Host can't redirect reset links. Links expire after 60 minutes.
- `[email] BACKEND = "console"` writes emails to the server log instead of sending them (development only). For real delivery set `BACKEND = "smtp"` and the `SMTP_*` settings. To try SMTP locally, a catch-all server such as [Mailpit](https://mailpit.axllent.org/) works: `SMTP_HOST = "127.0.0.1"`, `SMTP_PORT = 1025`, `SMTP_SECURITY = "none"`.

## Rate limiting

Sign-in, registration and the routes that send emails are rate limited. Over a limit, the API answers `429` with a `Retry-After` header.

| Limit | Default |
|---|---|
| Failed sign-ins in a row, per IP and email (a successful sign-in resets it) | 5 per 15 minutes |
| Sign-in attempts per IP | 30 per 15 minutes |
| Reset and verification emails per address, counted whether the account exists or not | 3 per hour |
| Reset and verification email requests per IP | 10 per hour |
| Registrations per IP | 10 per hour |

- Change them in the optional `[rate_limits]` section of `config.toml` (see `config_template.toml`).
- Counters live in memory, per process. With several workers, set `STORAGE_URI = "redis://..."` (and `uv add redis`) so they share them.
- Behind a reverse proxy, uvicorn must trust it to see the real client IPs. By default it trusts `127.0.0.1` and `::1`; for a proxy elsewhere, set `FORWARDED_ALLOW_IPS` to its address (the Docker Compose template already does, see [Docker](#docker)). Don't trust every address if the app can be reached directly: clients could fake their IP with `X-Forwarded-For`.

## Security headers

Every response carries:

- `X-Content-Type-Options: nosniff`: browsers use the declared content type instead of guessing one.
- `X-Frame-Options: DENY`: other sites can't show the app inside a frame (clickjacking).
- `Referrer-Policy: same-origin`: other sites don't see the app's URLs. (`no-referrer` would make browsers send `Origin: null` with the app's own form posts, which the Origin check rejects.)
- `Strict-Transport-Security: max-age=31536000`, only when `PUBLIC_URL` is https: for a year, browsers reach this host only over https. They remember it even if you go back to http, so use an https `PUBLIC_URL` only once the host is on https to stay.

HTML pages also get a strict Content Security Policy (`src/security_headers.py`): scripts, styles, images, requests and form posts only from the app itself, nothing inline, no `eval`, and no framing (`frame-ancestors 'none'`). In practice:

- No `<script>` blocks, `style="..."` attributes or `onclick="..."` handlers in the templates: put the code in `src/web/static/`. The tests check it.
- To load something from another site (fonts, analytics), add it to `CONTENT_SECURITY_POLICY`.
- FastAPI's `/docs` and `/redoc` load Swagger UI and ReDoc from a CDN with inline scripts, so they don't get the CSP.

## Frontend assets

No CDNs at runtime: the page loads its CSS, JS and images from `src/web/static/`.

- CSS: Tailwind v4, compiled from `src/web/tailwind.css`. After changing classes in the templates, run `bash build_css.sh` and commit `src/web/static/app.css`. The script downloads the Tailwind standalone CLI to `.tools/` on first use (no Node.js needed) and checks it against a pinned checksum.
- JS: the page's logic is in `app.js`, as an Alpine component (`Alpine.data("authApp", ...)`).
- Alpine.js: `alpine-csp-3.17.4.min.js`, the CSP build (`dist/cdn.min.js` from the `@alpinejs/csp` npm package), so the CSP doesn't need `'unsafe-eval'`. Its expressions are simpler than the regular build's (no arrow functions, template literals or globals like `window`): keep the attributes short and the logic in `app.js`. To update it, replace the file and its reference in `login.html`.

## Tests

`uv run pytest` (uses SQLite and a simulated Google login, no Postgres needed).

GitHub Actions runs them on every push to `main` and every pull request, and also checks that `src/web/static/app.css` matches the templates (`.github/workflows/tests.yml`).
