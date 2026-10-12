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
- The Python and uv images are pinned by digest, and Dependabot proposes their updates (see [Tests and CI](#tests-and-ci)). To update one by hand, change its tag and use the digest from `docker buildx imagetools inspect <image>:<tag>`.

## Database migrations

The schema is managed with Alembic (`src/migrations/`): the app doesn't create tables on startup.

- `uv run alembic upgrade head` brings the database up to date. `tmux_start_service.sh` runs it before starting the API.
- After changing the models in `src/models.py`, run `uv run alembic revision --autogenerate -m "describe the change"`, review the file it creates in `src/migrations/versions/` and commit it. The tests, and so CI, fail if a model change has no migration. Alembic runs `ruff check --fix` on every new migration (`[post_write_hooks]` in `alembic.ini`), so it already passes the linter.
- A database created before migrations existed (the app used to create its tables itself) already has the tables: run `uv run alembic stamp head` once instead, to mark it as up to date.

## Sessions

- Browsers sign in through `/auth/cookie/login`. The session lives in an HttpOnly cookie, so JavaScript (and an XSS) can't read it. It is SameSite=Lax, Secure when `PUBLIC_URL` is https, and scoped to `ROOT_PATH`.
- Each session is a row in the database that stores only a hash of the cookie's token. Signing out ends it for real, and resetting the password ends every session of the account. Sessions last 14 days (`SESSION_LIFETIME_SECONDS` in `src/sessions.py`). Expired sessions are deleted too: a user's own when they sign in again, and all of them every time the app starts.
- Signed-in users change their password from the account page (`POST /auth/change-password`), which asks for the current one. That ends every other session of the account and gives this browser a new one.
- The account page can also sign out of other devices (`POST /auth/cookie/logout-others`) without changing the password. It ends every session of the account, this one too, and gives this browser a new one, so a copy of its old cookie stops working as well.
- Users can delete their account from the account page (`POST /auth/delete-account`), which asks for their password. Accounts created with Google set one first with the reset link.
  - Deletion is immediate: the user and every session go, Bearer JWTs stop working, and verified addresses get a "Your account was deleted" email.
  - A superuser's `DELETE /users/{id}` gets the same cleanup and email.
  - Tables you add with a foreign key to `user` need `ON DELETE CASCADE`: otherwise deleting fails, and changes nothing.
  - Deletion doesn't reach emails already sent, logs (the `console` email backend logs whole emails) or database backups.
- There's no `PATCH /users/me`: fastapi-users' version changed the password without the current one, and the email without confirming it, so anyone with a session could take the account over (new email, then "forgot password").
- Users change their email from the account page (`POST /auth/request-email-change`), with their password, in two steps:
  - The current address gets a link to approve the change. This happens always, even if it isn't verified, so someone who only knows the password can't move the account.
  - Then the new address gets a link to confirm it. The account ends up verified with the new email, the old address gets a notice, and sessions stay.
  - Changing or resetting the password cancels pending changes.
  - If the current address can't approve (a typo at sign-up, a lost mailbox), delete the account and sign up again.
  - Google sign-in matches accounts by email: after a change, signing in with Google with the old address creates a new, separate account.
- API clients (scripts, mobile apps, Swagger's "Authorize") can use Bearer JWTs from `/auth/jwt/login`.
  - They carry a fingerprint of the password, so they stop working as soon as it changes: a change, a reset, or Google taking over an unverified account. The client then signs in again.
  - They can't be revoked any other way (signing out doesn't end them), so they last one hour.
- State-changing requests that a browser sends from another site are rejected with `403`: their `Origin` must be `PUBLIC_URL` or the host the request went to. This adds to SameSite and also covers sign-in.

## Google sign-in

Google only returns verified emails, so signing in with Google marks the account as verified. If an unverified email/password account already uses that email, Google wins: the user gets into that account and its old password stops working, since whoever set it never proved they own the email. Accounts that verified their email keep their password.

## Email: verification and password reset

- Signing up sends a verification link; users can sign in before verifying, and the account page lets them ask for a new link. Routes that need a verified email can use `fastapi_users.current_user(active=True, verified=True)`.
- "Forgot your password?" emails a reset link. Using it also verifies the account, since the link went to that address.
- Changing or resetting the password emails a "Your password was changed" notice. If it wasn't the owner, they find out and can take the account back with a reset link, which always reaches them because the email only changes with the current address's approval.
- Deleting an account emails a "Your account was deleted" notice, but only to verified addresses: anyone can sign up someone else's address, and signing up and deleting over and over would flood it.
- Links are built from `[app] PUBLIC_URL`, never from the request's Host header, so a forged Host can't redirect reset links. Links expire after 60 minutes.
- A link opens a page with a button, and nothing happens until the person clicks. Mail scanners open links too: a verification that ran on its own could verify an address its owner never saw.
- `[email] BACKEND = "console"` writes emails to the server log instead of sending them (development only). For real delivery set `BACKEND = "smtp"` and the `SMTP_*` settings. To try SMTP locally, a catch-all server such as [Mailpit](https://mailpit.axllent.org/) works: `SMTP_HOST = "127.0.0.1"`, `SMTP_PORT = 1025`, `SMTP_SECURITY = "none"`.

## Rate limiting

Sign-in, registration, password and email changes, account deletion and the routes that send emails are rate limited. Over a limit, the API answers `429` with a `Retry-After` header.

| Limit | Default |
|---|---|
| Failed sign-ins in a row, per IP and email (a successful sign-in resets it) | 5 per 15 minutes |
| Sign-in attempts per IP | 30 per 15 minutes |
| Reset, verification and email-change emails per address, counted whether the account exists or not | 3 per hour |
| Reset, verification and email-change email requests per IP | 10 per hour |
| Registrations per IP | 10 per hour |
| Registrations per address, since each one emails a verification link | 3 per hour |
| Wrong current passwords in a row, per account, counted together for password changes, email changes and account deletion (a correct one resets it) | 5 per 15 minutes |

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

No CDNs at runtime: the page loads its CSS, JS and images from `src/web/static/`. They're served with `Cache-Control: no-cache`, so browsers check with the server before reusing them (a `304` when nothing changed): after a deploy, the new page never runs with an old `app.js`.

- CSS: Tailwind v4, compiled from `src/web/tailwind.css`. After changing classes in the templates, run `bash build_css.sh` and commit `src/web/static/app.css`. The script downloads the Tailwind standalone CLI to `.tools/` on first use (no Node.js needed) and checks it against a pinned checksum.
- Icon: `favicon.svg`, declared in `login.html`. Otherwise browsers ask for `/favicon.ico` at the domain's root, outside `ROOT_PATH`.
- JS: the page's logic is in `app.js`, as an Alpine component (`Alpine.data("authApp", ...)`).
- Alpine.js: `alpine-csp-3.17.4.min.js`, the CSP build (`dist/cdn.min.js` from the `@alpinejs/csp` npm package), so the CSP doesn't need `'unsafe-eval'`. Its expressions are simpler than the regular build's (no arrow functions, template literals or globals like `window`): keep the attributes short and the logic in `app.js`. To update it, replace the file and its reference in `login.html`.

## Tests and CI

- `uv run pytest` runs the tests (with SQLite and a simulated Google login, no Postgres needed).
- `uv run ruff check` runs the linter: ruff's default rules (likely bugs, modern syntax, import order) plus a few more error rules (`pyproject.toml`). `uv run ruff check --fix` fixes most findings. Ruff's version is pinned in `uv.lock`, so its defaults only change when Dependabot updates it, and any new finding shows up in that pull request's CI.

GitHub Actions (`.github/workflows/tests.yml`) runs on every push to `main` and every pull request:

- the linter and the tests, and a check that `src/web/static/app.css` matches the templates;
- the Docker image, built and started from the compose template with Postgres. It checks that the API serves the sign-in page, and that no password from `config.toml` or the compose file ended up in the image.

Dependabot (`.github/dependabot.yml`) opens weekly pull requests for the actions, the Python packages and the Docker images.

- Minor and patch updates come grouped, one pull request per kind; major ones come one by one.
- A new release waits a week before Dependabot proposes it. The uv image can't wait, because its registry gives no release dates.
- It doesn't propose a new Python version, which is a decision of its own, or a new major version of Postgres, which can't read the previous one's data.
