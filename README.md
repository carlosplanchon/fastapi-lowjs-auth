# fastapi_lowjs_auth
FastAPI LowJS auth system with backend and frontend. FastAPI + fastapi-users + fastapi-sso / HTML + TailwindCSS + AlpineJS

## Quick start

1. `cp src/config_template.toml src/config.toml` and fill it in.
2. `cp src/web/db/docker-compose_template.yaml src/web/db/docker-compose.yml` and set the same Postgres credentials. `DB_PORT` in `config.toml` must match the published port.
3. From the repository root: `bash tmux_start_service.sh`. It starts Postgres and the API (`uv run main_api.py` inside `src/`).
4. Open `http://127.0.0.1:8000/login` (`http://127.0.0.1:8000/<ROOT_PATH>/login` if `ROOT_PATH` is set).

## Google sign-in

Google only returns verified emails, so signing in with Google marks the account as verified. If an unverified email/password account already uses that email, Google wins: the user gets into that account and its old password stops working, since whoever set it never proved they own the email. Accounts that verified their email keep their password.

## Email: verification and password reset

- Signing up sends a verification link; users can sign in before verifying, and the account page lets them ask for a new link. Routes that need a verified email can use `fastapi_users.current_user(active=True, verified=True)`.
- "Forgot your password?" emails a reset link. Using it also verifies the account, since the link went to that address.
- Links are built from `[app] PUBLIC_URL`, never from the request's Host header, so a forged Host can't redirect reset links. Links expire after 60 minutes.
- `[email] BACKEND = "console"` writes emails to the server log instead of sending them (development only). For real delivery set `BACKEND = "smtp"` and the `SMTP_*` settings. To try SMTP locally, a catch-all server such as [Mailpit](https://mailpit.axllent.org/) works: `SMTP_HOST = "127.0.0.1"`, `SMTP_PORT = 1025`, `SMTP_SECURITY = "none"`.

## Frontend assets

No CDNs at runtime: the page loads its CSS and JS from `src/web/static/`.

- CSS: Tailwind v4, compiled from `src/web/tailwind.css`. After changing classes in the templates, run `bash build_css.sh` and commit `src/web/static/app.css`. The script downloads the Tailwind standalone CLI to `.tools/` on first use (no Node.js needed) and checks it against a pinned checksum.
- Alpine.js: `alpine-3.17.4.min.js`, copied from the npm package. To update it, replace the file and its reference in `login.html`.

## Tests

`uv run pytest` (uses SQLite and a simulated Google login, no Postgres needed).
