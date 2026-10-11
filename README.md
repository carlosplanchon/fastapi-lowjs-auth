# fastapi_lowjs_auth
FastAPI LowJS auth system with backend and frontend. FastAPI + fastapi-users + fastapi-sso / HTML + TailwindCSS + AlpineJS

## Quick start

1. `cp src/config_template.toml src/config.toml` and fill it in.
2. `cp src/web/db/docker-compose_template.yaml src/web/db/docker-compose.yml` and set the same Postgres credentials. `DB_PORT` in `config.toml` must match the published port.
3. From the repository root: `bash tmux_start_service.sh`. It starts Postgres and the API (`uv run main_api.py` inside `src/`).
4. Open `http://127.0.0.1:8000/login` (`http://127.0.0.1:8000/<ROOT_PATH>/login` if `ROOT_PATH` is set).

## Tests

`uv run pytest` (uses SQLite and a simulated Google login, no Postgres needed).
