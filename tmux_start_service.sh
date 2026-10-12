#!/bin/bash
# -*- coding: utf-8 -*-

tmux new-session -d -s "fastapi_lowjs_auth" -n "fastapi_lowjs_auth"

# ------------------------------------------- #
# Split the window horizontally first:
tmux split-window -h -t "fastapi_lowjs_auth:0"

# "up -d" returns before Postgres accepts connections and the migrations need it,
# so wait for it (over TCP: during first-run init it only listens on a socket).
WAIT_FOR_DB="until docker compose -p fastapi_lowjs_auth exec -T postgres pg_isready -h 127.0.0.1 -q; do sleep 1; done"

# Send commands to the respective panes: start Postgres, bring the schema up to
# date, then start the API.
tmux send-keys -t "fastapi_lowjs_auth:0.0" "cd src/web/db && docker compose -p fastapi_lowjs_auth up -d && $WAIT_FOR_DB && cd ../../.. && uv run alembic upgrade head && uv run src/main_api.py" Enter

# ------------------------------------------- #
tmux attach -t "fastapi_lowjs_auth"
