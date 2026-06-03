#!/bin/bash
# Start WebUI on port 8789 WITHOUT HERMES_WEBUI_PASSWORD
# so it uses multi-user mode from config.yaml

unset HERMES_WEBUI_PASSWORD
unset HERMES_WEBUI_PASSWORD_HASH

cd /data/project/yml/hermes-webui

export HERMES_HOME=/data/project/yml/hermes-webui/.hermes_test
export HERMES_WEBUI_STATE_DIR=/data/project/yml/hermes-webui/.webui_state
export HERMES_WEBUI_PORT=8789
export HERMES_WEBUI_HOST=0.0.0.0
export PYTHONPATH=/data/project/yml/hermes-webui

exec python3 server.py
