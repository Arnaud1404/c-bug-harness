#!/usr/bin/env bash
# Starts llama-server in Docker on 127.0.0.1:8080 with one model of
# models.lock, then waits until it answers and checks that every layer is on
# the GPU. One model at a time: two do not fit in 8 GB.
# Usage: scripts/serve.sh NAME   (NAME from models.lock; stop: docker stop llama)
set -eu

cd "$(dirname "$0")/.."
image=ghcr.io/ggml-org/llama.cpp:server-cuda13-b12767
models="${MODELS_DIR:-$HOME/llm/models}"
url="$(awk -v n="${1:?usage: serve.sh NAME}" '$1 == n { print $2 }' models.lock)"
[ -n "$url" ] || { echo "no model $1 in models.lock" >&2; exit 2; }
file="$(basename "$url")"
[ -f "$models/$file" ] || { echo "run scripts/fetch.sh first" >&2; exit 2; }
if pwd -W > /dev/null 2>&1; then
    models="$(cd "$models" && pwd -W)"
fi

# Flags from c-secure-build's llm-eval/harness/serve.sh: 16k context, q8 KV
# cache, one slot, no RAM prompt cache. --jinja applies the model's chat
# template, which is what turns tool calls into the OpenAI format.
MSYS_NO_PATHCONV=1 docker run -d --rm --name llama --gpus all -p 127.0.0.1:8080:8080 \
    -v "$models:/models:ro" "$image" -m "/models/$file" --alias "$1" \
    -ngl 99 -c 16384 --jinja -fa on -ctk q8_0 -ctv q8_0 -np 1 --cache-ram 0 \
    --reasoning-format deepseek --host 0.0.0.0 --port 8080 > /dev/null

for _ in $(seq 1 180); do
    if curl -sf http://127.0.0.1:8080/health > /dev/null; then
        line="$(docker logs llama 2>&1 | grep -o 'offloaded [0-9]*/[0-9]* layers' | tail -1)"
        echo "$1 ready: $line"
        layers="$(echo "$line" | awk '{ print $2 }')"
        layers="${layers:-0/1}"
        [ "${layers%/*}" = "${layers#*/}" ] || { echo "not every layer is on the GPU" >&2; exit 1; }
        exit 0
    fi
    sleep 1
done
echo "llama-server did not start" >&2
docker logs llama 2>&1 | tail -20 >&2
exit 1
