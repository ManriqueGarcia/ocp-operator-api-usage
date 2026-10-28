#!/usr/bin/env bash

# Keep the existing entry point while using Python to stream large audit logs.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$script_dir/ocp-operator-api-usage.py" "$@"
