#!/usr/bin/env bash
#
# Compile the proto tree into custom_components/aegis_ajax/proto.
#
# With no arguments: wipes the generated tree and recompiles everything (~2600
# files of churn — only worth it when the toolchain itself changes).
#
# With arguments: recompiles just those protos, paths relative to proto_src/,
# leaving the rest of the tree untouched. Use this for an ordinary change to a
# single .proto — it keeps the diff readable *and*, unlike an ad-hoc
# `python -m grpc_tools.protoc` invocation, it goes through the pinned
# grpcio-tools from the dev extra. A stray compiler stamps a different Protobuf
# gencode version into the files it touches, and protobuf then refuses to load
# them on every user's install (#354).
#
#   make proto                                            # everything
#   make proto PROTOS="systems/ajax/.../hub_device.proto"  # just this one
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PROTO_SRC="$PROJECT_ROOT/proto_src"
PROTO_OUT="$PROJECT_ROOT/custom_components/aegis_ajax/proto"

if [ ! -d "$PROTO_SRC" ]; then
    echo "Error: proto_src/ directory not found at $PROTO_SRC"
    exit 1
fi

# Guard the toolchain before it writes anything: an unpinned or mismatched
# grpcio-tools is the whole reason this preamble exists.
EXPECTED_GRPCIO_TOOLS="$(
    cd "$PROJECT_ROOT" && python - <<'PY'
import re
import tomllib
from pathlib import Path

pyproject = tomllib.loads(Path("pyproject.toml").read_text())
for requirement in pyproject["project"]["optional-dependencies"]["dev"]:
    match = re.fullmatch(r"grpcio-tools\s*==\s*(\S+)", requirement.strip())
    if match:
        print(match.group(1))
        break
else:
    raise SystemExit("grpcio-tools is not pinned with '==' in pyproject.toml [dev]")
PY
)"
ACTUAL_GRPCIO_TOOLS="$(python -c 'import importlib.metadata as md; print(md.version("grpcio-tools"))')"

if [ "$EXPECTED_GRPCIO_TOOLS" != "$ACTUAL_GRPCIO_TOOLS" ]; then
    echo "Error: grpcio-tools $ACTUAL_GRPCIO_TOOLS is installed, but pyproject.toml pins $EXPECTED_GRPCIO_TOOLS."
    echo "       The compiler version is baked into every stub it writes, so compiling with"
    echo "       the wrong one ships code the user's protobuf runtime refuses to load (#354)."
    echo "       Rebuild the dev image (make build-docker) before regenerating."
    exit 1
fi

if [ "$#" -gt 0 ]; then
    PROTOS=("$@")
    for proto in "${PROTOS[@]}"; do
        if [ ! -f "$PROTO_SRC/$proto" ]; then
            echo "Error: $proto not found under $PROTO_SRC"
            exit 1
        fi
    done
    echo "Compiling ${#PROTOS[@]} proto file(s) with grpcio-tools $ACTUAL_GRPCIO_TOOLS..."
else
    echo "Cleaning old generated files..."
    find "$PROTO_OUT" -name '*_pb2.py' -o -name '*_pb2_grpc.py' -o -name '*_pb2.pyi' | xargs rm -f
    mapfile -t PROTOS < <(cd "$PROTO_SRC" && find . -name '*.proto' -printf '%P\n')
    echo "Compiling the full proto tree (${#PROTOS[@]} files) with grpcio-tools $ACTUAL_GRPCIO_TOOLS..."
fi

# Resolve protoc-gen-mypy from the active Python environment
MYPY_PLUGIN="$(python -c 'import sys; print(sys.prefix)')/bin/protoc-gen-mypy"

python -m grpc_tools.protoc \
    --proto_path="$PROTO_SRC" \
    --python_out="$PROTO_OUT" \
    --grpc_python_out="$PROTO_OUT" \
    --mypy_out="$PROTO_OUT" \
    --plugin="protoc-gen-mypy=${MYPY_PLUGIN}" \
    "${PROTOS[@]}"

echo "Proto compilation complete. Output: $PROTO_OUT"
