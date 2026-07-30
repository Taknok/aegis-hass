#!/usr/bin/env python3
"""Import every generated protobuf stub and report the ones that fail.

Why this exists as a separate script rather than a unit test: the dev image
installs the *newest* protobuf and grpcio that satisfy our floors, and a stub is
only unloadable when the runtime is *older* than the compiler that produced it.
So the environment that runs the test suite is structurally unable to reproduce
the failure that shipped in the 1.15.1 betas (#354) — the tests passed on every
Python version while the integration was broken on every install.

CI runs this in a throwaway container pinned to the exact floors
``manifest.json`` advertises, which is the oldest runtime a user can end up
with. Whatever passes here is a claim we have actually executed.

    python3 scripts/check_proto_imports.py --floors   # print "protobuf==X grpcio==Y"
    python3 scripts/check_proto_imports.py            # import every stub
"""

from __future__ import annotations

import json
import re
import sys
import traceback
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_COMPONENT = _REPO_ROOT / "custom_components" / "aegis_ajax"
_PROTO_ROOT = _COMPONENT / "proto"
_MANIFEST = _COMPONENT / "manifest.json"

_FLOOR_PACKAGES = ("protobuf", "grpcio")


def _requirement_floors() -> list[str]:
    """Return ``package==floor`` pins for the runtimes manifest.json advertises."""
    requirements = json.loads(_MANIFEST.read_text())["requirements"]
    pins = []
    for package in _FLOOR_PACKAGES:
        for requirement in requirements:
            match = re.fullmatch(rf"{re.escape(package)}\s*>=\s*(\S+)", requirement.strip())
            if match:
                pins.append(f"{package}=={match.group(1)}")
                break
        else:
            raise SystemExit(f"manifest.json declares no '{package}>=' requirement")
    return pins


def _module_names() -> list[str]:
    """Dotted module names for every generated stub, in import order."""
    names = []
    for pattern in ("*_pb2.py", "*_pb2_grpc.py"):
        for stub in sorted(_PROTO_ROOT.rglob(pattern)):
            relative = stub.relative_to(_PROTO_ROOT).with_suffix("")
            names.append(".".join(relative.parts))
    return names


def _import_all() -> int:
    import importlib

    # The stubs import each other by the paths they were compiled with, so the
    # proto root has to be importable as-is — the same thing the integration
    # does at runtime.
    sys.path.insert(0, str(_PROTO_ROOT))

    modules = _module_names()
    failures: list[tuple[str, str]] = []
    for name in modules:
        try:
            importlib.import_module(name)
        except Exception:  # noqa: BLE001 - reporting, not handling
            failures.append((name, traceback.format_exc(limit=3)))

    import google.protobuf
    import grpc

    print(f"protobuf {google.protobuf.__version__}, grpcio {grpc.__version__}")
    print(f"imported {len(modules) - len(failures)}/{len(modules)} generated stubs")

    if failures:
        print(f"\n{len(failures)} stub(s) failed to import:\n")
        for name, detail in failures[:10]:
            print(f"--- {name}\n{detail}")
        if len(failures) > 10:
            print(f"... and {len(failures) - 10} more")
        print(
            "A VersionError here means the stubs were compiled by a newer "
            "grpcio-tools than the runtime floor manifest.json advertises. "
            "Recompile with the pinned compiler (make proto) or raise the floor."
        )
        return 1
    return 0


def main() -> int:
    if "--floors" in sys.argv[1:]:
        print(" ".join(_requirement_floors()))
        return 0
    return _import_all()


if __name__ == "__main__":
    sys.exit(main())
