"""Guard against Protobuf gencode/runtime version drift in the generated stubs.

Every generated ``*_pb2.py`` opens with a hard runtime assertion::

    _runtime_version.ValidateProtobufRuntimeVersion(Domain.PUBLIC, 6, 31, 1, ...)

which raises ``VersionError`` at *import* time unless the protobuf runtime
installed alongside us is at least that version. The version is baked into the
file by whichever ``grpcio-tools`` produced it, so the stubs are only as
portable as the compiler that emitted them — and a stub compiled by a newer
compiler than the runtime we promise users is dead code on their install.

This is not hypothetical: 1.15.1-beta.6 shipped three stubs on the
``StreamHubDevice`` path recompiled by a newer ``grpcio-tools`` (gencode 7.35.1)
while the other 1611 stayed at 6.31.1. Home Assistant ships protobuf 6.x, so
importing those three raised ``VersionError`` on every install — taking the
whole rich per-device snapshot with it and reporting as "siren settings never
load" (#354). It had happened once before (cb57480) and was fixed by
recompiling, but nothing stopped it recurring.

The ``*_pb2_grpc.py`` stubs carry the same hazard through a second channel:
they stamp ``GRPC_GENERATED_VERSION`` and raise ``RuntimeError`` on import when
the installed ``grpcio`` is older. Both stamps are checked here.

The tests below close that loop by asserting the artifacts agree:

* every generated stub carries the version guard, and they all agree on one
  gencode version — a mixed set means a partial recompile with a different
  compiler;
* both stamped versions are satisfiable by the *oldest* runtime our
  ``manifest.json`` allows, so the floors we advertise are floors that actually
  work;
* ``grpcio-tools`` is pinned exactly, so regenerating a stub tomorrow cannot
  silently stamp a different version into it.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_COMPONENT = _REPO_ROOT / "custom_components" / "aegis_ajax"
_PROTO_ROOT = _COMPONENT / "proto"
_MANIFEST = _COMPONENT / "manifest.json"
_PYPROJECT = _REPO_ROOT / "pyproject.toml"

# The call is emitted across several lines, so match leniently on whitespace.
# Only the first three numbers matter: protobuf compares (major, minor, patch)
# and refuses to load a stub whose triple is newer than the runtime's.
_GUARD_RE = re.compile(
    r"ValidateProtobufRuntimeVersion\(\s*"
    r"[\w.]*Domain\.(?P<domain>\w+)\s*,\s*"
    r"(?P<major>\d+)\s*,\s*(?P<minor>\d+)\s*,\s*(?P<patch>\d+)\s*,",
)

# The gRPC service stubs stamp the grpcio they were built against and raise
# RuntimeError on import when the installed grpcio is older — the same hazard
# as the protobuf guard, through a second channel.
_GRPC_STAMP_RE = re.compile(
    r"^GRPC_GENERATED_VERSION = '(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)'",
    re.MULTILINE,
)

# Enough bytes to cover the header and the guard call in any generated stub.
_HEADER_BYTES = 2048


def _generated_stubs() -> list[Path]:
    return sorted(_PROTO_ROOT.rglob("*_pb2.py"))


def _gencode_versions() -> dict[tuple[int, int, int], list[Path]]:
    """Map each gencode version found in the stubs to the files declaring it."""
    by_version: dict[tuple[int, int, int], list[Path]] = {}
    for stub in _generated_stubs():
        with stub.open("r", encoding="utf-8") as handle:
            match = _GUARD_RE.search(handle.read(_HEADER_BYTES))
        if match is None:
            by_version.setdefault((-1, -1, -1), []).append(stub)
            continue
        version = (
            int(match["major"]),
            int(match["minor"]),
            int(match["patch"]),
        )
        by_version.setdefault(version, []).append(stub)
    return by_version


def _grpc_stamped_versions() -> dict[tuple[int, int, int], list[Path]]:
    """Map each stamped grpcio version to the service stubs demanding it."""
    by_version: dict[tuple[int, int, int], list[Path]] = {}
    for stub in sorted(_PROTO_ROOT.rglob("*_pb2_grpc.py")):
        with stub.open("r", encoding="utf-8") as handle:
            match = _GRPC_STAMP_RE.search(handle.read(_HEADER_BYTES))
        if match is None:
            continue
        version = (int(match["major"]), int(match["minor"]), int(match["patch"]))
        by_version.setdefault(version, []).append(stub)
    return by_version


def _requirement_floor(requirements: list[str], package: str) -> tuple[int, int, int]:
    """Parse the ``>=`` floor a requirements list declares for ``package``."""
    for requirement in requirements:
        match = re.fullmatch(
            rf"{re.escape(package)}\s*>=\s*(\d+)\.(\d+)(?:\.(\d+))?",
            requirement.strip(),
        )
        if match:
            return (int(match[1]), int(match[2]), int(match[3] or 0))
    raise AssertionError(
        f"No '{package}>=X.Y.Z' requirement found in {requirements!r}. This test "
        "needs one to know which runtime the generated stubs must load under."
    )


def _fmt(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def test_every_generated_stub_declares_the_runtime_guard() -> None:
    """A stub with no guard was built by a compiler we no longer use."""
    unguarded = _gencode_versions().get((-1, -1, -1), [])
    assert not unguarded, (
        f"{len(unguarded)} generated stub(s) carry no ValidateProtobufRuntimeVersion "
        "call, so they were emitted by a different protoc than the rest: "
        f"{[str(path.relative_to(_REPO_ROOT)) for path in unguarded[:5]]}. "
        "Recompile them with the pinned grpcio-tools (make proto)."
    )


def test_all_generated_stubs_share_one_gencode_version() -> None:
    """A mixed set means someone recompiled part of the tree with another protoc."""
    by_version = _gencode_versions()
    assert by_version, f"No generated *_pb2.py stubs found under {_PROTO_ROOT}"

    found = {version: files for version, files in by_version.items() if version != (-1, -1, -1)}
    if len(found) <= 1:
        return

    majority = max(found, key=lambda version: len(found[version]))
    detail = "; ".join(
        f"{_fmt(version)}: {len(files)} file(s) e.g. {files[0].relative_to(_REPO_ROOT)}"
        for version, files in sorted(found.items())
        if version != majority
    )
    raise AssertionError(
        f"Generated stubs declare {len(found)} different Protobuf gencode versions. "
        f"Most of the tree is on {_fmt(majority)}, but: {detail}. "
        "A partial recompile with a different grpcio-tools produces this, and any "
        "stub newer than the user's protobuf runtime raises VersionError on import "
        "(#354). Recompile the odd ones out with the pinned grpcio-tools."
    )


def test_gencode_version_is_loadable_by_the_advertised_protobuf_floor() -> None:
    """The oldest protobuf we tell HA we accept must be able to load our stubs."""
    manifest_floor = _requirement_floor(
        json.loads(_MANIFEST.read_text())["requirements"], "protobuf"
    )
    found = {version for version in _gencode_versions() if version != (-1, -1, -1)}
    assert found, "No gencode versions found to check against the manifest floor"

    newest = max(found)
    assert newest <= manifest_floor, (
        f"Generated stubs need protobuf >= {_fmt(newest)} but manifest.json only "
        f"requires protobuf >= {_fmt(manifest_floor)}. Protobuf refuses to load a "
        "stub newer than the runtime, so an install that resolves to the floor we "
        "advertise would fail at import. Either raise the manifest floor to "
        f"{_fmt(newest)} or recompile the stubs with an older grpcio-tools."
    )


def test_all_grpc_service_stubs_share_one_grpcio_version() -> None:
    """Same invariant as the protobuf gencode, for the gRPC service stubs."""
    by_version = _grpc_stamped_versions()
    assert by_version, f"No generated *_pb2_grpc.py stubs found under {_PROTO_ROOT}"
    if len(by_version) <= 1:
        return

    majority = max(by_version, key=lambda version: len(by_version[version]))
    detail = "; ".join(
        f"{_fmt(version)}: {len(files)} file(s) e.g. {files[0].relative_to(_REPO_ROOT)}"
        for version, files in sorted(by_version.items())
        if version != majority
    )
    raise AssertionError(
        f"Generated gRPC stubs stamp {len(by_version)} different grpcio versions. "
        f"Most of the tree is on {_fmt(majority)}, but: {detail}. Each stub raises "
        "RuntimeError on import when the installed grpcio is older than its stamp, "
        "so recompile the odd ones out with the pinned grpcio-tools."
    )


def test_grpc_stamp_is_loadable_by_the_advertised_grpcio_floor() -> None:
    """The oldest grpcio we tell HA we accept must be able to import our stubs."""
    manifest_floor = _requirement_floor(json.loads(_MANIFEST.read_text())["requirements"], "grpcio")
    stamped = set(_grpc_stamped_versions())
    assert stamped, "No grpcio stamps found to check against the manifest floor"

    newest = max(stamped)
    assert newest <= manifest_floor, (
        f"Generated gRPC stubs raise RuntimeError unless grpcio >= {_fmt(newest)}, but "
        f"manifest.json only requires grpcio >= {_fmt(manifest_floor)}. An install "
        "that resolves to the floor we advertise would fail at import. Either raise "
        f"the manifest floor to {_fmt(newest)} or recompile with an older grpcio-tools."
    )


def test_pyproject_mirrors_the_manifest_runtime_floors() -> None:
    """The dev environment must resolve the same runtime floors we ship against."""
    manifest_requirements = json.loads(_MANIFEST.read_text())["requirements"]
    pyproject_requirements = tomllib.loads(_PYPROJECT.read_text())["project"]["dependencies"]

    for package in ("protobuf", "grpcio"):
        manifest_floor = _requirement_floor(manifest_requirements, package)
        pyproject_floor = _requirement_floor(pyproject_requirements, package)
        assert pyproject_floor == manifest_floor, (
            f"pyproject.toml requires {package} >= {_fmt(pyproject_floor)} but "
            f"manifest.json requires >= {_fmt(manifest_floor)}. manifest.json is the "
            "source of truth Home Assistant reads; keep the mirror in step so tests "
            "run against the runtime users get."
        )


def test_grpcio_tools_is_pinned_exactly() -> None:
    """An unpinned compiler is what stamped a stray gencode version into #354."""
    pyproject = tomllib.loads(_PYPROJECT.read_text())
    dev_requirements = pyproject["project"]["optional-dependencies"]["dev"]
    grpcio_tools = [req for req in dev_requirements if req.strip().startswith("grpcio-tools")]

    assert grpcio_tools, "grpcio-tools is missing from the dev extra; nothing can compile protos"
    assert all("==" in req for req in grpcio_tools), (
        f"grpcio-tools must be pinned exactly, got {grpcio_tools!r}. The gencode "
        "version is baked into every generated stub, so a floating compiler makes "
        "codegen unreproducible: rebuilding the dev image silently changes what a "
        "regenerated stub demands of the user's protobuf runtime (#354)."
    )
