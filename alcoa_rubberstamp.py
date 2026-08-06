#!/usr/bin/env python3
"""ALCOA RubberStamp v1.0.0: deterministic file-set commitments.

The tool creates a shareable manifest for a directory, optionally binds the
commitment to an independently verifiable prior state, and can optionally ask
OpenTimestamps to timestamp the commitment file.

No network operation occurs unless ``--ots`` or ``--ots-receipt`` is supplied.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


TOOL_NAME = "alcoa-rubberstamp"
TOOL_VERSION = "1.0.0"
MANIFEST_SCHEMA = "hmic.alcoa-rubberstamp.manifest/v1"
PRIOR_STATE_SCHEMA = "hmic.sgap.prior-state/v1"
COMMITMENT_ALGORITHM = "sgap-file-set-merkle-sha256-v1"

LEAF_DOMAIN = b"ALCOA-RUBBERSTAMP-FILE-V1\0"
NODE_DOMAIN = b"ALCOA-RUBBERSTAMP-NODE-V1\0"
COMMITMENT_DOMAIN = b"ALCOA-RUBBERSTAMP-COMMITMENT-V1\0"
NO_PRIOR_STATE = bytes(32)

EXIT_USAGE = 2
EXIT_VERIFY_FAILED = 3
EXIT_OTS_FAILED = 4
EXIT_INPUT_CHANGED = 5


class RubberStampError(RuntimeError):
    """Expected operational failure with a stable command-line exit code."""

    def __init__(self, message: str, exit_code: int = 1):
        super().__init__(message)
        self.exit_code = exit_code


def utc_now() -> str:
    """Return an RFC 3339 UTC timestamp with second precision."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json_bytes(value: Any) -> bytes:
    """Encode JSON using the release's canonical byte representation."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_file(path: Path) -> tuple[str, int]:
    """Hash one stable regular file and return (hex digest, byte size)."""
    before = path.stat()
    if not path.is_file() or path.is_symlink():
        raise RubberStampError(f"not a regular non-symlink file: {path}", EXIT_INPUT_CHANGED)
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    after = path.stat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise RubberStampError(f"file changed while hashing: {path}", EXIT_INPUT_CHANGED)
    return digest.hexdigest(), size


def normalize_relative_path(relative: Path) -> str:
    """Return the cross-platform path representation committed by v1."""
    parts: list[str] = []
    for raw_part in relative.parts:
        if raw_part in ("", ".", ".."):
            raise RubberStampError(f"unsafe relative path component: {raw_part!r}")
        if "\\" in raw_part or "\x00" in raw_part:
            raise RubberStampError(
                f"path cannot be represented portably by schema v1: {relative}"
            )
        part = unicodedata.normalize("NFC", raw_part)
        parts.append(part)
    if not parts:
        raise RubberStampError("empty relative path")
    return "/".join(parts)


def _path_is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _excluded_relative_dirs(root: Path, out_dir: Path) -> list[str]:
    if not _path_is_within(out_dir, root):
        return []
    relative = out_dir.relative_to(root)
    if not relative.parts:
        raise RubberStampError("output directory cannot be the root being committed", EXIT_USAGE)
    return [normalize_relative_path(relative)]


def collect_records(root: Path, excluded_relative_dirs: Iterable[str] = ()) -> list[dict[str, Any]]:
    """Collect sorted records while rejecting ambiguous portable paths."""
    root = root.resolve()
    if not root.is_dir():
        raise RubberStampError(f"root is not a directory: {root}", EXIT_USAGE)

    excluded = tuple(item.rstrip("/") for item in excluded_relative_dirs)
    records: list[dict[str, Any]] = []
    portable_names: dict[str, str] = {}

    def register_portable_name(relative: str) -> None:
        collision_key = relative.casefold()
        prior = portable_names.get(collision_key)
        if prior is not None and prior != relative:
            raise RubberStampError(
                f"portable path collision after NFC/case folding: {prior!r} and {relative!r}"
            )
        portable_names[collision_key] = relative

    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)

        kept_dirs: list[str] = []
        for dirname in dirnames:
            candidate = current_path / dirname
            relative = normalize_relative_path(candidate.relative_to(root))
            if candidate.is_symlink():
                raise RubberStampError(f"symbolic links are not supported: {relative}")
            if any(relative == item or relative.startswith(item + "/") for item in excluded):
                continue
            register_portable_name(relative)
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        for filename in filenames:
            candidate = current_path / filename
            relative = normalize_relative_path(candidate.relative_to(root))
            if any(relative == item or relative.startswith(item + "/") for item in excluded):
                continue
            if candidate.is_symlink():
                raise RubberStampError(f"symbolic links are not supported: {relative}")

            register_portable_name(relative)
            digest, size = sha256_file(candidate)
            records.append({"path": relative, "sha256": digest, "size": size})

    records.sort(key=lambda record: record["path"].encode("utf-8"))
    if not records:
        raise RubberStampError("no files remain after excluding the output directory", EXIT_USAGE)
    return records


def file_leaf(record: dict[str, Any]) -> bytes:
    path_bytes = record["path"].encode("utf-8")
    size_bytes = str(record["size"]).encode("ascii")
    hash_bytes = bytes.fromhex(record["sha256"])
    return hashlib.sha256(
        LEAF_DOMAIN + path_bytes + b"\0" + size_bytes + b"\0" + hash_bytes
    ).digest()


def merkle_root(records: list[dict[str, Any]]) -> bytes:
    """Build a domain-separated binary Merkle root; odd nodes duplicate."""
    layer = [file_leaf(record) for record in records]
    if not layer:
        raise RubberStampError("cannot commit an empty file set")
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [
            hashlib.sha256(NODE_DOMAIN + layer[index] + layer[index + 1]).digest()
            for index in range(0, len(layer), 2)
        ]
    return layer[0]


def validate_prior_state(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise RubberStampError("prior-state document must be a JSON object", EXIT_USAGE)
    required = {"schema", "source", "identifier", "observed_at_utc"}
    allowed = required | {"evidence_uri"}
    missing = required - set(value)
    extra = set(value) - allowed
    if missing:
        raise RubberStampError(f"prior-state document is missing: {', '.join(sorted(missing))}", EXIT_USAGE)
    if extra:
        raise RubberStampError(f"prior-state document has unsupported keys: {', '.join(sorted(extra))}", EXIT_USAGE)
    if value["schema"] != PRIOR_STATE_SCHEMA:
        raise RubberStampError(f"unsupported prior-state schema: {value['schema']!r}", EXIT_USAGE)
    for key in required - {"schema"}:
        if not isinstance(value[key], str) or not value[key].strip():
            raise RubberStampError(f"prior-state {key} must be a non-empty string", EXIT_USAGE)
    timestamp = value["observed_at_utc"]
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RubberStampError("prior-state observed_at_utc must be RFC 3339", EXIT_USAGE) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise RubberStampError("prior-state observed_at_utc must be expressed in UTC", EXIT_USAGE)
    if "evidence_uri" in value and not isinstance(value["evidence_uri"], str):
        raise RubberStampError("prior-state evidence_uri must be a string", EXIT_USAGE)
    return {key: value[key] for key in sorted(value)}


def load_prior_state(path: Path | None) -> tuple[dict[str, str] | None, bytes]:
    if path is None:
        return None, NO_PRIOR_STATE
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RubberStampError(f"cannot read prior-state JSON: {exc}", EXIT_USAGE) from exc
    normalized = validate_prior_state(value)
    return normalized, hashlib.sha256(canonical_json_bytes(normalized)).digest()


def commitment_for(records: list[dict[str, Any]], prior_state_digest: bytes = NO_PRIOR_STATE) -> tuple[str, str]:
    if len(prior_state_digest) != 32:
        raise RubberStampError("prior-state digest must be 32 bytes")
    tree = merkle_root(records)
    commitment = hashlib.sha256(COMMITMENT_DOMAIN + tree + prior_state_digest).hexdigest()
    return tree.hex(), commitment


def build_manifest(
    records: list[dict[str, Any]],
    excluded_relative_dirs: list[str],
    prior_state: dict[str, str] | None,
    prior_state_digest: bytes,
) -> dict[str, Any]:
    tree_hex, commitment = commitment_for(records, prior_state_digest)
    lower = None
    if prior_state is not None:
        lower = {
            "status": "candidate",
            "basis": "operator-supplied prior-state binding",
            "observed_at_utc": prior_state["observed_at_utc"],
            "warning": "Valid only if the prior state is independently authentic and unpredictable before observation.",
        }
    return {
        "schema": MANIFEST_SCHEMA,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "created_at_utc": utc_now(),
        "commitment": {
            "algorithm": COMMITMENT_ALGORITHM,
            "value": commitment,
            "file_tree_root": tree_hex,
            "prior_state_digest": prior_state_digest.hex() if prior_state is not None else None,
        },
        "time_bounds": {
            "lower_bound": lower,
            "upper_bound": {
                "status": "not_established",
                "warning": "An OpenTimestamps receipt establishes an upper bound only after independent verification and calendar upgrade.",
            },
        },
        "prior_state": prior_state,
        "excluded_relative_directories": excluded_relative_dirs,
        "file_count": len(records),
        "total_bytes": sum(record["size"] for record in records),
        "files": records,
    }


def write_release_files(out_dir: Path, manifest: dict[str, Any]) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    manifest_path = out_dir / f"alcoa-manifest-{stamp}.json"
    commitment_path = out_dir / f"alcoa-commitment-{stamp}.txt"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    commitment_path.write_text(manifest["commitment"]["value"] + "\n", encoding="ascii")
    return manifest_path, commitment_path


def run_ots_stamp(commitment_path: Path) -> Path:
    try:
        result = subprocess.run(
            ["ots", "stamp", str(commitment_path)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RubberStampError("OpenTimestamps CLI 'ots' was not found", EXIT_OTS_FAILED) from exc
    except subprocess.TimeoutExpired as exc:
        raise RubberStampError("OpenTimestamps stamp timed out", EXIT_OTS_FAILED) from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown error").strip()
        raise RubberStampError(f"OpenTimestamps stamp failed: {detail}", EXIT_OTS_FAILED)
    receipt = Path(str(commitment_path) + ".ots")
    if not receipt.is_file():
        raise RubberStampError("OpenTimestamps reported success but created no receipt", EXIT_OTS_FAILED)
    return receipt


def run_ots_verify(receipt_path: Path) -> str:
    try:
        result = subprocess.run(
            ["ots", "verify", str(receipt_path)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RubberStampError("OpenTimestamps CLI 'ots' was not found", EXIT_OTS_FAILED) from exc
    except subprocess.TimeoutExpired as exc:
        raise RubberStampError("OpenTimestamps verification timed out", EXIT_OTS_FAILED) from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown error").strip()
        raise RubberStampError(f"OpenTimestamps verification failed: {detail}", EXIT_OTS_FAILED)
    return (result.stdout or result.stderr).strip()


def validate_manifest_shape(manifest: Any) -> dict[str, Any]:
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        raise RubberStampError("unsupported or missing manifest schema", EXIT_VERIFY_FAILED)
    if manifest.get("tool", {}).get("version") != TOOL_VERSION:
        raise RubberStampError("manifest tool version is not supported by this verifier", EXIT_VERIFY_FAILED)
    if manifest.get("commitment", {}).get("algorithm") != COMMITMENT_ALGORITHM:
        raise RubberStampError("unsupported commitment algorithm", EXIT_VERIFY_FAILED)
    if not isinstance(manifest.get("files"), list):
        raise RubberStampError("manifest files must be a list", EXIT_VERIFY_FAILED)
    records = manifest["files"]
    paths: list[str] = []
    portable_keys: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "size"}:
            raise RubberStampError(f"manifest file record {index} has an invalid shape", EXIT_VERIFY_FAILED)
        path = record["path"]
        if not isinstance(path, str):
            raise RubberStampError(f"manifest file record {index} has an invalid path", EXIT_VERIFY_FAILED)
        try:
            normalized = normalize_relative_path(Path(*path.split("/")))
        except RubberStampError as exc:
            raise RubberStampError(f"manifest path is invalid: {exc}", EXIT_VERIFY_FAILED) from exc
        if normalized != path or path.startswith("/") or "//" in path:
            raise RubberStampError(f"manifest path is not canonical: {path!r}", EXIT_VERIFY_FAILED)
        portable_key = path.casefold()
        if portable_key in portable_keys:
            raise RubberStampError(f"manifest contains a duplicate portable path: {path!r}", EXIT_VERIFY_FAILED)
        portable_keys.add(portable_key)
        paths.append(path)
        digest = record["sha256"]
        if not isinstance(digest, str) or len(digest) != 64:
            raise RubberStampError(f"manifest hash is invalid for {path}", EXIT_VERIFY_FAILED)
        try:
            bytes.fromhex(digest)
        except ValueError as exc:
            raise RubberStampError(f"manifest hash is invalid for {path}", EXIT_VERIFY_FAILED) from exc
        if not isinstance(record["size"], int) or isinstance(record["size"], bool) or record["size"] < 0:
            raise RubberStampError(f"manifest size is invalid for {path}", EXIT_VERIFY_FAILED)
    if paths != sorted(paths, key=lambda item: item.encode("utf-8")):
        raise RubberStampError("manifest files are not in canonical path order", EXIT_VERIFY_FAILED)
    return manifest


def verify_tree(root: Path, manifest: dict[str, Any]) -> list[str]:
    manifest = validate_manifest_shape(manifest)
    errors: list[str] = []
    expected_records = manifest["files"]
    try:
        actual_records = collect_records(root, manifest.get("excluded_relative_directories", []))
    except RubberStampError as exc:
        return [str(exc)]

    expected = {record["path"]: record for record in expected_records}
    actual = {record["path"]: record for record in actual_records}
    for path in sorted(expected.keys() - actual.keys()):
        errors.append(f"missing: {path}")
    for path in sorted(actual.keys() - expected.keys()):
        errors.append(f"added: {path}")
    for path in sorted(expected.keys() & actual.keys()):
        if expected[path].get("size") != actual[path]["size"]:
            errors.append(f"size changed: {path}")
        if expected[path].get("sha256") != actual[path]["sha256"]:
            errors.append(f"content changed: {path}")

    prior_state = manifest.get("prior_state")
    try:
        if prior_state is None:
            prior_digest = NO_PRIOR_STATE
        else:
            normalized = validate_prior_state(prior_state)
            prior_digest = hashlib.sha256(canonical_json_bytes(normalized)).digest()
        tree_hex, commitment = commitment_for(expected_records, prior_digest)
    except (RubberStampError, KeyError, TypeError, ValueError) as exc:
        errors.append(f"manifest commitment inputs invalid: {exc}")
        return errors

    stored = manifest["commitment"]
    if stored.get("file_tree_root") != tree_hex:
        errors.append("manifest file_tree_root does not recompute")
    if stored.get("value") != commitment:
        errors.append("manifest commitment does not recompute")
    expected_prior_hex = prior_digest.hex() if prior_state is not None else None
    if stored.get("prior_state_digest") != expected_prior_hex:
        errors.append("manifest prior_state_digest does not recompute")
    if manifest.get("file_count") != len(expected_records):
        errors.append("manifest file_count is inconsistent")
    if manifest.get("total_bytes") != sum(record.get("size", 0) for record in expected_records):
        errors.append("manifest total_bytes is inconsistent")
    return errors


def command_create(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    out_dir = Path(args.out).resolve() if args.out else root / "stamps"
    excluded = _excluded_relative_dirs(root, out_dir)
    prior_state, prior_digest = load_prior_state(Path(args.prior_state) if args.prior_state else None)
    records = collect_records(root, excluded)
    manifest = build_manifest(records, excluded, prior_state, prior_digest)
    manifest_path, commitment_path = write_release_files(out_dir, manifest)
    print(f"manifest: {manifest_path}")
    print(f"commitment: {commitment_path}")
    print(f"files: {manifest['file_count']}")
    print(f"sha256: {manifest['commitment']['value']}")
    if prior_state is None:
        print("time claim: none (no prior-state binding; no verified external timestamp)")
    else:
        print("lower-bound candidate: bound to supplied prior state; authenticity not validated by this tool")
    if args.ots:
        receipt = run_ots_stamp(commitment_path)
        print(f"ots receipt: {receipt}")
        print("upper-bound candidate: receipt must be upgraded and independently verified")
    return 0


def command_verify(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).resolve()
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RubberStampError(f"cannot read manifest: {exc}", EXIT_VERIFY_FAILED) from exc
    errors = verify_tree(Path(args.root).resolve(), manifest)
    if args.commitment_file:
        try:
            value = Path(args.commitment_file).read_text(encoding="ascii").strip()
        except OSError as exc:
            errors.append(f"cannot read commitment file: {exc}")
        else:
            if value != manifest.get("commitment", {}).get("value"):
                errors.append("commitment file does not match manifest")
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return EXIT_VERIFY_FAILED
    print("file-set verification: PASS")
    print(f"sha256: {manifest['commitment']['value']}")
    if args.ots_receipt:
        output = run_ots_verify(Path(args.ots_receipt).resolve())
        print("OpenTimestamps verification: PASS")
        if output:
            print(output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {TOOL_VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="create a manifest and deterministic commitment")
    create.add_argument("--root", required=True, help="directory whose regular files will be committed")
    create.add_argument("--out", help="artifact directory; defaults to <root>/stamps")
    create.add_argument("--prior-state", help="optional prior-state JSON document")
    create.add_argument("--ots", action="store_true", help="submit the commitment file to OpenTimestamps")
    create.set_defaults(handler=command_create)

    verify = subparsers.add_parser("verify", help="recompute and compare a manifest")
    verify.add_argument("--root", required=True, help="directory to verify")
    verify.add_argument("--manifest", required=True, help="manifest JSON produced by create")
    verify.add_argument("--commitment-file", help="optional commitment text file to compare")
    verify.add_argument("--ots-receipt", help="optional .ots receipt to verify using the ots CLI")
    verify.set_defaults(handler=command_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except RubberStampError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    sys.exit(main())
