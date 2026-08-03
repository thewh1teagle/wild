#!/usr/bin/env python3
"""Byte-identity oracle for PE linker architecture migrations.

This is a correctness harness, not a performance benchmark. It replays the
four frozen Goal 3 PE corpora through a pinned reference and a candidate,
records complete provenance, and requires byte-identical output at every
requested thread count.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
DEFAULT_CORPORA_ROOT = Path("/home/yakov/Documents/wild-goal3-corpora")
CORPUS_NAMES = ("ruststd", "ripgrep", "rust-analyzer", "uv")
HELPER_NAME = "dgx-corpus_001.py"


class OracleError(RuntimeError):
    """The byte oracle cannot safely continue."""


@dataclass(frozen=True)
class Tool:
    role: str
    path: Path
    sha256: str
    tree: dict[str, Any] | None
    dump_args: tuple[str, ...]


@dataclass(frozen=True)
class FrozenCorpus:
    name: str
    base: Path
    root: Path
    cwd: Path
    response: Path
    metadata_path: Path
    manifest_path: Path
    metadata: dict[str, Any]
    manifest: dict[str, Any]
    inventory: dict[str, Any]
    command_template: tuple[str, ...]
    replay_environment: dict[str, str]
    materialized_sha256: str


def load_capture_helper() -> Any:
    path = Path(__file__).resolve().with_name(HELPER_NAME)
    if not path.is_file():
        raise OracleError(f"required corpus helper is missing: {path}")
    spec = importlib.util.spec_from_file_location("wild_dgx_corpus_helper", path)
    if spec is None or spec.loader is None:
        raise OracleError(f"cannot load corpus helper: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CAPTURE = load_capture_helper()


def sha256_file(path: Path) -> str:
    return CAPTURE.sha256_file(path)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def read_json(path: Path, description: str) -> dict[str, Any]:
    if not path.is_file():
        raise OracleError(f"missing {description}: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OracleError(f"invalid {description} {path}: {error}") from error
    if not isinstance(value, dict):
        raise OracleError(f"{description} must be a JSON object: {path}")
    return value


def ensure_beneath(path: Path, root: Path, description: str) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise OracleError(f"{description} escapes frozen corpus: {path}") from error
    return resolved


def validate_manifest(root: Path, expected: dict[str, Any]) -> str:
    actual = CAPTURE.corpus_manifest(root)
    expected_summary = {
        "file_count": expected.get("file_count"),
        "total_bytes": expected.get("total_bytes"),
        "sha256": expected.get("sha256"),
    }
    if actual.metadata() != expected_summary or actual.files != expected.get("files"):
        raise OracleError(
            f"frozen corpus manifest mismatch at {root}: "
            f"expected {expected_summary}, got {actual.metadata()}"
        )
    return actual.sha256


def load_frozen_corpora(root: Path, template_key: str) -> list[FrozenCorpus]:
    root = root.resolve()
    inventory_path = root / "evidence/protocol/corpus-inventory.json"
    inventory = read_json(inventory_path, "frozen corpus inventory")
    if inventory.get("status") != "complete-and-frozen-before-authority-timing":
        raise OracleError("corpus inventory is not in the frozen complete state")
    entries = inventory.get("corpora")
    if not isinstance(entries, dict) or set(CORPUS_NAMES) - set(entries):
        raise OracleError("corpus inventory does not contain all four required corpora")

    corpora: list[FrozenCorpus] = []
    for name in CORPUS_NAMES:
        entry = entries[name].get("pe")
        if not isinstance(entry, dict):
            raise OracleError(f"inventory has no PE entry for {name}")
        base = root / "frozen" / name / "pe"
        metadata_path = base / "metadata.json"
        manifest_path = base / "manifest.json"
        if sha256_file(metadata_path) != entry.get("metadata_sha256"):
            raise OracleError(f"frozen metadata SHA-256 mismatch for {name}")
        if sha256_file(manifest_path) != entry.get("manifest_sha256"):
            raise OracleError(f"frozen manifest SHA-256 mismatch for {name}")
        metadata = read_json(metadata_path, f"{name} metadata")
        manifest = read_json(manifest_path, f"{name} manifest")
        if metadata.get("format") != "pe":
            raise OracleError(f"{name} metadata is not a PE corpus")
        corpus_meta = metadata.get("corpus")
        replay = metadata.get("replay")
        if not isinstance(corpus_meta, dict) or not isinstance(replay, dict):
            raise OracleError(f"{name} metadata lacks corpus/replay records")
        corpus_root = ensure_beneath(base / str(corpus_meta.get("directory")), base, "corpus root")
        if not corpus_root.is_dir():
            raise OracleError(f"missing materialized corpus for {name}: {corpus_root}")
        materialized = validate_manifest(corpus_root, manifest)
        if materialized != entry.get("materialized_corpus_sha256"):
            raise OracleError(f"materialized corpus SHA-256 mismatch for {name}")
        working = replay.get("working_directory")
        response_name = replay.get("response_file")
        commands = replay.get("commands")
        if not isinstance(working, str) or not isinstance(response_name, str):
            raise OracleError(f"{name} replay lacks cwd/response file")
        if not isinstance(commands, dict) or not isinstance(commands.get(template_key), list):
            raise OracleError(f"{name} replay lacks command template {template_key!r}")
        template = commands[template_key]
        if not template or not all(isinstance(item, str) for item in template):
            raise OracleError(f"{name} command template is malformed")
        cwd = ensure_beneath(corpus_root / working, corpus_root, "replay cwd")
        response = ensure_beneath(cwd / response_name, corpus_root, "response file")
        if not cwd.is_dir() or not response.is_file():
            raise OracleError(f"{name} replay cwd/response is missing")
        response_meta = corpus_meta.get("response")
        if not isinstance(response_meta, dict):
            raise OracleError(f"{name} has no frozen response metadata")
        if sha256_file(response) != response_meta.get("sha256"):
            raise OracleError(f"{name} response SHA-256 differs from metadata")
        if sha256_file(response) != entry.get("invocation_sha256"):
            raise OracleError(f"{name} response SHA-256 differs from inventory")
        replay_env = replay.get("environment", {})
        if not isinstance(replay_env, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in replay_env.items()
        ):
            raise OracleError(f"{name} replay environment is malformed")
        corpora.append(
            FrozenCorpus(
                name=name,
                base=base,
                root=corpus_root,
                cwd=cwd,
                response=response,
                metadata_path=metadata_path,
                manifest_path=manifest_path,
                metadata=metadata,
                manifest=manifest,
                inventory=entry,
                command_template=tuple(template),
                replay_environment=dict(replay_env),
                materialized_sha256=materialized,
            )
        )
    return corpora


def resolve_tree(value: str | None) -> dict[str, Any] | None:
    if value is None:
        return None
    path = Path(value)
    if not path.exists():
        return {"declared": value, "resolved": False}
    root = path.resolve()
    if root.is_file():
        root = root.parent
    completed = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD", "HEAD^{tree}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode or len(completed.stdout.splitlines()) != 2:
        raise OracleError(f"cannot resolve Git identity for tree {value!r}")
    commit, tree = completed.stdout.splitlines()
    dirty = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=False,
    )
    if dirty.returncode:
        raise OracleError(f"cannot inspect Git status for tree {value!r}")
    return {
        "declared": value,
        "resolved": True,
        "root": str(root),
        "commit": commit,
        "tree": tree,
        "dirty": bool(dirty.stdout),
    }


def resolve_tool(
    role: str,
    value: Path,
    expected_sha256: str | None,
    tree: str | None,
    dump_args: list[str],
) -> Tool:
    path = value.expanduser().resolve()
    try:
        mode = path.stat().st_mode
    except OSError as error:
        raise OracleError(f"missing {role} linker: {path}") from error
    if not stat.S_ISREG(mode) or not os.access(path, os.X_OK):
        raise OracleError(f"{role} linker is not an executable regular file: {path}")
    digest = sha256_file(path)
    if expected_sha256 is not None and digest.casefold() != expected_sha256.casefold():
        raise OracleError(
            f"{role} linker SHA-256 mismatch: expected {expected_sha256}, got {digest}"
        )
    return Tool(role, path, digest, resolve_tree(tree), tuple(dump_args))


def parse_threads(value: str, n_threads: int | None) -> list[int]:
    maximum = n_threads or os.cpu_count()
    if maximum is None or maximum <= 0:
        raise OracleError("cannot resolve N thread count; pass --n-threads")
    values: list[int] = []
    for token in value.split(","):
        token = token.strip()
        number = maximum if token.casefold() == "n" else int(token)
        if number <= 0:
            raise OracleError("thread counts must be positive")
        if number not in values:
            values.append(number)
    if not values:
        raise OracleError("at least one thread count is required")
    return values


def substitute(value: str, output: Path, threads: int, dump: Path) -> str:
    return (
        value.replace("${OUTPUT}", str(output))
        .replace("${THREADS}", str(threads))
        .replace("${DUMP}", str(dump))
    )


def controlled_environment(
    corpus: FrozenCorpus, output: Path, threads: int, dump: Path, temp: Path
) -> dict[str, str]:
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "TMPDIR": str(temp),
        "TZ": "UTC",
    }
    for key, value in corpus.replay_environment.items():
        environment[key] = substitute(value, output, threads, dump)
    return environment


def command_for(
    corpus: FrozenCorpus, tool: Tool, output: Path, threads: int, dump: Path
) -> list[str]:
    command = [
        str(tool.path),
        *(substitute(item, output, threads, dump) for item in corpus.command_template[1:]),
        *(substitute(item, output, threads, dump) for item in tool.dump_args),
    ]
    if not any(item == f"@{corpus.response.name}" for item in command):
        raise OracleError(f"{corpus.name} replay does not preserve its response file token")
    if str(output) not in "\0".join(command):
        raise OracleError(f"{corpus.name} replay command has no output substitution")
    return command


def binary_record(data: bytes, path: Path) -> dict[str, Any]:
    path.write_bytes(data)
    return {
        "path": path.name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "base64": base64.b64encode(data).decode("ascii"),
    }


def inspect_pe(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise OracleError(f"output is not a DOS/PE image: {path}")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe + 24 > len(data) or data[pe : pe + 4] != b"PE\0\0":
        raise OracleError(f"output has no valid PE signature: {path}")
    machine, sections, timestamp = struct.unpack_from("<HHI", data, pe + 4)
    optional_size, characteristics = struct.unpack_from("<HH", data, pe + 20)
    optional = pe + 24
    if optional + optional_size > len(data) or optional_size < 112:
        raise OracleError(f"output has a truncated optional header: {path}")
    magic = struct.unpack_from("<H", data, optional)[0]
    if machine != 0x8664 or magic != 0x20B:
        raise OracleError(f"output is not AMD64 PE32+: {path}")
    count = struct.unpack_from("<I", data, optional + 108)[0]
    directory_base = optional + 112

    def directory(index: int) -> dict[str, int | bool]:
        if index >= count or directory_base + (index + 1) * 8 > optional + optional_size:
            return {"rva": 0, "size": 0, "present": False}
        rva, size = struct.unpack_from("<II", data, directory_base + index * 8)
        return {"rva": rva, "size": size, "present": bool(rva and size)}

    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "machine": "IMAGE_FILE_MACHINE_AMD64",
        "section_count": sections,
        "coff_timestamp": timestamp,
        "characteristics": characteristics,
        "entry_point_rva": struct.unpack_from("<I", data, optional + 16)[0],
        "image_base": struct.unpack_from("<Q", data, optional + 24)[0],
        "size_of_image": struct.unpack_from("<I", data, optional + 56)[0],
        "checksum": struct.unpack_from("<I", data, optional + 64)[0],
        "subsystem": struct.unpack_from("<H", data, optional + 68)[0],
        "dll_characteristics": struct.unpack_from("<H", data, optional + 70)[0],
        "data_directories": {
            "exports": directory(0),
            "imports": directory(1),
            "exception": directory(3),
            "base_relocations": directory(5),
            "debug": directory(6),
            "tls": directory(9),
            "load_config": directory(10),
            "iat": directory(12),
            "delay_imports": directory(13),
        },
    }


def first_difference(left: Path, right: Path) -> int | None:
    offset = 0
    with left.open("rb") as lhs, right.open("rb") as rhs:
        while True:
            a = lhs.read(1024 * 1024)
            b = rhs.read(1024 * 1024)
            if a == b:
                if not a:
                    return None
                offset += len(a)
                continue
            for index, (x, y) in enumerate(zip(a, b)):
                if x != y:
                    return offset + index
            return offset + min(len(a), len(b))


def run_one(
    corpus: FrozenCorpus,
    tool: Tool,
    threads: int,
    directory: Path,
    timeout: float,
) -> dict[str, Any]:
    directory.mkdir(parents=True)
    output = directory / "output.exe"
    dump = directory / "resolution.dump"
    temp = directory / "tmp"
    temp.mkdir()
    command = command_for(corpus, tool, output, threads, dump)
    environment = controlled_environment(corpus, output, threads, dump, temp)
    started_ns = time.time_ns()
    timed_out = False
    try:
        completed = subprocess.run(
            command,
            cwd=corpus.cwd,
            env=environment,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        status = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as error:
        timed_out = True
        status = None
        stdout = error.stdout or b""
        stderr = error.stderr or b""
    ended_ns = time.time_ns()
    stdout_record = binary_record(stdout, directory / "stdout.bin")
    stderr_record = binary_record(stderr, directory / "stderr.bin")
    artifact = None
    artifact_error = None
    if output.is_file():
        try:
            artifact = inspect_pe(output)
        except OracleError as error:
            artifact_error = str(error)
    dump_record = None
    if tool.dump_args:
        if dump.is_file():
            dump_record = {
                "path": dump.name,
                "bytes": dump.stat().st_size,
                "sha256": sha256_file(dump),
            }
        else:
            artifact_error = (artifact_error + "; " if artifact_error else "") + (
                "configured resolution dump was not produced"
            )
    return {
        "corpus": corpus.name,
        "role": tool.role,
        "threads": threads,
        "command": command,
        "cwd": str(corpus.cwd),
        "environment": environment,
        "environment_sha256": hashlib.sha256(canonical_json(environment)).hexdigest(),
        "started_unix_ns": started_ns,
        "ended_unix_ns": ended_ns,
        "exit_status": status,
        "timed_out": timed_out,
        "stdout": stdout_record,
        "stderr": stderr_record,
        "artifact": artifact,
        "artifact_error": artifact_error,
        "resolution_dump": dump_record,
        "success": status == 0 and not timed_out and artifact is not None and artifact_error is None,
    }


def compare_runs(reference: dict[str, Any], candidate: dict[str, Any], directory: Path) -> dict[str, Any]:
    ref_artifact = reference.get("artifact")
    candidate_artifact = candidate.get("artifact")
    identical = bool(
        reference["success"]
        and candidate["success"]
        and ref_artifact["sha256"] == candidate_artifact["sha256"]
    )
    difference = None
    if reference["success"] and candidate["success"] and not identical:
        difference = first_difference(
            directory / "reference/output.exe", directory / "candidate/output.exe"
        )
    ref_dump = reference.get("resolution_dump")
    candidate_dump = candidate.get("resolution_dump")
    dumps_identical = None
    if ref_dump is not None or candidate_dump is not None:
        dumps_identical = bool(
            ref_dump is not None
            and candidate_dump is not None
            and ref_dump["sha256"] == candidate_dump["sha256"]
        )
    return {
        "byte_identical": identical,
        "first_differing_offset": difference,
        "metadata_identical": bool(
            reference["success"]
            and candidate["success"]
            and ref_artifact == candidate_artifact
        ),
        "resolution_dumps_identical": dumps_identical,
        "passed": identical and dumps_identical is not False,
    }


def dry_run_plan(corpora: list[FrozenCorpus], tools: list[Tool], threads: list[int]) -> dict[str, Any]:
    runs = []
    fake_root = Path("${EVIDENCE_ROOT}")
    for corpus in corpora:
        for count in threads:
            for tool in tools:
                output = fake_root / corpus.name / str(count) / tool.role / "output.exe"
                dump = output.with_name("resolution.dump")
                runs.append(
                    {
                        "corpus": corpus.name,
                        "role": tool.role,
                        "threads": count,
                        "cwd": str(corpus.cwd),
                        "response_sha256": sha256_file(corpus.response),
                        "command": command_for(corpus, tool, output, count, dump),
                    }
                )
    return {"schema_version": SCHEMA_VERSION, "dry_run": True, "runs": runs}


def execute_oracle(
    corpora: list[FrozenCorpus],
    reference: Tool,
    candidate: Tool,
    threads: list[int],
    output_dir: Path,
    timeout: float,
) -> tuple[dict[str, Any], bool]:
    output_dir = output_dir.resolve()
    for corpus in corpora:
        try:
            output_dir.relative_to(corpus.base)
        except ValueError:
            pass
        else:
            raise OracleError("evidence output must not be inside a frozen corpus")
    if output_dir.exists():
        raise OracleError(f"evidence output already exists: {output_dir}")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=output_dir.parent))
    try:
        runs: list[dict[str, Any]] = []
        comparisons: list[dict[str, Any]] = []
        for corpus in corpora:
            for count in threads:
                pair = stage / "artifacts" / corpus.name / f"threads-{count}"
                reference_run = run_one(corpus, reference, count, pair / "reference", timeout)
                candidate_run = run_one(corpus, candidate, count, pair / "candidate", timeout)
                runs.extend([reference_run, candidate_run])
                comparison = compare_runs(reference_run, candidate_run, pair)
                comparison.update({"corpus": corpus.name, "threads": count})
                comparisons.append(comparison)

        post_hashes = {corpus.name: validate_manifest(corpus.root, corpus.manifest) for corpus in corpora}
        mutation_free = all(
            post_hashes[corpus.name] == corpus.materialized_sha256 for corpus in corpora
        )
        deterministic: dict[str, dict[str, bool]] = {}
        for corpus in corpora:
            deterministic[corpus.name] = {}
            for role in ("reference", "candidate"):
                hashes = [
                    run["artifact"]["sha256"]
                    for run in runs
                    if run["role"] == role
                    and run["corpus"] == corpus.name
                    and run["success"]
                ]
                deterministic[corpus.name][role] = len(hashes) == len(threads) and len(set(hashes)) == 1
        passed = mutation_free and all(item["passed"] for item in comparisons) and all(
            value for corpus_values in deterministic.values() for value in corpus_values.values()
        )
        report = {
            "schema_version": SCHEMA_VERSION,
            "kind": "PE architecture migration byte-identity oracle",
            "passed": passed,
            "created_unix_ns": time.time_ns(),
            "host": {"node": platform.node(), "platform": platform.platform(), "python": sys.version},
            "threads": threads,
            "tools": {
                tool.role: {
                    "path": str(tool.path),
                    "bytes": tool.path.stat().st_size,
                    "sha256": tool.sha256,
                    "tree": tool.tree,
                    "dump_args": list(tool.dump_args),
                }
                for tool in (reference, candidate)
            },
            "corpora": [
                {
                    "name": corpus.name,
                    "base": str(corpus.base),
                    "cwd": str(corpus.cwd),
                    "response": str(corpus.response),
                    "response_sha256": sha256_file(corpus.response),
                    "manifest_path": str(corpus.manifest_path),
                    "manifest_file_sha256": sha256_file(corpus.manifest_path),
                    "materialized_sha256_before": corpus.materialized_sha256,
                    "materialized_sha256_after": post_hashes[corpus.name],
                }
                for corpus in corpora
            ],
            "mutation_free": mutation_free,
            "deterministic_across_threads": deterministic,
            "runs": runs,
            "comparisons": comparisons,
            "resolution_dump_note": (
                "Dump equality is mandatory when dump args are configured; current Wild has no "
                "stable selected-member dump flag, so the hook is opt-in."
            ),
        }
        (stage / "report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.replace(stage, output_dir)
        return report, passed
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def minimal_pe() -> bytes:
    data = bytearray(0x200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 0, 0, 0, 0, 0xF0, 0x22)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<I", data, optional + 56, 0x1000)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<I", data, optional + 108, 16)
    return bytes(data)


class OracleSelfTests(unittest.TestCase):
    def test_missing_json_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.json"
            with self.assertRaisesRegex(OracleError, "missing test input"):
                read_json(missing, "test input")

    def test_manifest_mutation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "input.obj"
            artifact.write_bytes(b"frozen")
            captured = CAPTURE.corpus_manifest(root)
            expected = {**captured.metadata(), "files": captured.files}
            self.assertEqual(validate_manifest(root, expected), captured.sha256)
            artifact.write_bytes(b"mutated")
            with self.assertRaisesRegex(OracleError, "manifest mismatch"):
                validate_manifest(root, expected)

    def test_threads_resolve_n_and_deduplicate(self) -> None:
        self.assertEqual(parse_threads("1,4,N,4", 12), [1, 4, 12])

    def test_pe_inspection_and_first_difference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.exe"
            second = root / "second.exe"
            first.write_bytes(minimal_pe())
            second.write_bytes(minimal_pe())
            self.assertEqual(inspect_pe(first)["machine"], "IMAGE_FILE_MACHINE_AMD64")
            self.assertIsNone(first_difference(first, second))
            changed = bytearray(minimal_pe())
            changed[-1] = 1
            second.write_bytes(changed)
            self.assertEqual(first_difference(first, second), len(changed) - 1)

    def test_command_preserves_response_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            response = root / "response.txt"
            response.write_text("/nologo\n", encoding="utf-8")
            corpus = FrozenCorpus(
                "test", root, root, root, response, root / "metadata.json", root / "manifest.json",
                {}, {}, {}, ("old", "@response.txt", "/out:${OUTPUT}", "/threads:${THREADS}"), {}, "x",
            )
            tool = Tool("candidate", Path("/bin/true"), "x", None, ())
            command = command_for(corpus, tool, root / "out.exe", 4, root / "dump")
            self.assertIn("@response.txt", command)
            self.assertIn("/threads:4", command)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--reference", type=Path, help="pinned reference Wild executable")
    value.add_argument("--candidate", type=Path, help="candidate Wild executable")
    value.add_argument("--reference-sha256", help="required reference executable pin")
    value.add_argument("--candidate-sha256", help="optional candidate executable pin")
    value.add_argument("--reference-tree", help="reference source tree path or declared identity")
    value.add_argument("--candidate-tree", help="candidate source tree path or declared identity")
    value.add_argument("--corpora-root", type=Path, default=DEFAULT_CORPORA_ROOT)
    value.add_argument("--template-key", default="wild", help="frozen replay command key")
    value.add_argument("--threads", default="1,4,N", help="comma-separated counts; N means host CPUs")
    value.add_argument("--n-threads", type=int, help="explicit value for N")
    value.add_argument("--timeout", type=float, default=120.0)
    value.add_argument("--output-dir", type=Path, help="new external evidence directory")
    value.add_argument("--reference-dump-arg", action="append", default=[], metavar="ARG")
    value.add_argument("--candidate-dump-arg", action="append", default=[], metavar="ARG")
    value.add_argument("--dry-run", action="store_true", help="verify inputs and print commands only")
    value.add_argument("--smoke", action="store_true", help="run first corpus at first thread count")
    value.add_argument("--self-test", action="store_true", help="run corpus-independent unit tests")
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(OracleSelfTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    if args.reference is None or args.candidate is None:
        raise OracleError("--reference and --candidate are required")
    if args.reference_sha256 is None:
        raise OracleError("--reference-sha256 is required to pin the oracle authority")
    if args.timeout <= 0:
        raise OracleError("--timeout must be positive")
    threads = parse_threads(args.threads, args.n_threads)
    corpora = load_frozen_corpora(args.corpora_root, args.template_key)
    reference = resolve_tool(
        "reference", args.reference, args.reference_sha256, args.reference_tree, args.reference_dump_arg
    )
    candidate = resolve_tool(
        "candidate", args.candidate, args.candidate_sha256, args.candidate_tree, args.candidate_dump_arg
    )
    if bool(reference.dump_args) != bool(candidate.dump_args):
        raise OracleError("resolution dump hooks must be configured for both tools or neither")
    if args.smoke:
        corpora = corpora[:1]
        threads = threads[:1]
    if args.dry_run:
        print(json.dumps(dry_run_plan(corpora, [reference, candidate], threads), indent=2, sort_keys=True))
        return 0
    if args.output_dir is None:
        raise OracleError("--output-dir is required unless --dry-run is used")
    report, passed = execute_oracle(
        corpora, reference, candidate, threads, args.output_dir, args.timeout
    )
    print(json.dumps({"passed": passed, "report": str(args.output_dir / "report.json")}))
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OracleError, OSError, ValueError) as error:
        print(f"pe-byte-oracle: {error}", file=sys.stderr)
        raise SystemExit(2)
