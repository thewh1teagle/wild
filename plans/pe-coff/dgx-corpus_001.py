#!/usr/bin/env python3
"""Capture immutable PE or ELF linker replay corpora on the DGX host.

The build command is supplied after ``--`` and is executed directly, without a
shell.  The literals ``{linker}``, ``{project}``, and ``{capture_root}`` in an
argument are replaced with paths owned by this capture.  This keeps quoting an
argv concern rather than a shell-programming concern.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = 1
PE_REQUIRED_FLAGS = ("/OPT:REF", "/OPT:NOICF", "/DEBUG:NONE")
ORIGINAL_OUTPUT_PREFIX = b"# Original output file: "


class CaptureError(RuntimeError):
    """A capture cannot safely or reproducibly continue."""


@dataclass(frozen=True)
class CorpusManifest:
    file_count: int
    total_bytes: int
    sha256: str
    files: list[dict[str, Any]]

    def metadata(self) -> dict[str, Any]:
        return {
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "sha256": self.sha256,
        }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def safe_relative_path(name: str) -> PurePosixPath:
    if not name or "\\" in name or name.startswith("/"):
        raise CaptureError(f"archive path is not a safe POSIX relative path: {name!r}")
    if re.match(r"^[A-Za-z]:", name):
        raise CaptureError(f"archive path contains a Windows drive prefix: {name!r}")
    raw_components = name.split("/")
    if any(component in ("", ".", "..") for component in raw_components):
        raise CaptureError(f"archive path contains traversal or ambiguity: {name!r}")
    path = PurePosixPath(name)
    return path


def regular_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise CaptureError(f"frozen corpus contains a symlink: {path}")
        if stat.S_ISREG(metadata.st_mode):
            files.append(path)
        elif not stat.S_ISDIR(metadata.st_mode):
            raise CaptureError(f"frozen corpus contains a special file: {path}")
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def corpus_manifest(root: Path) -> CorpusManifest:
    digest = hashlib.sha256()
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    for path in regular_files(root):
        relative = path.relative_to(root).as_posix()
        relative_bytes = relative.encode("utf-8")
        size = path.stat().st_size
        file_sha = sha256_file(path)
        digest.update(struct.pack("<Q", len(relative_bytes)))
        digest.update(relative_bytes)
        digest.update(struct.pack("<Q", size))
        digest.update(bytes.fromhex(file_sha))
        total_bytes += size
        entries.append({"path": relative, "bytes": size, "sha256": file_sha})
    if not entries:
        raise CaptureError(f"corpus contains no files: {root}")
    return CorpusManifest(len(entries), total_bytes, digest.hexdigest(), entries)


def materialize_tree(source: Path, destination: Path) -> None:
    """Copy a tree without retaining hardlinks or symlinks to mutable inputs."""

    def copy_entry(
        src: Path, dst: Path, directory_stack: frozenset[tuple[int, int]]
    ) -> None:
        metadata = src.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            try:
                target = src.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise CaptureError(
                    f"cannot resolve corpus symlink {src}: {error}"
                ) from error
            copy_entry(target, dst, directory_stack)
            return
        if stat.S_ISDIR(metadata.st_mode):
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in directory_stack:
                raise CaptureError(f"directory/symlink cycle while copying {src}")
            dst.mkdir(mode=0o755)
            next_stack = directory_stack | {identity}
            for child in sorted(src.iterdir(), key=lambda item: item.name):
                copy_entry(child, dst / child.name, next_stack)
            return
        if not stat.S_ISREG(metadata.st_mode):
            raise CaptureError(f"refusing to copy special file {src}")
        dst.parent.mkdir(parents=True, exist_ok=True)
        # copyfile always creates independent contents; copy2 could retain mutable metadata.
        shutil.copyfile(src, dst)
        os.chmod(dst, 0o755 if os.access(src, os.X_OK) else 0o644)

    if destination.exists():
        raise CaptureError(f"copy destination already exists: {destination}")
    copy_entry(source, destination, frozenset())


def inspect_tar(archive: Path) -> tuple[list[tarfile.TarInfo], str]:
    response_entries: list[str] = []
    with tarfile.open(archive, "r:*") as source:
        members = source.getmembers()
        if not members:
            raise CaptureError(f"archive is empty: {archive}")
        for member in members:
            relative = safe_relative_path(member.name.rstrip("/"))
            if not (member.isdir() or member.isfile()):
                raise CaptureError(
                    f"archive member must be a regular file or directory: {member.name!r}"
                )
            if relative.name.casefold() == "response.txt":
                if not member.isfile():
                    raise CaptureError("response.txt is not a regular file")
                response_entries.append(member.name)
    if len(response_entries) != 1:
        raise CaptureError(
            f"archive must contain exactly one response.txt; found {len(response_entries)}"
        )
    return members, response_entries[0]


def extract_safe(archive: Path, destination: Path) -> Path:
    members, response_name = inspect_tar(archive)
    destination.mkdir(mode=0o755)
    with tarfile.open(archive, "r:*") as source:
        for member in members:
            relative = safe_relative_path(member.name.rstrip("/"))
            output = destination.joinpath(*relative.parts)
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            extracted = source.extractfile(member)
            if extracted is None:
                raise CaptureError(f"cannot read archive member: {member.name}")
            with extracted, output.open("xb") as target:
                shutil.copyfileobj(extracted, target)
            os.chmod(output, 0o644)
    response = destination.joinpath(*safe_relative_path(response_name).parts)
    if not response.is_file():
        raise CaptureError("safe extraction did not produce response.txt")
    return response


def write_deterministic_tar(root: Path, archive: Path) -> None:
    paths = sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as output:
        root_info = tarfile.TarInfo("corpus")
        root_info.type = tarfile.DIRTYPE
        root_info.mode = 0o555
        root_info.mtime = root_info.uid = root_info.gid = 0
        root_info.uname = root_info.gname = ""
        output.addfile(root_info)
        for path in paths:
            relative = path.relative_to(root).as_posix()
            safe_relative_path(relative)
            metadata = path.lstat()
            info = tarfile.TarInfo(f"corpus/{relative}")
            info.mtime = info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.pax_headers = {}
            if stat.S_ISDIR(metadata.st_mode):
                info.type = tarfile.DIRTYPE
                info.mode = 0o555
                output.addfile(info)
            elif stat.S_ISREG(metadata.st_mode):
                info.type = tarfile.REGTYPE
                info.mode = 0o555 if metadata.st_mode & 0o111 else 0o444
                info.size = metadata.st_size
                with path.open("rb") as source:
                    output.addfile(info, source)
            else:
                raise CaptureError(f"cannot archive non-regular corpus entry: {path}")


def verify_corpus_archive(archive: Path, expected: CorpusManifest) -> None:
    with tempfile.TemporaryDirectory(prefix="wild-dgx-corpus-verify-") as directory:
        extracted = Path(directory)
        # A general corpus archive need not have response.txt, unlike an lld reproducer.
        with tarfile.open(archive, "r:*") as source:
            members = source.getmembers()
            for member in members:
                safe_relative_path(member.name.rstrip("/"))
                if not (member.isdir() or member.isfile()):
                    raise CaptureError(f"unsafe corpus archive member: {member.name}")
                output = extracted.joinpath(*PurePosixPath(member.name).parts)
                if member.isdir():
                    output.mkdir(parents=True, exist_ok=True)
                else:
                    output.parent.mkdir(parents=True, exist_ok=True)
                    stream = source.extractfile(member)
                    if stream is None:
                        raise CaptureError(f"cannot extract {member.name}")
                    with stream, output.open("xb") as target:
                        shutil.copyfileobj(stream, target)
        actual = corpus_manifest(extracted / "corpus")
        if actual.metadata() != expected.metadata() or actual.files != expected.files:
            raise CaptureError("corpus archive round-trip changed its file manifest")


def parse_key_value(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError(f"expected KEY=VALUE, got {value!r}")
    key, item = value.split("=", 1)
    if not key or "\0" in key or "\0" in item:
        raise argparse.ArgumentTypeError(f"invalid KEY=VALUE: {value!r}")
    return key, item


def unique_pairs(values: list[tuple[str, str]], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in values:
        if key in result:
            raise CaptureError(f"duplicate {label} key: {key}")
        result[key] = value
    return result


def substitute_command(
    command: list[str], *, linker: Path, project: Path, capture_root: Path
) -> list[str]:
    replacements = {
        "{linker}": str(linker),
        "{project}": str(project),
        "{capture_root}": str(capture_root),
    }
    expanded: list[str] = []
    for argument in command:
        for placeholder, replacement in replacements.items():
            argument = argument.replace(placeholder, replacement)
        expanded.append(argument)
    if not expanded:
        raise CaptureError("a build command is required after --")
    return expanded


def resolve_executable(value: str) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_file():
        return candidate.resolve()
    found = shutil.which(value)
    if found:
        return Path(found).resolve()
    raise CaptureError(f"executable not found: {value}")


def tool_metadata(name: str, executable: Path) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [str(executable), "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
            check=False,
        )
        version = result.stdout.decode(errors="replace").splitlines()
    except (OSError, subprocess.TimeoutExpired):
        version = []
    return {
        "name": name,
        "path": str(executable),
        "bytes": executable.stat().st_size,
        "sha256": sha256_file(executable),
        "version": version[0].strip() if version else "unknown",
    }


def git_source_metadata(
    project: Path, requested_revision: str, allow_dirty: bool
) -> dict[str, Any]:
    def git(*arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(project), *arguments],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode:
            raise CaptureError(
                f"git {' '.join(arguments)} failed for {project}: {result.stderr.strip()}"
            )
        return result.stdout.strip()

    head = git("rev-parse", "HEAD")
    resolved_requested = git("rev-parse", f"{requested_revision}^{{commit}}")
    if head != resolved_requested:
        raise CaptureError(
            f"requested source revision resolves to {resolved_requested}, but HEAD is {head}"
        )
    dirty_paths = git("status", "--porcelain", "--untracked-files=all").splitlines()
    if dirty_paths and not allow_dirty:
        raise CaptureError(
            "source tree is dirty; commit it or pass --allow-dirty explicitly"
        )
    return {
        "project": str(project),
        "requested_revision": requested_revision,
        "commit": head,
        "dirty": bool(dirty_paths),
        "dirty_status": dirty_paths,
    }


def write_pe_wrapper(
    path: Path, lld_link: Path, capture_root: Path, final_output: str
) -> None:
    configuration = {
        "lld_link": str(lld_link),
        "capture_root": str(capture_root),
        "final_output": final_output,
        "required_flags": list(PE_REQUIRED_FLAGS),
    }
    source = f"""#!/usr/bin/env python3
import json, os, pathlib, re, subprocess, sys
CONFIG = {configuration!r}

def output_name(argv):
    for arg in reversed(argv):
        match = re.match(r"^[/-]out:(.*)$", arg, re.IGNORECASE)
        if match:
            return pathlib.PureWindowsPath(match.group(1).strip('"')).name
    return None

argv = sys.argv[1:]
actual_output = output_name(argv)
selected = actual_output is not None and actual_output.casefold() == CONFIG["final_output"].casefold()
archive = pathlib.Path(CONFIG["capture_root"]) / "source-reproduce.tar"
marker = pathlib.Path(CONFIG["capture_root"]) / "selected-invocation.json"
if selected:
    try:
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print("DGX capture matched more than one final-link invocation", file=sys.stderr)
        sys.exit(97)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump({{"argv": argv, "output_name": output_name(argv)}}, stream)
        stream.write("\\n")
command = [CONFIG["lld_link"], *argv, *CONFIG["required_flags"]]
if selected:
    command.append("/reproduce:" + str(archive))
result = subprocess.run(command)
sys.exit(result.returncode)
"""
    path.write_text(source, encoding="utf-8")
    path.chmod(0o700)


def validate_pe_response(response: Path) -> None:
    data = response.read_bytes()
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise CaptureError(f"PE response.txt is not UTF-8: {error}") from error
    upper = text.upper()
    for flag in PE_REQUIRED_FLAGS:
        if flag not in upper:
            raise CaptureError(f"PE response.txt is missing enforced flag {flag}")
    debug_positions = [(upper.rfind("/DEBUG"), "debug")]
    none_position = upper.rfind("/DEBUG:NONE")
    if none_position != debug_positions[0][0]:
        raise CaptureError(
            "/DEBUG:NONE is not the final /DEBUG setting in response.txt"
        )
    ref_enabled: bool | None = None
    icf_enabled: bool | None = None
    for opt_token in re.findall(r"(?i)[/-]OPT:([^\r\n\s]+)", text):
        for setting in opt_token.split(","):
            setting = setting.split("=", 1)[0].casefold()
            if setting == "ref":
                ref_enabled = True
            elif setting == "noref":
                ref_enabled = False
            elif setting == "icf":
                icf_enabled = True
            elif setting == "noicf":
                icf_enabled = False
    if ref_enabled is not True:
        raise CaptureError("response does not end with /OPT:REF enabled")
    if icf_enabled is not False:
        raise CaptureError("response does not end with /OPT:NOICF")


def original_output(run_with: Path) -> str | None:
    for line in reversed(run_with.read_bytes().splitlines()):
        if line.startswith(ORIGINAL_OUTPUT_PREFIX):
            return line[len(ORIGINAL_OUTPUT_PREFIX) :].decode(
                "utf-8", errors="surrogateescape"
            )
    return None


def select_elf_save(save_base: Path, final_output: str) -> Path:
    matches: list[Path] = []
    for run_with in sorted(save_base.glob("*/run-with")):
        output = original_output(run_with)
        if output is not None and Path(output).name == final_output:
            matches.append(run_with.parent)
    if len(matches) != 1:
        raise CaptureError(
            f"expected exactly one ELF save-dir for output {final_output!r}; found {len(matches)}"
        )
    return matches[0]


def execute_build(
    command: list[str], project: Path, environment: dict[str, str], stage: Path
) -> None:
    stdout_path = stage / "build.stdout.log"
    stderr_path = stage / "build.stderr.log"
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        result = subprocess.run(
            command,
            cwd=project,
            env=environment,
            stdout=stdout,
            stderr=stderr,
            check=False,
        )
    if result.returncode:
        tail = stderr_path.read_bytes()[-8000:].decode(errors="replace")
        raise CaptureError(f"build command exited with {result.returncode}:\n{tail}")


def make_immutable(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            path.chmod(0o555)
        elif stat.S_ISREG(metadata.st_mode):
            path.chmod(0o555 if metadata.st_mode & 0o111 else 0o444)
    root.chmod(0o555)


def common_metadata(args: argparse.Namespace, command: list[str]) -> dict[str, Any]:
    project = args.project.expanduser().resolve()
    lockfile = args.lockfile.expanduser().resolve()
    if not lockfile.is_file():
        raise CaptureError(f"lockfile not found: {lockfile}")
    source = git_source_metadata(project, args.source_revision, args.allow_dirty)
    source["lockfile"] = {
        "path": str(lockfile),
        "bytes": lockfile.stat().st_size,
        "sha256": sha256_file(lockfile),
    }
    declared_tools = unique_pairs(args.tool, "tool")
    toolchain = {
        name: tool_metadata(name, resolve_executable(executable))
        for name, executable in declared_tools.items()
    }
    build_driver = resolve_executable(command[0])
    return {
        "schema_version": SCHEMA_VERSION,
        "source": source,
        "toolchain": {
            "build_driver": tool_metadata("build-driver", build_driver),
            "declared": toolchain,
        },
        "build": {
            "command": command,
            "profile": args.profile,
            "target": args.target,
            "features": args.feature,
            "labels": unique_pairs(args.label, "label"),
            "environment_overrides": unique_pairs(args.env, "environment"),
        },
    }


def capture(args: argparse.Namespace) -> Path:
    project = args.project.expanduser().resolve()
    if not project.is_dir():
        raise CaptureError(f"project directory not found: {project}")
    if (
        args.name in ("", ".", "..")
        or Path(args.name).name != args.name
        or "/" in args.name
        or "\\" in args.name
    ):
        raise CaptureError(f"capture name must be one path component: {args.name!r}")
    output_root = args.output_root.expanduser().resolve()
    if output_root == project or project in output_root.parents:
        raise CaptureError("output root must be outside the source project")
    output_root.mkdir(parents=True, exist_ok=True)
    destination = output_root / args.name
    if destination.exists():
        raise CaptureError(f"refusing to overwrite existing capture: {destination}")

    with tempfile.TemporaryDirectory(
        prefix=f".{args.name}-", dir=output_root
    ) as temporary:
        stage = Path(temporary)
        capture_root = stage / "capture"
        capture_root.mkdir()
        environment = os.environ.copy()
        environment.update(unique_pairs(args.env, "environment"))
        tools: dict[str, Any] = {}

        if args.format == "pe":
            lld_link = resolve_executable(args.lld_link)
            wild = resolve_executable(args.wild)
            wrapper = stage / "lld-link-capture"
            write_pe_wrapper(wrapper, lld_link, capture_root, args.final_output)
            command = substitute_command(
                args.build_command,
                linker=wrapper,
                project=project,
                capture_root=capture_root,
            )
            environment["DGX_CAPTURE_LINKER"] = str(wrapper)
            environment["DGX_CAPTURE_ROOT"] = str(capture_root)
            execute_build(command, project, environment, stage)
            archive = capture_root / "source-reproduce.tar"
            marker = capture_root / "selected-invocation.json"
            if not archive.is_file() or not marker.is_file():
                raise CaptureError(
                    "build did not invoke the capture linker exactly once for --final-output"
                )
            source_archive = stage / "source-reproduce.tar"
            shutil.copyfile(archive, source_archive)
            corpus = stage / "corpus"
            response = extract_safe(source_archive, corpus)
            validate_pe_response(response)
            tools = {
                "lld-link": tool_metadata("lld-link", lld_link),
                "wild": tool_metadata("wild", wild),
            }
            replay = {
                "working_directory": str(response.parent.relative_to(corpus)),
                "response_file": response.name,
                "commands": {
                    "lld-link": [
                        str(lld_link),
                        f"@{response.name}",
                        "/out:${OUTPUT}",
                        "/threads:${THREADS}",
                    ],
                    "wild": [
                        str(wild),
                        "-flavor",
                        "link",
                        f"@{response.name}",
                        "/out:${OUTPUT}",
                        "/threads:${THREADS}",
                    ],
                },
            }
            capture_specific = {
                "source_reproduce_archive": {
                    "file": source_archive.name,
                    "bytes": source_archive.stat().st_size,
                    "sha256": sha256_file(source_archive),
                },
                "response": {
                    "path": response.relative_to(corpus).as_posix(),
                    "bytes": response.stat().st_size,
                    "sha256": sha256_file(response),
                    "enforced_flags": list(PE_REQUIRED_FLAGS),
                },
                "selected_invocation": json.loads(marker.read_text(encoding="utf-8")),
            }
        else:
            wild = resolve_executable(args.wild)
            reference = resolve_executable(args.reference_linker)
            save_base = capture_root / "wild-save"
            command = substitute_command(
                args.build_command,
                linker=wild,
                project=project,
                capture_root=capture_root,
            )
            environment["WILD_SAVE_BASE"] = str(save_base)
            environment["DGX_CAPTURE_LINKER"] = str(wild)
            environment["DGX_CAPTURE_ROOT"] = str(capture_root)
            execute_build(command, project, environment, stage)
            selected = select_elf_save(save_base, args.final_output)
            corpus = stage / "corpus"
            materialize_tree(selected, corpus)
            run_with = corpus / "run-with"
            if not run_with.is_file():
                raise CaptureError("materialized ELF corpus has no run-with script")
            tools = {
                "wild": tool_metadata("wild", wild),
                "reference": tool_metadata("reference", reference),
            }
            replay = {
                "working_directory": ".",
                "environment": {"OUT": "${OUTPUT}"},
                "commands": {
                    "wild": ["./run-with", str(wild)],
                    "reference": ["./run-with", str(reference)],
                },
            }
            capture_specific = {
                "selected_save_dir": selected.name,
                "original_output": original_output(selected / "run-with"),
                "run_with": {
                    "path": "run-with",
                    "bytes": run_with.stat().st_size,
                    "sha256": sha256_file(run_with),
                },
            }

        manifest = corpus_manifest(corpus)
        atomic_json(
            stage / "manifest.json", {**manifest.metadata(), "files": manifest.files}
        )
        corpus_archive = stage / "corpus.tar"
        write_deterministic_tar(corpus, corpus_archive)
        verify_corpus_archive(corpus_archive, manifest)
        metadata = common_metadata(args, command)
        metadata.update(
            {
                "format": args.format,
                "name": args.name,
                "tools": tools,
                "corpus": {
                    **manifest.metadata(),
                    "directory": "corpus",
                    "archive": {
                        "file": corpus_archive.name,
                        "bytes": corpus_archive.stat().st_size,
                        "sha256": sha256_file(corpus_archive),
                        "round_trip_verified": True,
                    },
                    **capture_specific,
                },
                "replay": replay,
                "immutability": (
                    "all frozen corpus files are byte copies, never hardlinks; symlinks are "
                    "materialized; hashes are authoritative and files are made read-only"
                ),
            }
        )
        atomic_json(stage / "metadata.json", metadata)
        # The wrapper and transient capture directory are implementation details.
        shutil.rmtree(capture_root)
        wrapper = stage / "lld-link-capture"
        if wrapper.exists():
            wrapper.unlink()
        stage.replace(destination)
    make_immutable(destination)
    return destination


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--name", required=True, help="new directory name below output root"
    )
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--lockfile", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--feature", action="append", default=[])
    parser.add_argument("--label", action="append", type=parse_key_value, default=[])
    parser.add_argument("--env", action="append", type=parse_key_value, default=[])
    parser.add_argument(
        "--tool",
        action="append",
        type=parse_key_value,
        default=[],
        help="repeatable NAME=EXECUTABLE toolchain provenance entry",
    )
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument(
        "--final-output", required=True, help="basename of the final linked file"
    )
    parser.add_argument("--wild", required=True)
    parser.add_argument(
        "build_command",
        nargs=argparse.REMAINDER,
        help="build argv after --; use {linker}, {project}, and {capture_root}",
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--self-test", action="store_true")
    subcommands = result.add_subparsers(dest="format")
    pe = subcommands.add_parser("pe", help="capture an lld-link /reproduce archive")
    add_common_arguments(pe)
    pe.add_argument("--lld-link", required=True)
    elf = subcommands.add_parser(
        "elf", help="capture one Wild WILD_SAVE_BASE directory"
    )
    add_common_arguments(elf)
    elf.add_argument("--reference-linker", required=True)
    return result


class CaptureTests(unittest.TestCase):
    def make_git_project(self, root: Path) -> tuple[Path, str]:
        project = root / "project"
        project.mkdir()
        (project / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(project)], check=True)
        subprocess.run(
            ["git", "-C", str(project), "config", "user.email", "capture@test.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(project), "config", "user.name", "Capture Test"],
            check=True,
        )
        subprocess.run(["git", "-C", str(project), "add", "Cargo.lock"], check=True)
        subprocess.run(
            ["git", "-C", str(project), "commit", "-qm", "fixture"], check=True
        )
        revision = subprocess.check_output(
            ["git", "-C", str(project), "rev-parse", "HEAD"], text=True
        ).strip()
        return project, revision

    def write_executable(self, path: Path, source: str) -> None:
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)

    def common_args(
        self,
        *,
        root: Path,
        project: Path,
        revision: str,
        format_name: str,
        final_output: str,
        wild: Path,
        command: list[str],
    ) -> argparse.Namespace:
        return argparse.Namespace(
            name=f"fixture-{format_name}",
            output_root=root / "output",
            project=project,
            source_revision=revision,
            lockfile=project / "Cargo.lock",
            profile="release",
            target=(
                "x86_64-pc-windows-msvc"
                if format_name == "pe"
                else "x86_64-unknown-linux-gnu"
            ),
            feature=["fixture"],
            label=[("rustc", "fixture")],
            env=[],
            tool=[],
            allow_dirty=False,
            final_output=final_output,
            wild=str(wild),
            build_command=command,
            format=format_name,
            lld_link=None,
            reference_linker=None,
        )

    def make_writable(self, root: Path) -> None:
        if not root.exists():
            return
        for path in [root, *root.rglob("*")]:
            if path.is_dir():
                path.chmod(0o755)
            elif path.is_file():
                path.chmod(0o644)

    def test_command_substitution_preserves_argv_and_spaces(self) -> None:
        command = substitute_command(
            ["cargo", "arg with spaces", "-Clinker={linker}", "{project}/Cargo.toml"],
            linker=Path("/tmp/linker with space"),
            project=Path("/src/project with space"),
            capture_root=Path("/capture"),
        )
        self.assertEqual(
            command,
            [
                "cargo",
                "arg with spaces",
                "-Clinker=/tmp/linker with space",
                "/src/project with space/Cargo.toml",
            ],
        )

    def test_archive_path_rejections(self) -> None:
        for invalid in ("../escape", "/absolute", "C:/drive", "a\\b", "a/../b", "./a"):
            with self.subTest(invalid=invalid), self.assertRaises(CaptureError):
                safe_relative_path(invalid)
        self.assertEqual(
            safe_relative_path("root/a file.obj").as_posix(), "root/a file.obj"
        )

    def test_manifest_is_path_and_content_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "b").write_bytes(b"two")
            (root / "a").write_bytes(b"one")
            first = corpus_manifest(root)
            second = corpus_manifest(root)
            self.assertEqual(first, second)
            self.assertEqual([entry["path"] for entry in first.files], ["a", "b"])

    def test_materialize_breaks_hardlinks_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            original = source / "input.o"
            original.write_bytes(b"before")
            os.link(original, source / "hard.o")
            (source / "symbolic.o").symlink_to(original)
            frozen = root / "frozen"
            materialize_tree(source, frozen)
            original.write_bytes(b"after")
            self.assertEqual((frozen / "input.o").read_bytes(), b"before")
            self.assertEqual((frozen / "hard.o").read_bytes(), b"before")
            self.assertEqual((frozen / "symbolic.o").read_bytes(), b"before")
            self.assertFalse((frozen / "symbolic.o").is_symlink())

    def test_reproducer_preserves_response_bytes_and_rejects_links(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            response_bytes = b'/OUT:"a b.exe"\n/OPT:REF\n/OPT:NOICF\n/DEBUG:NONE\n'
            good = root / "good.tar"
            with tarfile.open(good, "w") as archive:
                info = tarfile.TarInfo("repro/response.txt")
                info.size = len(response_bytes)
                import io

                archive.addfile(info, io.BytesIO(response_bytes))
            extracted = root / "extracted"
            response = extract_safe(good, extracted)
            self.assertEqual(response.read_bytes(), response_bytes)
            validate_pe_response(response)

            bad = root / "bad.tar"
            with tarfile.open(bad, "w") as archive:
                info = tarfile.TarInfo("repro/response.txt")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                archive.addfile(info)
            with self.assertRaises(CaptureError):
                inspect_tar(bad)

    def test_deterministic_archive_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = root / "input"
            corpus.mkdir()
            (corpus / "response.txt").write_bytes(b"exact\r\nbytes\n")
            (corpus / "sub").mkdir()
            (corpus / "sub" / "quoted file.o").write_bytes(b"object")
            expected = corpus_manifest(corpus)
            first, second = root / "first.tar", root / "second.tar"
            write_deterministic_tar(corpus, first)
            write_deterministic_tar(corpus, second)
            self.assertEqual(sha256_file(first), sha256_file(second))
            verify_corpus_archive(first, expected)

    def test_select_elf_save_by_original_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, output in ((0, "/tmp/build-script"), (1, "/tmp/rg")):
                save = root / str(index)
                save.mkdir()
                (save / "run-with").write_bytes(
                    b"#!/bin/bash\n" + ORIGINAL_OUTPUT_PREFIX + output.encode() + b"\n"
                )
            self.assertEqual(select_elf_save(root, "rg"), root / "1")
            with self.assertRaises(CaptureError):
                select_elf_save(root, "missing")

    def test_end_to_end_fake_pe_capture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project, revision = self.make_git_project(root)
            fake_lld = root / "lld-link"
            fake_wild = root / "wild"
            self.write_executable(
                fake_wild,
                "#!/usr/bin/env python3\nimport sys\n"
                "print('Wild fixture') if '--version' in sys.argv else None\n",
            )
            self.write_executable(
                fake_lld,
                """#!/usr/bin/env python3
import io, pathlib, sys, tarfile
if '--version' in sys.argv:
    print('LLD fixture')
    raise SystemExit(0)
archive = next((a.split(':', 1)[1] for a in sys.argv if a.lower().startswith('/reproduce:')), None)
if archive:
    response = ('\\n'.join(sys.argv[1:]) + '\\n').encode()
    with tarfile.open(archive, 'w') as output:
        info = tarfile.TarInfo('repro/response.txt')
        info.size = len(response)
        output.addfile(info, io.BytesIO(response))
raise SystemExit(0)
""",
            )
            args = self.common_args(
                root=root,
                project=project,
                revision=revision,
                format_name="pe",
                final_output="App Name.exe",
                wild=fake_wild,
                command=["{linker}", '/OUT:"app name.exe"'],
            )
            args.lld_link = str(fake_lld)
            try:
                destination = capture(args)
                metadata = json.loads((destination / "metadata.json").read_text())
                self.assertEqual(metadata["format"], "pe")
                self.assertEqual(
                    metadata["corpus"]["response"]["enforced_flags"],
                    list(PE_REQUIRED_FLAGS),
                )
                self.assertTrue(metadata["corpus"]["archive"]["round_trip_verified"])
            finally:
                self.make_writable(root / "output")

    def test_end_to_end_fake_elf_capture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project, revision = self.make_git_project(root)
            fake_wild = root / "wild"
            fake_reference = root / "ld.lld"
            self.write_executable(
                fake_reference,
                "#!/usr/bin/env python3\nimport sys\nprint('LLD fixture')\n",
            )
            self.write_executable(
                fake_wild,
                """#!/usr/bin/env python3
import os, pathlib, sys
if '--version' in sys.argv:
    print('Wild fixture')
    raise SystemExit(0)
save = pathlib.Path(os.environ['WILD_SAVE_BASE']) / '0'
save.mkdir(parents=True)
(save / 'input.o').write_bytes(b'object')
(save / 'run-with').write_bytes(b'#!/bin/bash\\n# Original output file: /tmp/rg\\n')
(save / 'run-with').chmod(0o755)
""",
            )
            args = self.common_args(
                root=root,
                project=project,
                revision=revision,
                format_name="elf",
                final_output="rg",
                wild=fake_wild,
                command=["{linker}", "-o", "/tmp/rg"],
            )
            args.reference_linker = str(fake_reference)
            try:
                destination = capture(args)
                metadata = json.loads((destination / "metadata.json").read_text())
                self.assertEqual(metadata["format"], "elf")
                self.assertEqual(metadata["corpus"]["original_output"], "/tmp/rg")
                self.assertEqual(
                    (destination / "corpus" / "input.o").read_bytes(), b"object"
                )
            finally:
                self.make_writable(root / "output")


def main() -> int:
    args = parser().parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(CaptureTests)
        return (
            0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
        )
    if args.format is None:
        parser().error("choose pe or elf (or pass --self-test)")
    # argparse.REMAINDER retains a conventional separator.
    if args.build_command[:1] == ["--"]:
        args.build_command = args.build_command[1:]
    try:
        destination = capture(args)
    except (
        CaptureError,
        OSError,
        subprocess.SubprocessError,
        tarfile.TarError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
