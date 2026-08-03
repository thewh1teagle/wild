#!/usr/bin/env python3
"""Measure a representative Rust std PE link through lld-link and Wild."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

TARGET = "x86_64-pc-windows-msvc"
SOURCE = """\
use std::collections::BTreeMap;

fn main() {
    let values = (0_u64..4096).map(|value| (value, value.rotate_left(7)));
    let table: BTreeMap<_, _> = values.collect();
    let checksum = table.values().copied().fold(0_u64, u64::wrapping_add);
    println!("wild-pe-perf {checksum}");
}
"""


class ProbeError(RuntimeError):
    pass


class ProbeTimeout(ProbeError):
    def __init__(
        self, label: str, limit: float, elapsed: float, stdout: str, stderr: str
    ):
        super().__init__(
            f"{label} exceeded {limit:.3f}s (elapsed {elapsed:.3f}s); "
            f"stdout={stdout[-2000:]!r}; stderr={stderr[-2000:]!r}"
        )
        self.label = label
        self.limit = limit
        self.elapsed = elapsed


@dataclass(frozen=True)
class CommandResult:
    command: list[str]
    elapsed_seconds: float
    stdout: str
    stderr: str


def resolve_tool(
    explicit: str | None, environment: str, names: tuple[str, ...]
) -> Path:
    for candidate in (explicit, os.environ.get(environment), *names):
        if not candidate:
            continue
        path = Path(candidate).expanduser()
        if path.is_file():
            # Preserve rustup proxy names: resolving `rustc` or `cargo` to the
            # shared `rustup` binary changes argv[0] and breaks dispatch.
            return path.absolute()
        found = shutil.which(candidate)
        if found:
            return Path(found).absolute()
    option = environment.lower().replace("_", "-")
    raise ProbeError(
        f"could not find {'/'.join(names)}; pass --{option} or set {environment}"
    )


def timed_run(
    command: list[str],
    timeout: float,
    label: str,
    cwd: Path,
    extra_env: dict[str, str] | None = None,
) -> CommandResult:
    started = time.perf_counter()
    process = subprocess.Popen(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name != "nt",
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        env={**os.environ, "LC_ALL": "C", **(extra_env or {})},
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        elapsed = time.perf_counter() - started
        raise ProbeTimeout(label, timeout, elapsed, stdout, stderr)
    elapsed = time.perf_counter() - started
    if process.returncode:
        raise ProbeError(
            f"{label} exited with {process.returncode} after {elapsed:.3f}s; "
            f"stdout={stdout[-2000:]!r}; stderr={stderr[-2000:]!r}"
        )
    return CommandResult(command, elapsed, stdout, stderr)


def version(tool: Path, repository: Path) -> str:
    result = timed_run([str(tool), "--version"], 15, f"probe {tool.name}", repository)
    return (result.stdout or result.stderr).splitlines()[0].strip()


def xwin_library_paths(root: Path) -> list[Path]:
    paths = [
        root / "crt/lib/x86_64",
        root / "sdk/lib/ucrt/x86_64",
        root / "sdk/lib/um/x86_64",
    ]
    missing = [str(path) for path in paths if not path.is_dir()]
    if missing:
        raise ProbeError(f"xwin library directories are missing: {', '.join(missing)}")
    return [path.resolve() for path in paths]


def rust_command(
    rustc: Path, source: Path, linker: Path, output: Path, library_paths: list[Path]
) -> list[str]:
    command = [
        str(rustc),
        "--crate-name",
        "wild_pe_perf",
        "--edition=2021",
        "--target",
        TARGET,
        str(source),
        "-C",
        "opt-level=1",
        "-C",
        "debuginfo=0",
        "-C",
        f"linker={linker}",
    ]
    for path in library_paths:
        command.extend(["-C", f"link-arg=/libpath:{path}"])
    command.extend(["-o", str(output)])
    return command


def inspect_pe(path: Path, llvm_readobj: Path, repository: Path) -> dict[str, Any]:
    if not path.is_file() or path.read_bytes()[:2] != b"MZ":
        raise ProbeError(f"linker did not produce a DOS/PE image at {path}")
    inspection = timed_run(
        [str(llvm_readobj), "--file-headers", "--coff-imports", str(path)],
        30,
        f"inspect {path.name}",
        repository,
    ).stdout
    if "IMAGE_FILE_MACHINE_AMD64" not in inspection:
        raise ProbeError(f"{path} is not an AMD64 image")
    if "Import {" not in inspection:
        raise ProbeError(f"{path} has no readable PE imports")
    data = path.read_bytes()
    return {
        "file": path.name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "machine": "IMAGE_FILE_MACHINE_AMD64",
        "import_records": inspection.count("Import {"),
    }


def run_probe(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    repository = Path(__file__).resolve().parents[2]
    cargo = resolve_tool(args.cargo, "CARGO", ("cargo",))
    rustc = resolve_tool(args.rustc, "RUSTC", ("rustc",))
    lld_link = resolve_tool(args.lld_link, "LLD_LINK", ("lld-link",))
    llvm_readobj = resolve_tool(
        args.llvm_readobj,
        "LLVM_READOBJ",
        ("llvm-readobj", *(f"llvm-readobj-{version}" for version in range(22, 14, -1))),
    )
    xwin_root = args.xwin_root.expanduser().resolve()
    library_paths = xwin_library_paths(xwin_root)
    target_dir = args.cargo_target_dir.expanduser().resolve()

    target_libdir = timed_run(
        [str(rustc), "--print", "target-libdir", "--target", TARGET],
        15,
        "locate Rust target library",
        repository,
    ).stdout.strip()
    target_libraries = Path(target_libdir) if target_libdir else None
    if (
        target_libraries is None
        or not target_libraries.is_dir()
        or not any(target_libraries.glob("libstd-*.rlib"))
    ):
        raise ProbeError(f"Rust target {TARGET} is not installed for {rustc}")

    build = timed_run(
        [
            str(cargo),
            "build",
            "--profile",
            "ci",
            "-p",
            "wild-linker",
            "--no-default-features",
            "--features",
            "pe",
            "--target-dir",
            str(target_dir),
        ],
        args.build_timeout_seconds,
        "build Wild",
        repository,
        extra_env={"RUSTC": str(rustc)},
    )
    wild_binary = target_dir / "ci" / ("wild.exe" if os.name == "nt" else "wild")
    if not wild_binary.is_file():
        raise ProbeError(f"Wild build did not produce {wild_binary}")

    report: dict[str, Any] = {
        "schema_version": 1,
        "status": "running",
        "target": TARGET,
        "tools": {
            "cargo": version(cargo, repository),
            "rustc": version(rustc, repository),
            "lld_link": version(lld_link, repository),
            "llvm_readobj": version(llvm_readobj, repository),
            "wild": str(wild_binary),
        },
        "xwin_root": str(xwin_root),
        "limits": {
            "build_timeout_seconds": args.build_timeout_seconds,
            "link_timeout_seconds": args.link_timeout_seconds,
            "wild_budget_seconds": args.wild_budget_seconds,
        },
        "timings_seconds": {"wild_build": round(build.elapsed_seconds, 6)},
        "images": {},
    }

    with tempfile.TemporaryDirectory(prefix="wild-pe-perf-") as temporary:
        work = Path(temporary)
        source = work / "rust_std.rs"
        source.write_text(SOURCE, encoding="utf-8")
        wild_link = work / "link.exe"
        shutil.copy2(wild_binary, wild_link)
        wild_link.chmod(wild_link.stat().st_mode | 0o111)

        outputs = {
            "lld-link": work / "lld-link.exe",
            "wild": work / "wild.exe",
        }
        links: dict[str, CommandResult] = {}
        links["lld-link"] = timed_run(
            rust_command(rustc, source, lld_link, outputs["lld-link"], library_paths),
            args.link_timeout_seconds,
            "compile and link Rust std with lld-link",
            repository,
        )
        report["timings_seconds"]["lld_link_rustc"] = round(
            links["lld-link"].elapsed_seconds, 6
        )
        report["images"]["lld-link"] = inspect_pe(
            outputs["lld-link"], llvm_readobj, repository
        )
        wild_limit = min(args.link_timeout_seconds, args.wild_budget_seconds)
        try:
            links["wild"] = timed_run(
                rust_command(rustc, source, wild_link, outputs["wild"], library_paths),
                wild_limit,
                "compile and link Rust std with Wild",
                repository,
            )
        except ProbeTimeout as error:
            if args.wild_budget_seconds <= args.link_timeout_seconds:
                report["status"] = "budget-exceeded"
                report["failure"] = {
                    "kind": "timeout",
                    "label": error.label,
                    "limit_seconds": error.limit,
                    "elapsed_seconds": round(error.elapsed, 6),
                }
                report["timings_seconds"]["wild_rustc_lower_bound"] = round(
                    error.elapsed, 6
                )
                return report, 1
            raise

        report["images"]["wild"] = inspect_pe(outputs["wild"], llvm_readobj, repository)
        if args.keep_artifacts:
            destination = args.keep_artifacts.expanduser().resolve()
            if destination.exists():
                raise ProbeError(
                    f"--keep-artifacts destination already exists: {destination}"
                )
            shutil.copytree(work, destination)
            for image in report["images"].values():
                image["path"] = str(destination / image["file"])

        wild_elapsed = links["wild"].elapsed_seconds
        within_budget = wild_elapsed <= args.wild_budget_seconds
        report["status"] = "pass" if within_budget else "budget-exceeded"
        report["timings_seconds"].update(
            {
                "wild_rustc": round(wild_elapsed, 6),
                "wild_over_lld_ratio": round(
                    wild_elapsed / links["lld-link"].elapsed_seconds, 6
                ),
            }
        )
        return report, 0 if within_budget else 1


def positive_seconds(
    parser: argparse.ArgumentParser, value: float, option: str
) -> None:
    if value <= 0:
        parser.error(f"{option} must be positive")


def main() -> int:
    repository = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", help="cargo executable")
    parser.add_argument("--rustc", help="rustc executable")
    parser.add_argument("--lld-link", help="lld-link executable")
    parser.add_argument("--llvm-readobj", help="llvm-readobj executable")
    parser.add_argument(
        "--xwin-root",
        type=Path,
        default=Path(os.environ.get("XWIN_ROOT", "~/.xwin")),
        help="xwin root (default: XWIN_ROOT or ~/.xwin)",
    )
    parser.add_argument(
        "--cargo-target-dir",
        type=Path,
        default=repository / "target",
        help="Cargo target directory",
    )
    parser.add_argument("--build-timeout-seconds", type=float, default=300.0)
    parser.add_argument("--link-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--wild-budget-seconds", type=float, default=30.0)
    parser.add_argument("--keep-artifacts", type=Path, metavar="DIR")
    args = parser.parse_args()
    for option in (
        "build_timeout_seconds",
        "link_timeout_seconds",
        "wild_budget_seconds",
    ):
        positive_seconds(parser, getattr(args, option), f"--{option.replace('_', '-')}")
    try:
        report, exit_code = run_probe(args)
    except (OSError, ProbeError) as error:
        report = {"schema_version": 1, "status": "error", "error": str(error)}
        exit_code = 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
