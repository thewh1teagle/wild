#!/usr/bin/env python3
"""Bridge rustc's x86-64 GNU link through Zig to an external linker.

Zig 0.16.0 owns the cross sysroot and emits its effective ld.lld command with
``-###``. This wrapper validates that plan, removes only known Zig-internal LLD
controls, and executes the external native linker selected by GOAL3_LINKER.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ZIG_VERSION = "0.16.0"
ZIG_SHA256 = "6e2989a7efbd4e81acbacb6c6378e34340d8e88bb023b10c4a941021be55cdcb"
ZIG_TARGET = "x86_64-linux-gnu"
ELF_EMULATION = "elf_x86_64"
INTERNAL_PAIRS = (("-mllvm", "-float-abi=hard"),)
INTERNAL_SINGLE = frozenset(("--error-limit=0", "--image-base=0"))
INTERNAL_PREFIXES = ("--error-limit", "--image-base", "-mllvm")


class BridgeError(RuntimeError):
    """A cross-link plan or environment failed closed validation."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def absolute_executable(env: dict[str, str], name: str) -> Path:
    value = env.get(name)
    if not value:
        raise BridgeError(f"{name} must name a frozen executable")
    path = Path(value)
    if not path.is_absolute():
        raise BridgeError(f"{name} must be an absolute path: {value}")
    if not path.is_file() or not os.access(path, os.X_OK):
        raise BridgeError(f"{name} is not an executable file: {value}")
    return path


def validate_environment(env: dict[str, str]) -> tuple[Path, Path, Path]:
    if override := env.get("GOAL3_ZIG_TARGET"):
        raise BridgeError(
            f"GOAL3_ZIG_TARGET must be unset; the only supported target is {ZIG_TARGET}, got {override}"
        )
    zig = absolute_executable(env, "GOAL3_ZIG")
    linker = absolute_executable(env, "GOAL3_LINKER")
    provenance_value = env.get("GOAL3_LINK_PROVENANCE_DIR")
    if not provenance_value:
        raise BridgeError("GOAL3_LINK_PROVENANCE_DIR must be set")
    provenance_dir = Path(provenance_value)
    if not provenance_dir.is_absolute():
        raise BridgeError("GOAL3_LINK_PROVENANCE_DIR must be absolute")
    provenance_dir.mkdir(parents=True, exist_ok=True)
    if not provenance_dir.is_dir():
        raise BridgeError(f"provenance path is not a directory: {provenance_dir}")
    if env.get("WILD_SAVE_DIR") and env.get("WILD_SAVE_BASE"):
        raise BridgeError("set only one of WILD_SAVE_DIR and WILD_SAVE_BASE")
    return zig, linker, provenance_dir


def zig_version(zig: Path) -> str:
    result = subprocess.run(
        [zig, "version"],
        check=False,
        text=True,
        capture_output=True,
    )
    version = result.stdout.strip()
    digest = sha256_file(zig.resolve())
    if (
        result.returncode != 0
        or result.stderr
        or version != ZIG_VERSION
        or digest != ZIG_SHA256
    ):
        raise BridgeError(
            f"expected Zig {ZIG_VERSION}, got status={result.returncode}, "
            f"stdout={result.stdout!r}, stderr={result.stderr!r}, sha256={digest}"
        )
    return version


def parse_plan(stderr: str) -> list[str]:
    command_lines: list[str] = []
    for line in stderr.splitlines():
        if not line.strip() or line.startswith("warning:"):
            continue
        if line.startswith("ld.lld "):
            command_lines.append(line)
            continue
        raise BridgeError(f"unexpected Zig -### output line: {line!r}")
    if len(command_lines) != 1:
        raise BridgeError(
            f"expected exactly one ld.lld plan, found {len(command_lines)}"
        )
    try:
        command = shlex.split(command_lines[0], posix=True)
    except ValueError as error:
        raise BridgeError(f"invalid shell quoting in Zig link plan: {error}") from error
    if not command or command[0] != "ld.lld":
        raise BridgeError("Zig link plan did not start with ld.lld")
    if any("\x00" in argument for argument in command):
        raise BridgeError("Zig link plan contained a NUL byte")
    return command[1:]


def validate_target(args: list[str]) -> None:
    emulations = [
        args[index + 1] for index, argument in enumerate(args[:-1]) if argument == "-m"
    ]
    if emulations != [ELF_EMULATION]:
        raise BridgeError(
            f"expected exactly '-m {ELF_EMULATION}' in Zig plan, got {emulations}"
        )
    if "-m" == args[-1]:
        raise BridgeError("Zig plan ended with a value-less -m")


def effective_arguments(plan_args: list[str]) -> tuple[list[str], list[list[str]]]:
    validate_target(plan_args)
    effective: list[str] = []
    stripped: list[list[str]] = []
    index = 0
    while index < len(plan_args):
        argument = plan_args[index]
        if argument == INTERNAL_PAIRS[0][0]:
            if index + 1 >= len(plan_args):
                raise BridgeError("Zig plan ended with a value-less -mllvm")
            pair = (argument, plan_args[index + 1])
            if pair not in INTERNAL_PAIRS:
                raise BridgeError(f"unexpected Zig internal control pair: {pair!r}")
            stripped.append(list(pair))
            index += 2
            continue
        if argument in INTERNAL_SINGLE:
            stripped.append([argument])
            index += 1
            continue
        if argument.startswith(INTERNAL_PREFIXES):
            raise BridgeError(f"unexpected Zig internal control: {argument!r}")
        effective.append(argument)
        index += 1
    expected = [list(pair) for pair in INTERNAL_PAIRS] + [
        [argument] for argument in sorted(INTERNAL_SINGLE)
    ]
    if sorted(stripped) != sorted(expected):
        raise BridgeError(
            f"Zig internal control schema changed: expected {expected!r}, got {stripped!r}"
        )
    validate_target(effective)
    return effective, stripped


def write_provenance(
    directory: Path,
    *,
    zig: Path,
    linker: Path,
    driver_args: list[str],
    plan_args: list[str],
    effective_args: list[str],
    stripped: list[list[str]],
    env: dict[str, str],
) -> Path:
    payload = {
        "schema": 1,
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "cwd": os.getcwd(),
        "target": ZIG_TARGET,
        "elf_emulation": ELF_EMULATION,
        "bridge": {
            "path": str(Path(__file__).resolve()),
            "sha256": sha256_file(Path(__file__).resolve()),
        },
        "zig": {
            "path": str(zig),
            "realpath": str(zig.resolve()),
            "version": ZIG_VERSION,
            "sha256": sha256_file(zig.resolve()),
        },
        "linker": {
            "path": str(linker),
            "realpath": str(linker.resolve()),
            "sha256": sha256_file(linker.resolve()),
        },
        "driver_argv": driver_args,
        "zig_plan_argv": ["ld.lld", *plan_args],
        "stripped_zig_internal_controls": stripped,
        "effective_linker_argv": [str(linker), *effective_args],
        "capture": {
            "WILD_SAVE_DIR": env.get("WILD_SAVE_DIR"),
            "WILD_SAVE_BASE": env.get("WILD_SAVE_BASE"),
        },
    }
    stem = f"link-{os.getpid()}-{dt.datetime.now(dt.UTC).strftime('%Y%m%dT%H%M%S%fZ')}"
    path = directory / f"{stem}.json"
    with path.open("x", encoding="utf-8") as output:
        json.dump(payload, output, indent=2, sort_keys=True, ensure_ascii=False)
        output.write("\n")
    return path


def run_bridge(driver_args: list[str], env: dict[str, str]) -> int:
    zig, linker, provenance_dir = validate_environment(env)
    zig_version(zig)
    result = subprocess.run(
        [zig, "cc", "-target", ZIG_TARGET, "-###", *driver_args],
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0 or result.stdout:
        raise BridgeError(
            f"Zig plan failed: status={result.returncode}, "
            f"stdout={result.stdout!r}, stderr={result.stderr!r}"
        )
    plan_args = parse_plan(result.stderr)
    effective_args, stripped = effective_arguments(plan_args)
    write_provenance(
        provenance_dir,
        zig=zig,
        linker=linker,
        driver_args=driver_args,
        plan_args=plan_args,
        effective_args=effective_args,
        stripped=stripped,
        env=env,
    )
    return subprocess.run([linker, *effective_args], check=False, env=env).returncode


class BridgeTests(unittest.TestCase):
    def test_plan_parsing_preserves_quoted_tokens(self) -> None:
        args = parse_plan("ld.lld 'space name.o' 'single'\\''quote.o' -m elf_x86_64\n")
        self.assertEqual(args, ["space name.o", "single'quote.o", "-m", ELF_EMULATION])

    def test_only_exact_internal_controls_are_stripped(self) -> None:
        semantic = ["-m", ELF_EMULATION, "a b.o", "--gc-sections", "-o", "out file"]
        plan = [
            "--error-limit=0",
            "-mllvm",
            "-float-abi=hard",
            *semantic,
            "--image-base=0",
        ]
        effective, stripped = effective_arguments(plan)
        self.assertEqual(effective, semantic)
        self.assertEqual(
            stripped,
            [["--error-limit=0"], ["-mllvm", "-float-abi=hard"], ["--image-base=0"]],
        )

    def test_changed_internal_controls_fail_closed(self) -> None:
        base = ["-m", ELF_EMULATION, "--error-limit=0", "--image-base=0"]
        for extra in (
            ["-mllvm", "-different"],
            ["--error-limit=1", "-mllvm", "-float-abi=hard"],
            ["--image-base=4096", "-mllvm", "-float-abi=hard"],
        ):
            with self.subTest(extra=extra), self.assertRaises(BridgeError):
                effective_arguments([*base, *extra])

    def test_plan_schema_and_target_fail_closed(self) -> None:
        with self.assertRaises(BridgeError):
            parse_plan("note: new output\nld.lld -m elf_x86_64\n")
        with self.assertRaises(BridgeError):
            parse_plan("ld.lld -m elf_x86_64\nld.lld -m elf_x86_64\n")
        complete_controls = [
            "--error-limit=0",
            "--image-base=0",
            "-mllvm",
            "-float-abi=hard",
        ]
        with self.assertRaises(BridgeError):
            effective_arguments(["-m", "aarch64linux", *complete_controls])

    def test_environment_requires_absolute_frozen_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "tool"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)
            base = {
                "GOAL3_ZIG": str(executable),
                "GOAL3_LINKER": str(executable),
                "GOAL3_LINK_PROVENANCE_DIR": str(Path(directory) / "provenance"),
            }
            validate_environment(base)
            for key, value in (
                ("GOAL3_ZIG", "zig"),
                ("GOAL3_LINKER", "ld.lld"),
                ("GOAL3_ZIG_TARGET", "aarch64-linux-gnu"),
            ):
                with self.subTest(key=key), self.assertRaises(BridgeError):
                    validate_environment({**base, key: value})
            with self.assertRaises(BridgeError):
                validate_environment(
                    {**base, "WILD_SAVE_DIR": "a", "WILD_SAVE_BASE": "b"}
                )

    def test_zig_version_is_exact(self) -> None:
        result = subprocess.CompletedProcess([], 0, "0.16.0\n", "")
        with (
            mock.patch("subprocess.run", return_value=result),
            mock.patch.object(
                sys.modules[__name__], "sha256_file", return_value=ZIG_SHA256
            ),
        ):
            self.assertEqual(zig_version(Path("/zig")), ZIG_VERSION)
        result.stdout = "0.17.0\n"
        with (
            mock.patch("subprocess.run", return_value=result),
            mock.patch.object(
                sys.modules[__name__], "sha256_file", return_value=ZIG_SHA256
            ),
            self.assertRaises(BridgeError),
        ):
            zig_version(Path("/zig"))
        result.stdout = "0.16.0\n"
        with (
            mock.patch("subprocess.run", return_value=result),
            mock.patch.object(
                sys.modules[__name__], "sha256_file", return_value="0" * 64
            ),
            self.assertRaises(BridgeError),
        ):
            zig_version(Path("/zig"))

    def test_bridge_forwards_semantic_tokens_and_capture_environment(self) -> None:
        semantic = [
            "-m",
            ELF_EMULATION,
            "space name.o",
            "single'quote.o",
            "-o",
            "out file",
        ]
        plan = [
            "--error-limit=0",
            "-mllvm",
            "-float-abi=hard",
            *semantic,
            "--image-base=0",
        ]
        plan_result = subprocess.CompletedProcess(
            [], 0, "", f"{shlex.join(['ld.lld', *plan])}\n"
        )
        link_result = subprocess.CompletedProcess([], 0, "", "")
        env = {"WILD_SAVE_BASE": "/capture"}
        module = sys.modules[__name__]
        with (
            mock.patch.object(
                module,
                "validate_environment",
                return_value=(Path("/zig"), Path("/wild"), Path("/provenance")),
            ),
            mock.patch.object(module, "zig_version", return_value=ZIG_VERSION),
            mock.patch.object(module, "write_provenance"),
            mock.patch("subprocess.run", side_effect=[plan_result, link_result]) as run,
        ):
            self.assertEqual(run_bridge(["driver input"], env), 0)
        self.assertEqual(run.call_args_list[1].args[0], [Path("/wild"), *semantic])
        self.assertIs(run.call_args_list[1].kwargs["env"], env)


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(BridgeTests)
        return (
            0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
        )
    try:
        return run_bridge(sys.argv[1:], dict(os.environ))
    except (BridgeError, OSError) as error:
        print(f"zig-external-linker: error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
