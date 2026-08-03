#!/usr/bin/env python3
"""Benchmark replayable PE links without including compilation time."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import random
import resource
import shutil
import statistics
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
AMD64_MACHINE = 0x8664
PE32_PLUS_MAGIC = 0x20B


class BenchError(RuntimeError):
    """A benchmark setup or execution error with a user-facing diagnostic."""


@dataclass(frozen=True)
class Tool:
    name: str
    path: Path
    flavor_args: tuple[str, ...]


@dataclass(frozen=True)
class Sample:
    elapsed_seconds: float
    user_seconds: float
    system_seconds: float


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def resolve_executable(value: str) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_file():
        return candidate.absolute()
    found = shutil.which(value)
    if found:
        return Path(found).absolute()
    raise BenchError(f"executable not found: {value}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def tool_metadata(tool: Tool) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            [str(tool.path), "--version"],
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
        version = (completed.stdout or completed.stderr).splitlines()
        version_text = version[0].strip() if version else "unknown"
    except (OSError, subprocess.TimeoutExpired):
        version_text = "unknown"
    return {
        "path": str(tool.path),
        "bytes": tool.path.stat().st_size,
        "sha256": sha256_file(tool.path),
        "version": version_text,
    }


def corpus_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise BenchError(
                f"corpus contains a symlink, which is not supported: {path}"
            )
        if path.is_file():
            files.append(path)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def corpus_metadata(root: Path, response: Path, files: list[Path]) -> dict[str, Any]:
    digest = hashlib.sha256()
    total_bytes = 0
    for path in files:
        relative = path.relative_to(root).as_posix().encode()
        size = path.stat().st_size
        file_digest = bytes.fromhex(sha256_file(path))
        digest.update(struct.pack("<Q", len(relative)))
        digest.update(relative)
        digest.update(struct.pack("<Q", size))
        digest.update(file_digest)
        total_bytes += size
    return {
        "root": str(root),
        "response_file": str(response.relative_to(root)),
        "response_sha256": sha256_file(response),
        "file_count": len(files),
        "total_bytes": total_bytes,
        "manifest_sha256": digest.hexdigest(),
    }


def parse_cpu_list(value: str) -> tuple[int, ...]:
    cpus: set[int] = set()
    try:
        for component in value.split(","):
            if not component:
                raise ValueError
            if "-" in component:
                first_text, last_text = component.split("-", 1)
                first, last = int(first_text), int(last_text)
                if first < 0 or last < first:
                    raise ValueError
                cpus.update(range(first, last + 1))
            else:
                cpu = int(component)
                if cpu < 0:
                    raise ValueError
                cpus.add(cpu)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid CPU list: {value}") from error
    if not cpus:
        raise argparse.ArgumentTypeError("CPU list must not be empty")
    return tuple(sorted(cpus))


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def summarize(values: list[float]) -> dict[str, float | int]:
    if not values:
        raise BenchError("cannot summarize an empty sample set")
    median = statistics.median(values)
    deviations = [abs(value - median) for value in values]
    return {
        "samples": len(values),
        "min": min(values),
        "median": median,
        "mad": statistics.median(deviations),
        "p95": percentile(values, 0.95),
    }


def command_for(
    tool: Tool,
    response: Path,
    output: Path,
    threads: int,
    taskset: Path | None,
    cpu_list: str | None,
) -> list[str]:
    command = [
        str(tool.path),
        *tool.flavor_args,
        f"@{response.relative_to(response.parent)}",
        f"/out:{output}",
        f"/threads:{threads}",
    ]
    if taskset is not None and cpu_list is not None:
        command = [str(taskset), "--cpu-list", cpu_list, *command]
    return command


def unlink_output(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def run_sample(command: list[str], cwd: Path, timeout: float, label: str) -> Sample:
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise BenchError(f"{label} exceeded {timeout:.3f} seconds") from error
    elapsed = time.perf_counter() - started
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    if completed.returncode:
        stderr = completed.stderr.decode(errors="replace")[-4000:]
        stdout = completed.stdout.decode(errors="replace")[-2000:]
        raise BenchError(
            f"{label} exited with {completed.returncode}; stdout={stdout!r}; stderr={stderr!r}"
        )
    return Sample(
        elapsed_seconds=elapsed,
        user_seconds=max(0.0, after.ru_utime - before.ru_utime),
        system_seconds=max(0.0, after.ru_stime - before.ru_stime),
    )


def evict_input_cache(paths: list[Path]) -> dict[str, int]:
    if not hasattr(os, "posix_fadvise") or not hasattr(os, "POSIX_FADV_DONTNEED"):
        raise BenchError(
            "cold-input-cache mode requires os.posix_fadvise and POSIX_FADV_DONTNEED"
        )
    advised_bytes = 0
    for path in paths:
        try:
            with path.open("rb", buffering=0) as source:
                os.posix_fadvise(source.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
            advised_bytes += path.stat().st_size
        except OSError as error:
            raise BenchError(
                f"failed to advise cache eviction for {path}: {error}"
            ) from error
    return {"advised_files": len(paths), "advised_bytes": advised_bytes}


def inspect_pe(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise BenchError(f"output is not a DOS/PE image: {path}")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise BenchError(f"output has no valid PE signature: {path}")
    machine, section_count = struct.unpack_from("<HH", data, pe_offset + 4)
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional = pe_offset + 24
    if optional + optional_size > len(data) or optional_size < 70:
        raise BenchError(f"output has a truncated PE optional header: {path}")
    magic = struct.unpack_from("<H", data, optional)[0]
    if machine != AMD64_MACHINE or magic != PE32_PLUS_MAGIC:
        raise BenchError(
            f"output is not AMD64 PE32+: machine={machine:#x}, magic={magic:#x}"
        )
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "machine": "IMAGE_FILE_MACHINE_AMD64",
        "sections": section_count,
        "entry_point_rva": struct.unpack_from("<I", data, optional + 16)[0],
        "subsystem": struct.unpack_from("<H", data, optional + 68)[0],
    }


def validate_outputs(
    tool: Tool,
    response: Path,
    work: Path,
    threads: int,
    taskset: Path | None,
    cpu_list: str | None,
    timeout: float,
) -> dict[str, Any]:
    inspections = []
    output = work / f"validate-{tool.name}-{threads}.exe"
    for _ in range(2):
        unlink_output(output)
        run_sample(
            command_for(tool, response, output, threads, taskset, cpu_list),
            response.parent,
            timeout,
            f"validate {tool.name}",
        )
        inspections.append(inspect_pe(output))
    return {
        **inspections[0],
        "deterministic": inspections[0]["sha256"] == inspections[1]["sha256"],
        "second_sha256": inspections[1]["sha256"],
    }


def gnu_time_rss(
    gnu_time: Path,
    command: list[str],
    cwd: Path,
    output: Path,
    timeout: float,
) -> int:
    unlink_output(output)
    with tempfile.NamedTemporaryFile(prefix="wild-pe-rss-", delete=False) as stats_file:
        stats_path = Path(stats_file.name)
    try:
        timed = [str(gnu_time), "-f", "%M", "-o", str(stats_path), *command]
        run_sample(timed, cwd, timeout, "RSS measurement")
        text = stats_path.read_text(encoding="utf-8").strip()
        try:
            return int(text)
        except ValueError as error:
            raise BenchError(
                f"GNU time returned invalid maximum RSS: {text!r}"
            ) from error
    finally:
        stats_path.unlink(missing_ok=True)


def benchmark_configuration(
    tools: list[Tool],
    response: Path,
    work: Path,
    mode: str,
    threads: int,
    cache_paths: list[Path],
    taskset: Path | None,
    cpu_list: str | None,
    warmups: int,
    min_samples: int,
    min_seconds: float,
    max_samples: int,
    rss_samples: int,
    gnu_time: Path | None,
    timeout: float,
    rng: random.Random,
) -> dict[str, Any]:
    samples: dict[str, list[Sample]] = {tool.name: [] for tool in tools}
    execution_order: list[list[str]] = []
    outputs = {
        tool.name: work / f"sample-{mode}-{threads}-{tool.name}.exe" for tool in tools
    }
    eviction: dict[str, int] | None = None

    def invoke(tool: Tool, measured: bool) -> None:
        nonlocal eviction
        if mode == "cold-input-cache":
            eviction = evict_input_cache(cache_paths)
        output = outputs[tool.name]
        unlink_output(output)
        sample = run_sample(
            command_for(tool, response, output, threads, taskset, cpu_list),
            response.parent,
            timeout,
            f"{tool.name} {mode} threads={threads}",
        )
        if measured:
            samples[tool.name].append(sample)

    for _ in range(warmups):
        order = tools.copy()
        rng.shuffle(order)
        for tool in order:
            invoke(tool, False)

    while True:
        enough_count = all(len(values) >= min_samples for values in samples.values())
        enough_time = all(
            sum(sample.elapsed_seconds for sample in values) >= min_seconds
            for values in samples.values()
        )
        if enough_count and enough_time:
            break
        if any(len(values) >= max_samples for values in samples.values()):
            raise BenchError(
                f"max samples ({max_samples}) reached before min accumulated seconds "
                f"({min_seconds}) for {mode}, threads={threads}"
            )
        order = tools.copy()
        rng.shuffle(order)
        execution_order.append([tool.name for tool in order])
        for tool in order:
            invoke(tool, True)

    result: dict[str, Any] = {
        "mode": mode,
        "threads": threads,
        "execution_order": execution_order,
        "tools": {},
    }
    if eviction is not None:
        result["cache_advice"] = {
            **eviction,
            "scope": "corpus files and linker executables only",
            "guarantee": "POSIX_FADV_DONTNEED is advisory; this is not a global cold cache",
        }
    for tool in tools:
        tool_samples = samples[tool.name]
        tool_result: dict[str, Any] = {
            "elapsed_seconds": summarize(
                [sample.elapsed_seconds for sample in tool_samples]
            ),
            "user_seconds": summarize([sample.user_seconds for sample in tool_samples]),
            "system_seconds": summarize(
                [sample.system_seconds for sample in tool_samples]
            ),
            "raw_samples": [sample.__dict__ for sample in tool_samples],
        }
        if rss_samples:
            if gnu_time is None:
                raise BenchError("RSS samples requested but GNU time was not found")
            rss_values = []
            for index in range(rss_samples):
                if mode == "cold-input-cache":
                    eviction = evict_input_cache(cache_paths)
                output = work / f"rss-{mode}-{threads}-{tool.name}-{index}.exe"
                command = command_for(
                    tool, response, output, threads, taskset, cpu_list
                )
                rss_values.append(
                    gnu_time_rss(gnu_time, command, response.parent, output, timeout)
                )
            tool_result["maximum_rss_kib"] = summarize(
                [float(value) for value in rss_values]
            )
            tool_result["maximum_rss_kib"]["raw_samples"] = rss_values
        result["tools"][tool.name] = tool_result
    wild_median = result["tools"]["wild"]["elapsed_seconds"]["median"]
    lld_median = result["tools"]["lld-link"]["elapsed_seconds"]["median"]
    result["wild_over_lld_median_ratio"] = wild_median / lld_median
    return result


def thread_scaling(configurations: list[dict[str, Any]]) -> dict[str, Any]:
    scaling: dict[str, Any] = {}
    for mode in {configuration["mode"] for configuration in configurations}:
        by_threads = {
            configuration["threads"]: configuration
            for configuration in configurations
            if configuration["mode"] == mode
        }
        baseline = by_threads.get(1)
        if baseline is None:
            scaling[mode] = {"available": False, "reason": "threads=1 was not measured"}
            continue
        tools: dict[str, Any] = {}
        for tool in ("wild", "lld-link"):
            baseline_median = baseline["tools"][tool]["elapsed_seconds"]["median"]
            tools[tool] = {
                str(threads): {
                    "median_seconds": configuration["tools"][tool]["elapsed_seconds"][
                        "median"
                    ],
                    "speedup_over_one_thread": (
                        baseline_median
                        / configuration["tools"][tool]["elapsed_seconds"]["median"]
                    ),
                }
                for threads, configuration in sorted(by_threads.items())
            }
        scaling[mode] = {"available": True, "baseline_threads": 1, "tools": tools}
    return scaling


def run_benchmark(args: argparse.Namespace) -> dict[str, Any]:
    corpus = args.corpus.expanduser().resolve()
    if not corpus.is_dir():
        raise BenchError(f"corpus directory does not exist: {corpus}")
    response = (corpus / args.response).resolve()
    try:
        response.relative_to(corpus)
    except ValueError as error:
        raise BenchError("response file must remain within the corpus") from error
    if not response.is_file():
        raise BenchError(f"response file does not exist: {response}")
    files = corpus_files(corpus)
    wild = Tool("wild", resolve_executable(args.wild), ("-flavor", "link"))
    lld = Tool("lld-link", resolve_executable(args.lld_link), ())
    tools = [wild, lld]
    taskset = resolve_executable("taskset") if args.cpu_list else None
    gnu_time = resolve_executable(args.gnu_time) if args.rss_samples else None
    cache_paths = sorted({*files, wild.path, lld.path}, key=str)
    rng = random.Random(args.seed)
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "running",
        "benchmark": "PE/COFF link-only lld /reproduce replay",
        "cache_mode_definition": {
            "warm": "ordinary repeated process runs with no explicit cache eviction",
            "cold-input-cache": (
                "advisory POSIX_FADV_DONTNEED for corpus files and linker executables; "
                "not a global cold cache"
            ),
        },
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "logical_cpus": os.cpu_count(),
            "cpu_list": args.cpu_list,
        },
        "corpus": corpus_metadata(corpus, response, files),
        "tools": {tool.name: tool_metadata(tool) for tool in tools},
        "settings": {
            "modes": args.mode,
            "threads": args.threads,
            "warmups": args.warmups,
            "min_samples": args.min_samples,
            "min_accumulated_seconds": args.min_seconds,
            "max_samples": args.max_samples,
            "rss_samples": args.rss_samples,
            "timeout_seconds": args.timeout,
            "random_seed": args.seed,
            "compilation_in_timed_region": False,
        },
        "configurations": [],
    }
    with tempfile.TemporaryDirectory(prefix="wild-pe-link-bench-") as directory:
        work = Path(directory)
        for mode in args.mode:
            for threads in args.threads:
                log(f"benchmarking mode={mode}, threads={threads}")
                report["configurations"].append(
                    benchmark_configuration(
                        tools,
                        response,
                        work,
                        mode,
                        threads,
                        cache_paths,
                        taskset,
                        args.cpu_list,
                        args.warmups,
                        args.min_samples,
                        args.min_seconds,
                        args.max_samples,
                        args.rss_samples,
                        gnu_time,
                        args.timeout,
                        rng,
                    )
                )
        report["thread_scaling"] = thread_scaling(report["configurations"])
        validations: dict[str, Any] = {}
        for threads in args.threads:
            validations[str(threads)] = {
                tool.name: validate_outputs(
                    tool,
                    response,
                    work,
                    threads,
                    taskset,
                    args.cpu_list,
                    args.timeout,
                )
                for tool in tools
            }
        report["validation"] = validations
    report["status"] = "pass"
    return report


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def nonnegative_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--corpus", type=Path, help="extracted lld /reproduce root")
    result.add_argument(
        "--response",
        type=Path,
        default=Path("response.txt"),
        help="response path within corpus",
    )
    result.add_argument("--wild", default="target/release/wild")
    result.add_argument("--lld-link", default="lld-link")
    result.add_argument(
        "--mode",
        action="append",
        choices=("warm", "cold-input-cache"),
        help="repeatable; defaults to warm and cold-input-cache",
    )
    result.add_argument(
        "--threads",
        type=lambda value: [positive_int(item) for item in value.split(",")],
        default=[1, 2, 4, 8],
        help="comma-separated thread counts",
    )
    result.add_argument(
        "--cpu-list", type=lambda value: ",".join(map(str, parse_cpu_list(value)))
    )
    result.add_argument("--warmups", type=nonnegative_int, default=3)
    result.add_argument("--min-samples", type=positive_int, default=15)
    result.add_argument("--min-seconds", type=nonnegative_float, default=5.0)
    result.add_argument("--max-samples", type=positive_int, default=1000)
    result.add_argument("--rss-samples", type=nonnegative_int, default=5)
    result.add_argument("--gnu-time", default="/usr/bin/time")
    result.add_argument("--timeout", type=positive_float, default=120.0)
    result.add_argument("--seed", type=int, default=1)
    result.add_argument("--output", type=Path, help="write JSON here instead of stdout")
    result.add_argument("--self-test", action="store_true")
    return result


def minimal_pe() -> bytes:
    data = bytearray(0x200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", data, 0x84, AMD64_MACHINE, 1)
    struct.pack_into("<H", data, 0x94, 0xF0)
    struct.pack_into("<H", data, 0x98, PE32_PLUS_MAGIC)
    struct.pack_into("<I", data, 0x98 + 16, 0x1000)
    struct.pack_into("<H", data, 0x98 + 68, 3)
    return bytes(data)


class HarnessTests(unittest.TestCase):
    def test_statistics(self) -> None:
        summary = summarize([1.0, 2.0, 3.0, 100.0])
        self.assertEqual(summary["samples"], 4)
        self.assertEqual(summary["median"], 2.5)
        self.assertEqual(summary["mad"], 1.0)
        self.assertEqual(summary["min"], 1.0)

    def test_cpu_list(self) -> None:
        self.assertEqual(parse_cpu_list("1-3,5"), (1, 2, 3, 5))
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_cpu_list("3-1")

    def test_pe_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "test.exe"
            image.write_bytes(minimal_pe())
            inspection = inspect_pe(image)
            self.assertEqual(inspection["machine"], "IMAGE_FILE_MACHINE_AMD64")
            self.assertEqual(inspection["entry_point_rva"], 0x1000)

    def test_command_keeps_link_inputs_in_response(self) -> None:
        root = Path("/corpus")
        tool = Tool("wild", Path("/bin/wild"), ("-flavor", "link"))
        command = command_for(
            tool, root / "response.txt", Path("/tmp/out.exe"), 4, None, None
        )
        self.assertEqual(
            command,
            [
                "/bin/wild",
                "-flavor",
                "link",
                "@response.txt",
                "/out:/tmp/out.exe",
                "/threads:4",
            ],
        )

    def test_thread_scaling(self) -> None:
        configurations = []
        for threads, wild, lld in ((1, 4.0, 2.0), (4, 2.0, 1.0)):
            configurations.append(
                {
                    "mode": "warm",
                    "threads": threads,
                    "tools": {
                        "wild": {"elapsed_seconds": {"median": wild}},
                        "lld-link": {"elapsed_seconds": {"median": lld}},
                    },
                }
            )
        scaling = thread_scaling(configurations)
        self.assertEqual(
            scaling["warm"]["tools"]["wild"]["4"]["speedup_over_one_thread"],
            2.0,
        )


def main() -> int:
    args = parser().parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(HarnessTests)
        return (
            0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
        )
    if args.corpus is None:
        parser().error("--corpus is required unless --self-test is used")
    if args.mode is None:
        args.mode = ["warm", "cold-input-cache"]
    if len(set(args.mode)) != len(args.mode):
        parser().error("--mode values must be unique")
    if len(set(args.threads)) != len(args.threads):
        parser().error("--threads values must be unique")
    if args.max_samples < args.min_samples:
        parser().error("--max-samples must be at least --min-samples")
    destination = args.output.expanduser().resolve() if args.output else None
    if destination is not None and destination.exists():
        parser().error(f"refusing to overwrite existing output: {destination}")
    if destination is not None and not destination.parent.is_dir():
        parser().error(f"output parent directory does not exist: {destination.parent}")
    try:
        report = run_benchmark(args)
        exit_code = 0
    except (BenchError, OSError) as error:
        report = {
            "schema_version": SCHEMA_VERSION,
            "status": "error",
            "error": str(error),
        }
        exit_code = 2
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if destination is not None:
        destination.write_text(encoded, encoding="utf-8")
        log(f"wrote {destination}")
    else:
        sys.stdout.write(encoded)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
