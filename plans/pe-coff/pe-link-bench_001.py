#!/usr/bin/env python3
"""Benchmark replayable PE links without including compilation time."""

from __future__ import annotations

import argparse
import datetime
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
from unittest import mock

SCHEMA_VERSION = 1
AMD64_MACHINE = 0x8664
PE32_PLUS_MAGIC = 0x20B
ELF64_CLASS = 2
ELF_LITTLE_ENDIAN = 1
ELF_X86_64_MACHINE = 62


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


@dataclass(frozen=True)
class ThreadPair:
    wild: int
    lld_link: int

    def metadata(self) -> dict[str, int]:
        return {"wild": self.wild, "lld-link": self.lld_link}


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


def host_metadata(cpu_list: str | None, environment_note: str | None) -> dict[str, Any]:
    cpu_models: set[str] = set()
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith(("model name", "Model")) and ":" in line:
                cpu_models.add(line.split(":", 1)[1].strip())
    except OSError:
        pass
    memory_total_kib: int | None = None
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                memory_total_kib = int(line.split()[1])
                break
    except (OSError, ValueError, IndexError):
        pass
    cpu_state: dict[str, Any] = {}
    if cpu_list is not None:
        for cpu in parse_cpu_list(cpu_list):
            root = Path(f"/sys/devices/system/cpu/cpu{cpu}")

            def read(relative: str) -> str | None:
                try:
                    return (root / relative).read_text(encoding="utf-8").strip()
                except OSError:
                    return None

            cpu_state[str(cpu)] = {
                "physical_package_id": read("topology/physical_package_id"),
                "core_id": read("topology/core_id"),
                "scaling_driver": read("cpufreq/scaling_driver"),
                "scaling_governor": read("cpufreq/scaling_governor"),
                "cpuinfo_max_freq_khz": read("cpufreq/cpuinfo_max_freq"),
            }
    try:
        affinity = sorted(os.sched_getaffinity(0))
    except AttributeError:
        affinity = None
    return {
        "platform": platform.platform(),
        "kernel_release": platform.release(),
        "machine": platform.machine(),
        "logical_cpus": os.cpu_count(),
        "cpu_list": cpu_list,
        "process_affinity_at_start": affinity,
        "cpu_models": sorted(cpu_models),
        "memory_total_kib": memory_total_kib,
        "selected_cpu_state": cpu_state,
        "environment_note": environment_note,
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


def parse_thread_pair(value: str) -> ThreadPair:
    try:
        wild_text, lld_text = value.split(":")
        wild, lld_link = int(wild_text), int(lld_text)
        if wild <= 0 or lld_link <= 0:
            raise ValueError
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"invalid thread pair {value!r}; expected positive WILD:LLD counts"
        ) from error
    return ThreadPair(wild=wild, lld_link=lld_link)


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


def paired_comparison(
    wild_samples: list[Sample],
    lld_samples: list[Sample],
    comparator_name: str = "lld-link",
) -> dict[str, Any]:
    paired_deltas = [
        wild.elapsed_seconds - lld.elapsed_seconds
        for wild, lld in zip(wild_samples, lld_samples, strict=True)
    ]
    paired_summary = summarize(paired_deltas)
    paired_summary["raw_samples"] = paired_deltas
    return {
        "delta_definition": (
            f"wild elapsed seconds minus {comparator_name} elapsed seconds"
        ),
        "wild_minus_lld_seconds": paired_summary,
        "wild_faster_pairs": sum(delta < 0 for delta in paired_deltas),
        "pair_count": len(paired_deltas),
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


def run_sample(
    command: list[str],
    cwd: Path,
    timeout: float,
    label: str,
    env: dict[str, str] | None = None,
) -> Sample:
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            env=env,
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


def elf_command_for(
    run_with: Path,
    tool: Tool,
    threads: int,
    taskset: Path | None,
    cpu_list: str | None,
) -> list[str]:
    command = [str(run_with), str(tool.path), f"--threads={threads}"]
    if taskset is not None and cpu_list is not None:
        command = [str(taskset), "--cpu-list", cpu_list, *command]
    return command


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
    if optional + optional_size > len(data) or optional_size < 112:
        raise BenchError(f"output has a truncated PE optional header: {path}")
    magic = struct.unpack_from("<H", data, optional)[0]
    if machine != AMD64_MACHINE or magic != PE32_PLUS_MAGIC:
        raise BenchError(
            f"output is not AMD64 PE32+: machine={machine:#x}, magic={magic:#x}"
        )
    directory_count = struct.unpack_from("<I", data, optional + 108)[0]
    directory_base = optional + 112

    def data_directory(index: int) -> dict[str, int | bool]:
        if index >= directory_count or directory_base + (index + 1) * 8 > optional + optional_size:
            return {"rva": 0, "size": 0, "present": False}
        rva, size = struct.unpack_from("<II", data, directory_base + index * 8)
        return {"rva": rva, "size": size, "present": bool(rva and size)}

    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "machine": "IMAGE_FILE_MACHINE_AMD64",
        "sections": section_count,
        "entry_point_rva": struct.unpack_from("<I", data, optional + 16)[0],
        "subsystem": struct.unpack_from("<H", data, optional + 68)[0],
        "data_directories": {
            "exports": data_directory(0),
            "imports": data_directory(1),
            "base_relocations": data_directory(5),
        },
    }


def inspect_elf(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise BenchError(f"output is not an ELF image: {path}")
    if data[4] != ELF64_CLASS or data[5] != ELF_LITTLE_ENDIAN:
        raise BenchError(
            f"output is not little-endian ELF64: class={data[4]}, data={data[5]}"
        )
    if data[6] != 1:
        raise BenchError(f"output uses unsupported ELF ident version: {data[6]}")
    elf_type, machine, version = struct.unpack_from("<HHI", data, 16)
    entry, program_offset, section_offset = struct.unpack_from("<QQQ", data, 24)
    (
        header_size,
        program_entry_size,
        program_count,
        section_entry_size,
        section_count,
    ) = struct.unpack_from(
        "<HHHHH", data, 52
    )
    if machine != ELF_X86_64_MACHINE:
        raise BenchError(f"output is not x86-64 ELF: machine={machine}")
    if version != 1 or header_size != 64:
        raise BenchError(
            f"output has invalid ELF header: version={version}, size={header_size}"
        )
    if program_count and (
        program_entry_size < 56
        or program_offset + program_entry_size * program_count > len(data)
    ):
        raise BenchError(f"output has a truncated ELF program header table: {path}")
    if section_count and (
        section_entry_size < 64
        or section_offset + section_entry_size * section_count > len(data)
    ):
        raise BenchError(f"output has a truncated ELF section header table: {path}")
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "class": "ELF64",
        "endianness": "little",
        "machine": "EM_X86_64",
        "type": elf_type,
        "entry_point": entry,
        "program_headers": program_count,
        "sections": section_count,
        "section_header_offset": section_offset,
    }


def require_tmpfs(path: Path) -> str:
    if not path.is_dir():
        raise BenchError(f"tmpfs output directory does not exist: {path}")
    try:
        completed = subprocess.run(
            ["stat", "-f", "-c", "%T", str(path)],
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BenchError(f"unable to identify filesystem for {path}: {error}") from error
    filesystem = completed.stdout.strip()
    if completed.returncode or filesystem != "tmpfs":
        detail = completed.stderr.strip() or filesystem or "unknown"
        raise BenchError(
            f"benchmark output directory must be tmpfs, got {detail!r}: {path}"
        )
    return filesystem


def load_output_expectations(path: Path | None, link_format: str) -> dict[str, Any] | None:
    if path is None:
        return None
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise BenchError(f"output expectations file does not exist: {resolved}")
    try:
        properties = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BenchError(f"invalid output expectations JSON: {resolved}: {error}") from error
    required = (
        {
            "format",
            "machine",
            "subsystem",
            "entry_point_nonzero",
            "exports",
            "imports",
            "base_relocations",
        }
        if link_format == "pe"
        else {"format", "machine", "type", "entry_point_nonzero"}
    )
    if not isinstance(properties, dict) or set(properties) != required:
        raise BenchError(
            f"{link_format.upper()} output expectations must contain exactly "
            f"{sorted(required)}"
        )
    if properties["format"] != link_format:
        raise BenchError(f"output expectations format must be {link_format!r}")
    if link_format == "pe":
        if properties["machine"] != "IMAGE_FILE_MACHINE_AMD64" or not isinstance(
            properties["subsystem"], int
        ):
            raise BenchError("PE expectations require AMD64 machine and integer subsystem")
        boolean_keys = (
            "entry_point_nonzero",
            "exports",
            "imports",
            "base_relocations",
        )
    else:
        if properties["machine"] != "EM_X86_64" or not isinstance(
            properties["type"], int
        ):
            raise BenchError("ELF expectations require EM_X86_64 and integer type")
        boolean_keys = ("entry_point_nonzero",)
    if any(not isinstance(properties[key], bool) for key in boolean_keys):
        raise BenchError("output expectation presence fields must be JSON booleans")
    return {
        "path": str(resolved),
        "sha256": sha256_file(resolved),
        "properties": properties,
    }


def pe_property_signature(inspection: dict[str, Any]) -> dict[str, Any]:
    directories = inspection["data_directories"]
    return {
        "format": "pe",
        "machine": inspection["machine"],
        "subsystem": inspection["subsystem"],
        "entry_point_nonzero": inspection["entry_point_rva"] != 0,
        "exports": directories["exports"]["present"],
        "imports": directories["imports"]["present"],
        "base_relocations": directories["base_relocations"]["present"],
    }


def elf_property_signature(inspection: dict[str, Any]) -> dict[str, Any]:
    return {
        "format": "elf",
        "machine": inspection["machine"],
        "type": inspection["type"],
        "entry_point_nonzero": inspection["entry_point"] != 0,
    }


def enforce_output_expectations(
    inspection: dict[str, Any],
    expectations: dict[str, Any] | None,
    link_format: str,
) -> None:
    if expectations is None:
        return
    signature = (
        pe_property_signature(inspection)
        if link_format == "pe"
        else elf_property_signature(inspection)
    )
    if signature != expectations["properties"]:
        raise BenchError(
            f"{link_format.upper()} output properties differ from frozen expectations: "
            f"expected {expectations['properties']}, got {signature}"
        )


def require_matching_output_properties(
    validations: dict[str, dict[str, Any]], link_format: str
) -> None:
    signatures = {
        name: (
            pe_property_signature(inspection)
            if link_format == "pe"
            else elf_property_signature(inspection)
        )
        for name, inspection in validations.items()
    }
    if len({json.dumps(value, sort_keys=True) for value in signatures.values()}) != 1:
        raise BenchError(f"{link_format.upper()} linker output properties disagree: {signatures}")


def validate_outputs(
    tool: Tool,
    response: Path,
    work: Path,
    threads: int,
    taskset: Path | None,
    cpu_list: str | None,
    timeout: float,
    expectations: dict[str, Any] | None = None,
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
        inspection = inspect_pe(output)
        enforce_output_expectations(inspection, expectations, "pe")
        inspections.append(inspection)
    return {
        **inspections[0],
        "deterministic": inspections[0]["sha256"] == inspections[1]["sha256"],
        "second_sha256": inspections[1]["sha256"],
    }


def validate_elf_outputs(
    tool: Tool,
    run_with: Path,
    corpus: Path,
    work: Path,
    threads: int,
    taskset: Path | None,
    cpu_list: str | None,
    timeout: float,
    expectations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    inspections = []
    output = work / f"validate-{tool.name}-{threads}"
    for _ in range(2):
        unlink_output(output)
        environment = {**os.environ, "OUT": str(output)}
        run_sample(
            elf_command_for(run_with, tool, threads, taskset, cpu_list),
            corpus,
            timeout,
            f"validate {tool.name}",
            environment,
        )
        inspection = inspect_elf(output)
        enforce_output_expectations(inspection, expectations, "elf")
        inspections.append(inspection)
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
    env: dict[str, str] | None = None,
) -> int:
    unlink_output(output)
    with tempfile.NamedTemporaryFile(prefix="wild-pe-rss-", delete=False) as stats_file:
        stats_path = Path(stats_file.name)
    try:
        timed = [str(gnu_time), "-f", "%M", "-o", str(stats_path), *command]
        run_sample(timed, cwd, timeout, "RSS measurement", env)
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
    thread_pair: ThreadPair | None = None,
) -> dict[str, Any]:
    samples: dict[str, list[Sample]] = {tool.name: [] for tool in tools}
    execution_order: list[list[str]] = []
    comparator_name = tools[1].name
    if thread_pair is None:
        tool_threads = {tool.name: threads for tool in tools}
        configuration_label = f"threads={threads}"
        output_label = str(threads)
    else:
        tool_threads = {
            "wild": thread_pair.wild,
            comparator_name: thread_pair.lld_link,
        }
        comparator_label = "lld" if comparator_name == "lld-link" else comparator_name
        configuration_label = (
            f"wild_threads={thread_pair.wild},"
            f"{comparator_label}_threads={thread_pair.lld_link}"
        )
        output_label = (
            f"wild-{thread_pair.wild}-{comparator_label}-{thread_pair.lld_link}"
        )
    outputs = {
        tool.name: work / f"sample-{mode}-{output_label}-{tool.name}.exe" for tool in tools
    }
    eviction: dict[str, int] | None = None

    def invoke(tool: Tool, measured: bool) -> None:
        nonlocal eviction
        if mode == "cold-input-cache":
            eviction = evict_input_cache(cache_paths)
        output = outputs[tool.name]
        unlink_output(output)
        sample = run_sample(
            command_for(
                tool, response, output, tool_threads[tool.name], taskset, cpu_list
            ),
            response.parent,
            timeout,
            f"{tool.name} {mode} {configuration_label}",
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
                f"({min_seconds}) for {mode}, {configuration_label}"
            )
        order = tools.copy()
        rng.shuffle(order)
        execution_order.append([tool.name for tool in order])
        for tool in order:
            invoke(tool, True)

    result: dict[str, Any] = {"mode": mode, "execution_order": execution_order, "tools": {}}
    if thread_pair is None:
        result["threads"] = threads
    else:
        result["configuration"] = "direct-thread-pair"
        result["thread_pair"] = {
            "wild": thread_pair.wild,
            comparator_name: thread_pair.lld_link,
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
                output = work / f"rss-{mode}-{output_label}-{tool.name}-{index}.exe"
                command = command_for(
                    tool,
                    response,
                    output,
                    tool_threads[tool.name],
                    taskset,
                    cpu_list,
                )
                rss_values.append(
                    gnu_time_rss(gnu_time, command, response.parent, output, timeout)
                )
            tool_result["maximum_rss_kib"] = summarize(
                [float(value) for value in rss_values]
            )
            tool_result["maximum_rss_kib"]["raw_samples"] = rss_values
        result["tools"][tool.name] = tool_result
        if thread_pair is not None:
            tool_result["threads"] = tool_threads[tool.name]
    wild_median = result["tools"]["wild"]["elapsed_seconds"]["median"]
    lld_median = result["tools"][comparator_name]["elapsed_seconds"]["median"]
    ratio_key = (
        "wild_over_lld_median_ratio"
        if comparator_name == "lld-link"
        else "wild_over_baseline_wild_median_ratio"
    )
    result[ratio_key] = wild_median / lld_median
    if thread_pair is not None:
        result["paired_comparison"] = paired_comparison(
            samples["wild"], samples[comparator_name], comparator_name
        )
    return result


def benchmark_elf_configuration(
    tools: list[Tool],
    run_with: Path,
    corpus: Path,
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
    thread_pair: ThreadPair | None = None,
) -> dict[str, Any]:
    samples: dict[str, list[Sample]] = {tool.name: [] for tool in tools}
    execution_order: list[list[str]] = []
    if thread_pair is None:
        tool_threads = {tool.name: threads for tool in tools}
        configuration_label = f"threads={threads}"
        output_label = str(threads)
    else:
        tool_threads = {"wild": thread_pair.wild, "ld.lld": thread_pair.lld_link}
        configuration_label = (
            f"wild_threads={thread_pair.wild},ld_lld_threads={thread_pair.lld_link}"
        )
        output_label = f"wild-{thread_pair.wild}-ld-lld-{thread_pair.lld_link}"
    outputs = {
        tool.name: work / f"sample-{mode}-{output_label}-{tool.name}"
        for tool in tools
    }
    eviction: dict[str, int] | None = None

    def invoke(tool: Tool, measured: bool) -> None:
        nonlocal eviction
        if mode == "cold-input-cache":
            eviction = evict_input_cache(cache_paths)
        output = outputs[tool.name]
        unlink_output(output)
        environment = {**os.environ, "OUT": str(output)}
        sample = run_sample(
            elf_command_for(
                run_with, tool, tool_threads[tool.name], taskset, cpu_list
            ),
            corpus,
            timeout,
            f"{tool.name} {mode} {configuration_label}",
            environment,
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
                f"({min_seconds}) for ELF {mode}, {configuration_label}"
            )
        order = tools.copy()
        rng.shuffle(order)
        execution_order.append([tool.name for tool in order])
        for tool in order:
            invoke(tool, True)

    result: dict[str, Any] = {"mode": mode, "execution_order": execution_order, "tools": {}}
    if thread_pair is None:
        result["threads"] = threads
    else:
        result["configuration"] = "direct-thread-pair"
        result["thread_pair"] = {
            "wild": thread_pair.wild,
            "ld.lld": thread_pair.lld_link,
        }
    if eviction is not None:
        result["cache_advice"] = {
            **eviction,
            "scope": "corpus files, run-with, and linker executables only",
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
                output = work / f"rss-{mode}-{output_label}-{tool.name}-{index}"
                environment = {**os.environ, "OUT": str(output)}
                command = elf_command_for(
                    run_with,
                    tool,
                    tool_threads[tool.name],
                    taskset,
                    cpu_list,
                )
                rss_values.append(
                    gnu_time_rss(
                        gnu_time, command, corpus, output, timeout, environment
                    )
                )
            tool_result["maximum_rss_kib"] = summarize(
                [float(value) for value in rss_values]
            )
            tool_result["maximum_rss_kib"]["raw_samples"] = rss_values
        result["tools"][tool.name] = tool_result
        if thread_pair is not None:
            tool_result["threads"] = tool_threads[tool.name]
    wild_median = result["tools"]["wild"]["elapsed_seconds"]["median"]
    lld_median = result["tools"]["ld.lld"]["elapsed_seconds"]["median"]
    result["wild_over_ld_lld_median_ratio"] = wild_median / lld_median
    if thread_pair is not None:
        result["paired_comparison"] = paired_comparison(
            samples["wild"], samples["ld.lld"], "ld.lld"
        )
    return result


def thread_scaling(
    configurations: list[dict[str, Any]],
    tool_names: tuple[str, str] = ("wild", "lld-link"),
) -> dict[str, Any]:
    scaling: dict[str, Any] = {}
    for mode in {configuration["mode"] for configuration in configurations}:
        by_threads = {
            configuration["threads"]: configuration
            for configuration in configurations
            if configuration["mode"] == mode and "threads" in configuration
        }
        baseline = by_threads.get(1)
        if baseline is None:
            reason = (
                "direct thread-pair confirmation does not measure thread scaling"
                if not by_threads
                else "threads=1 was not measured"
            )
            scaling[mode] = {"available": False, "reason": reason}
            continue
        tools: dict[str, Any] = {}
        for tool in tool_names:
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


def selection_sweep_metadata(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise BenchError(f"selection sweep does not exist: {resolved}")
    try:
        report = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BenchError(f"selection sweep is not valid JSON: {resolved}: {error}") from error
    if report.get("status") != "pass":
        raise BenchError(f"selection sweep did not pass: {resolved}")
    if any(
        configuration.get("configuration") == "direct-thread-pair"
        for configuration in report.get("configurations", [])
    ):
        raise BenchError(f"selection source must be a sweep, not a direct run: {resolved}")
    return {"path": str(resolved), "sha256": sha256_file(resolved)}


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
    output_root: Path | None = None
    output_filesystem: str | None = None
    if args.tmpfs_output_dir is not None:
        output_root = args.tmpfs_output_dir.expanduser().resolve()
        output_filesystem = require_tmpfs(output_root)
    expectations = load_output_expectations(args.output_expectations, "pe")
    files = corpus_files(corpus)
    wild = Tool("wild", resolve_executable(args.wild), ("-flavor", "link"))
    if args.baseline_wild is None:
        comparator = Tool("lld-link", resolve_executable(args.lld_link), ())
    else:
        comparator = Tool(
            "baseline-wild",
            resolve_executable(args.baseline_wild),
            ("-flavor", "link"),
        )
    tools = [wild, comparator]
    taskset = resolve_executable("taskset") if args.cpu_list else None
    gnu_time = resolve_executable(args.gnu_time) if args.rss_samples else None
    cache_paths = sorted({*files, wild.path, comparator.path}, key=str)
    rng = random.Random(args.seed)
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "running",
        "started_at_utc": datetime.datetime.now(datetime.UTC).isoformat(),
        "benchmark": (
            "PE/COFF final-Wild/baseline-Wild link-only replay"
            if args.baseline_wild is not None
            else "PE/COFF link-only lld /reproduce replay"
        ),
        "cache_mode_definition": {
            "warm": "ordinary repeated process runs with no explicit cache eviction",
            "cold-input-cache": (
                "advisory POSIX_FADV_DONTNEED for corpus files and linker executables; "
                "not a global cold cache"
            ),
        },
        "host": host_metadata(args.cpu_list, args.environment_note),
        "corpus": corpus_metadata(corpus, response, files),
        "tools": {tool.name: tool_metadata(tool) for tool in tools},
        "invocation": {
            "kind": "response-file",
            "response_sha256": sha256_file(response),
            "tool_flavor_args": {
                tool.name: list(tool.flavor_args) for tool in tools
            },
            "output_override": "/out:<per-sample-path>",
            "thread_override": "/threads:<selected-count>",
        },
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
            "benchmark_role": (
                "direct-holdout" if args.thread_pair else "thread-sweep"
            ),
        },
        "configurations": [],
    }
    if output_root is not None:
        report["settings"]["output_directory"] = str(output_root)
        report["settings"]["output_filesystem"] = output_filesystem
    if expectations is not None:
        report["output_expectations"] = expectations
    if args.thread_pair:
        report["settings"]["thread_pairs"] = [
            {
                "wild": thread_pair.wild,
                comparator.name: thread_pair.lld_link,
            }
            for thread_pair in args.thread_pair
        ]
        selection = selection_sweep_metadata(args.selection_sweep)
        if selection is not None:
            report["settings"]["selection_sweep"] = selection
    with tempfile.TemporaryDirectory(
        prefix="wild-pe-link-bench-", dir=output_root
    ) as directory:
        work = Path(directory)
        for mode in args.mode:
            if args.thread_pair:
                for thread_pair in args.thread_pair:
                    log(
                        f"benchmarking mode={mode}, wild_threads={thread_pair.wild}, "
                        f"{comparator.name}_threads={thread_pair.lld_link}"
                    )
                    report["configurations"].append(
                        benchmark_configuration(
                            tools,
                            response,
                            work,
                            mode,
                            thread_pair.wild,
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
                            thread_pair,
                        )
                    )
            else:
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
        report["thread_scaling"] = thread_scaling(
            report["configurations"], ("wild", comparator.name)
        )
        validations: dict[str, Any] = {}
        if args.thread_pair:
            for thread_pair in args.thread_pair:
                comparator_label = (
                    "lld" if comparator.name == "lld-link" else comparator.name
                )
                key = (
                    f"wild-{thread_pair.wild}-{comparator_label}-"
                    f"{thread_pair.lld_link}"
                )
                validations[key] = {
                    "configuration": "direct-thread-pair",
                    "thread_pair": {
                        "wild": thread_pair.wild,
                        comparator.name: thread_pair.lld_link,
                    },
                    "tools": {},
                }
                for tool in tools:
                    threads = (
                        thread_pair.wild
                        if tool.name == "wild"
                        else thread_pair.lld_link
                    )
                    validation = validate_outputs(
                        tool,
                        response,
                        work,
                        threads,
                        taskset,
                        args.cpu_list,
                        args.timeout,
                        expectations,
                    )
                    validation["threads"] = threads
                    validations[key]["tools"][tool.name] = validation
                require_matching_output_properties(
                    validations[key]["tools"], "pe"
                )
        else:
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
                        expectations,
                    )
                    for tool in tools
                }
                require_matching_output_properties(validations[str(threads)], "pe")
        report["validation"] = validations
    report["status"] = "pass"
    report["finished_at_utc"] = datetime.datetime.now(datetime.UTC).isoformat()
    return report


def run_elf_benchmark(args: argparse.Namespace) -> dict[str, Any]:
    corpus = args.corpus.expanduser().resolve()
    if not corpus.is_dir():
        raise BenchError(f"corpus directory does not exist: {corpus}")
    run_with = (corpus / args.run_with).resolve()
    try:
        run_with.relative_to(corpus)
    except ValueError as error:
        raise BenchError("run-with file must remain within the corpus") from error
    if not run_with.is_file() or not os.access(run_with, os.X_OK):
        raise BenchError(f"run-with is missing or not executable: {run_with}")
    output_root = args.tmpfs_output_dir.expanduser().resolve()
    filesystem = require_tmpfs(output_root)
    expectations = load_output_expectations(args.output_expectations, "elf")
    files = corpus_files(corpus)
    wild = Tool("wild", resolve_executable(args.wild), ())
    lld = Tool("ld.lld", resolve_executable(args.ld_lld), ())
    tools = [wild, lld]
    taskset = resolve_executable("taskset") if args.cpu_list else None
    gnu_time = resolve_executable(args.gnu_time) if args.rss_samples else None
    cache_paths = sorted({*files, wild.path, lld.path, run_with}, key=str)
    rng = random.Random(args.seed)
    metadata = corpus_metadata(corpus, run_with, files)
    metadata["run_with_file"] = metadata.pop("response_file")
    metadata["run_with_sha256"] = metadata.pop("response_sha256")
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "running",
        "started_at_utc": datetime.datetime.now(datetime.UTC).isoformat(),
        "benchmark": "ELF link-only Wild save-dir replay",
        "link_format": "elf",
        "cache_mode_definition": {
            "warm": "ordinary repeated process runs with no explicit cache eviction",
            "cold-input-cache": (
                "advisory POSIX_FADV_DONTNEED for corpus files, run-with, and "
                "linker executables; not a global cold cache"
            ),
        },
        "host": host_metadata(args.cpu_list, args.environment_note),
        "corpus": metadata,
        "tools": {tool.name: tool_metadata(tool) for tool in tools},
        "invocation": {
            "kind": "wild-save-dir-run-with",
            "run_with_sha256": sha256_file(run_with),
            "command_template": "run-with <native-linker> --threads=<selected-count>",
            "output_environment": "OUT=<per-sample-tmpfs-path>",
        },
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
            "benchmark_role": (
                "direct-holdout" if args.thread_pair else "thread-sweep"
            ),
            "output_directory": str(output_root),
            "output_filesystem": filesystem,
        },
        "configurations": [],
    }
    if expectations is not None:
        report["output_expectations"] = expectations
    if args.thread_pair:
        report["settings"]["thread_pairs"] = [
            {"wild": pair.wild, "ld.lld": pair.lld_link}
            for pair in args.thread_pair
        ]
        selection = selection_sweep_metadata(args.selection_sweep)
        if selection is not None:
            report["settings"]["selection_sweep"] = selection
    with tempfile.TemporaryDirectory(
        prefix="wild-elf-link-bench-", dir=output_root
    ) as directory:
        work = Path(directory)
        for mode in args.mode:
            if args.thread_pair:
                for pair in args.thread_pair:
                    log(
                        f"benchmarking ELF mode={mode}, wild_threads={pair.wild}, "
                        f"ld_lld_threads={pair.lld_link}"
                    )
                    report["configurations"].append(
                        benchmark_elf_configuration(
                            tools,
                            run_with,
                            corpus,
                            work,
                            mode,
                            pair.wild,
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
                            pair,
                        )
                    )
            else:
                for threads in args.threads:
                    log(f"benchmarking ELF mode={mode}, threads={threads}")
                    report["configurations"].append(
                        benchmark_elf_configuration(
                            tools,
                            run_with,
                            corpus,
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
        report["thread_scaling"] = thread_scaling(
            report["configurations"], ("wild", "ld.lld")
        )
        validations: dict[str, Any] = {}
        if args.thread_pair:
            for pair in args.thread_pair:
                key = f"wild-{pair.wild}-ld-lld-{pair.lld_link}"
                validations[key] = {
                    "configuration": "direct-thread-pair",
                    "thread_pair": {
                        "wild": pair.wild,
                        "ld.lld": pair.lld_link,
                    },
                    "tools": {},
                }
                for tool in tools:
                    threads = pair.wild if tool.name == "wild" else pair.lld_link
                    validation = validate_elf_outputs(
                        tool,
                        run_with,
                        corpus,
                        work,
                        threads,
                        taskset,
                        args.cpu_list,
                        args.timeout,
                        expectations,
                    )
                    validation["threads"] = threads
                    validations[key]["tools"][tool.name] = validation
                require_matching_output_properties(
                    validations[key]["tools"], "elf"
                )
        else:
            for threads in args.threads:
                validations[str(threads)] = {
                    tool.name: validate_elf_outputs(
                        tool,
                        run_with,
                        corpus,
                        work,
                        threads,
                        taskset,
                        args.cpu_list,
                        args.timeout,
                        expectations,
                    )
                    for tool in tools
                }
                require_matching_output_properties(validations[str(threads)], "elf")
        report["validation"] = validations
    report["status"] = "pass"
    report["finished_at_utc"] = datetime.datetime.now(datetime.UTC).isoformat()
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
    result.add_argument(
        "--format",
        dest="link_format",
        choices=("pe", "elf"),
        default="pe",
        help="link format; default pe preserves the original harness interface",
    )
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
        "--baseline-wild",
        help=(
            "compare final --wild directly with this frozen Wild binary instead "
            "of lld-link (PE regression holdout)"
        ),
    )
    result.add_argument("--ld-lld", default="ld.lld")
    result.add_argument(
        "--run-with",
        type=Path,
        default=Path("run-with"),
        help="ELF save-dir run-with path within --corpus",
    )
    result.add_argument(
        "--tmpfs-output-dir",
        type=Path,
        help="per-sample output directory; required for ELF and Goal 3 authority",
    )
    result.add_argument(
        "--output-expectations",
        type=Path,
        help="frozen JSON properties required of every validated PE or ELF output",
    )
    result.add_argument(
        "--selection-sweep",
        type=Path,
        help="sweep JSON whose independently selected thread counts this holdout confirms",
    )
    result.add_argument(
        "--mode",
        action="append",
        choices=("warm", "cold-input-cache"),
        help="repeatable; defaults to warm and cold-input-cache",
    )
    thread_selection = result.add_mutually_exclusive_group()
    thread_selection.add_argument(
        "--threads",
        type=lambda value: [positive_int(item) for item in value.split(",")],
        help="comma-separated thread counts",
    )
    thread_selection.add_argument(
        "--thread-pair",
        action="append",
        type=parse_thread_pair,
        help=(
            "repeatable direct comparison as WILD:LLD thread counts; use after a sweep "
            "when the linkers have different independently optimal counts"
        ),
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
    result.add_argument(
        "--environment-note",
        help="record dedicated-runner/interference controls in provenance",
    )
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


def minimal_elf() -> bytes:
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4:7] = bytes((ELF64_CLASS, ELF_LITTLE_ENDIAN, 1))
    struct.pack_into("<HHI", data, 16, 2, ELF_X86_64_MACHINE, 1)
    struct.pack_into("<QQQ", data, 24, 0x401000, 0, 0)
    struct.pack_into("<HHH", data, 52, 64, 0, 0)
    return bytes(data)


class HarnessTests(unittest.TestCase):
    def test_statistics(self) -> None:
        summary = summarize([1.0, 2.0, 3.0, 100.0])
        self.assertEqual(summary["samples"], 4)
        self.assertEqual(summary["median"], 2.5)
        self.assertEqual(summary["mad"], 1.0)
        self.assertEqual(summary["min"], 1.0)

    def test_paired_comparison(self) -> None:
        wild = [Sample(1.0, 0.0, 0.0), Sample(3.0, 0.0, 0.0)]
        lld = [Sample(2.0, 0.0, 0.0), Sample(2.5, 0.0, 0.0)]
        comparison = paired_comparison(wild, lld)
        self.assertEqual(comparison["pair_count"], 2)
        self.assertEqual(comparison["wild_faster_pairs"], 1)
        self.assertEqual(
            comparison["wild_minus_lld_seconds"]["raw_samples"], [-1.0, 0.5]
        )

    def test_cpu_list(self) -> None:
        self.assertEqual(parse_cpu_list("1-3,5"), (1, 2, 3, 5))
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_cpu_list("3-1")

    def test_thread_pair(self) -> None:
        self.assertEqual(parse_thread_pair("10:1"), ThreadPair(wild=10, lld_link=1))
        for invalid in ("10", "1:2:3", "0:1", "1:-2", "wild:1"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(argparse.ArgumentTypeError):
                    parse_thread_pair(invalid)

    def test_thread_pair_cli_is_mutually_exclusive_with_sweep(self) -> None:
        parsed = parser().parse_args(["--thread-pair", "10:1"])
        self.assertEqual(parsed.thread_pair, [ThreadPair(wild=10, lld_link=1)])
        self.assertIsNone(parsed.threads)

    def test_direct_pair_passes_distinct_threads_and_records_them(self) -> None:
        commands: list[list[str]] = []

        def fake_run_sample(
            command: list[str], cwd: Path, timeout: float, label: str
        ) -> Sample:
            del cwd, timeout, label
            commands.append(command)
            elapsed = 1.0 if command[0] == "/bin/wild" else 2.0
            return Sample(elapsed, 0.0, 0.0)

        tools = [
            Tool("wild", Path("/bin/wild"), ("-flavor", "link")),
            Tool("lld-link", Path("/bin/lld-link"), ()),
        ]
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch(f"{__name__}.run_sample", side_effect=fake_run_sample):
                result = benchmark_configuration(
                    tools=tools,
                    response=Path(directory) / "response.txt",
                    work=Path(directory),
                    mode="warm",
                    threads=10,
                    cache_paths=[],
                    taskset=None,
                    cpu_list=None,
                    warmups=0,
                    min_samples=2,
                    min_seconds=0.0,
                    max_samples=2,
                    rss_samples=0,
                    gnu_time=None,
                    timeout=1.0,
                    rng=random.Random(1),
                    thread_pair=ThreadPair(wild=10, lld_link=1),
                )

        wild_commands = [command for command in commands if command[0] == "/bin/wild"]
        lld_commands = [command for command in commands if command[0] == "/bin/lld-link"]
        self.assertTrue(all("/threads:10" in command for command in wild_commands))
        self.assertTrue(all("/threads:1" in command for command in lld_commands))
        self.assertEqual(result["thread_pair"], {"wild": 10, "lld-link": 1})
        self.assertEqual(result["tools"]["wild"]["threads"], 10)
        self.assertEqual(result["tools"]["lld-link"]["threads"], 1)
        self.assertEqual(result["paired_comparison"]["pair_count"], 2)

    def test_pe_baseline_pair_uses_wild_flavor_and_distinct_schema(self) -> None:
        commands: list[list[str]] = []

        def fake_run_sample(
            command: list[str], cwd: Path, timeout: float, label: str
        ) -> Sample:
            del cwd, timeout, label
            commands.append(command)
            return Sample(1.0, 0.0, 0.0)

        tools = [
            Tool("wild", Path("/bin/final-wild"), ("-flavor", "link")),
            Tool(
                "baseline-wild",
                Path("/bin/baseline-wild"),
                ("-flavor", "link"),
            ),
        ]
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch(f"{__name__}.run_sample", side_effect=fake_run_sample):
                result = benchmark_configuration(
                    tools=tools,
                    response=Path(directory) / "response.txt",
                    work=Path(directory),
                    mode="warm",
                    threads=8,
                    cache_paths=[],
                    taskset=None,
                    cpu_list=None,
                    warmups=0,
                    min_samples=1,
                    min_seconds=0.0,
                    max_samples=1,
                    rss_samples=0,
                    gnu_time=None,
                    timeout=1.0,
                    rng=random.Random(1),
                    thread_pair=ThreadPair(wild=8, lld_link=4),
                )
        self.assertTrue(all("-flavor" in command for command in commands))
        self.assertEqual(
            result["thread_pair"], {"wild": 8, "baseline-wild": 4}
        )
        self.assertIn("wild_over_baseline_wild_median_ratio", result)

    def test_pe_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "test.exe"
            image.write_bytes(minimal_pe())
            inspection = inspect_pe(image)
            self.assertEqual(inspection["machine"], "IMAGE_FILE_MACHINE_AMD64")
            self.assertEqual(inspection["entry_point_rva"], 0x1000)

    def test_pe_semantic_directories_and_expectation_mismatch(self) -> None:
        image_data = bytearray(minimal_pe())
        optional = 0x98
        struct.pack_into("<I", image_data, optional + 108, 16)
        struct.pack_into("<II", image_data, optional + 112 + 8, 0x2000, 80)
        struct.pack_into("<II", image_data, optional + 112 + 5 * 8, 0x3000, 32)
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "test.exe"
            image.write_bytes(image_data)
            inspection = inspect_pe(image)
        expected = pe_property_signature(inspection)
        self.assertTrue(expected["imports"])
        self.assertTrue(expected["base_relocations"])
        self.assertFalse(expected["exports"])
        enforce_output_expectations(
            inspection, {"properties": expected}, "pe"
        )
        wrong = {**expected, "imports": False}
        with self.assertRaisesRegex(BenchError, "frozen expectations"):
            enforce_output_expectations(
                inspection, {"properties": wrong}, "pe"
            )

    def test_property_disagreement_is_rejected(self) -> None:
        first = minimal_pe()
        with tempfile.TemporaryDirectory() as directory:
            left = Path(directory) / "left.exe"
            right = Path(directory) / "right.exe"
            left.write_bytes(first)
            changed = bytearray(first)
            struct.pack_into("<H", changed, 0x98 + 68, 2)
            right.write_bytes(changed)
            validations = {"wild": inspect_pe(left), "lld-link": inspect_pe(right)}
        with self.assertRaisesRegex(BenchError, "properties disagree"):
            require_matching_output_properties(validations, "pe")

    def test_elf_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "test"
            image.write_bytes(minimal_elf())
            inspection = inspect_elf(image)
            self.assertEqual(inspection["machine"], "EM_X86_64")
            self.assertEqual(inspection["entry_point"], 0x401000)

    def test_elf_run_with_command_and_tmpfs_output_environment(self) -> None:
        command = elf_command_for(
            Path("/corpus/run-with"),
            Tool("wild", Path("/bin/wild"), ()),
            8,
            Path("/usr/bin/taskset"),
            "2,3",
        )
        self.assertEqual(
            command,
            [
                "/usr/bin/taskset",
                "--cpu-list",
                "2,3",
                "/corpus/run-with",
                "/bin/wild",
                "--threads=8",
            ],
        )

    @unittest.skipUnless(Path("/dev/shm").is_dir(), "requires Linux /dev/shm tmpfs")
    def test_elf_synthetic_save_dir_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as corpus_directory:
            corpus = Path(corpus_directory)
            run_with = corpus / "run-with"
            run_with.write_text("#!/bin/sh\nexec \"$@\"\n", encoding="utf-8")
            run_with.chmod(0o755)
            linker = corpus / "synthetic-linker"
            linker.write_text(
                f"#!{sys.executable}\n"
                "import os, pathlib, sys\n"
                "if '--version' in sys.argv:\n"
                "    print('synthetic lld 1.0')\n"
                "else:\n"
                "    pathlib.Path(os.environ['OUT']).write_bytes("
                f"bytes.fromhex('{minimal_elf().hex()}'))\n",
                encoding="utf-8",
            )
            linker.chmod(0o755)
            args = parser().parse_args(
                [
                    "--format",
                    "elf",
                    "--corpus",
                    str(corpus),
                    "--wild",
                    str(linker),
                    "--ld-lld",
                    str(linker),
                    "--tmpfs-output-dir",
                    "/dev/shm",
                    "--mode",
                    "warm",
                    "--threads",
                    "1",
                    "--warmups",
                    "0",
                    "--min-samples",
                    "1",
                    "--min-seconds",
                    "0",
                    "--max-samples",
                    "1",
                    "--rss-samples",
                    "0",
                ]
            )
            report = run_elf_benchmark(args)
            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["settings"]["output_filesystem"], "tmpfs")
            self.assertTrue(report["validation"]["1"]["wild"]["deterministic"])

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

    def test_direct_pair_does_not_claim_thread_scaling(self) -> None:
        scaling = thread_scaling(
            [{"mode": "warm", "configuration": "direct-thread-pair"}]
        )
        self.assertEqual(
            scaling["warm"],
            {
                "available": False,
                "reason": "direct thread-pair confirmation does not measure thread scaling",
            },
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
    if args.link_format == "elf" and args.tmpfs_output_dir is None:
        parser().error("--tmpfs-output-dir is required with --format elf")
    if args.link_format == "elf" and args.baseline_wild is not None:
        parser().error("--baseline-wild is only valid for PE benchmarks")
    if args.selection_sweep is not None and not args.thread_pair:
        parser().error("--selection-sweep is only valid with --thread-pair")
    if args.mode is None:
        args.mode = ["warm", "cold-input-cache"]
    if args.threads is None:
        args.threads = [] if args.thread_pair else [1, 2, 4, 8]
    if len(set(args.mode)) != len(args.mode):
        parser().error("--mode values must be unique")
    if len(set(args.threads)) != len(args.threads):
        parser().error("--threads values must be unique")
    if args.thread_pair and len(set(args.thread_pair)) != len(args.thread_pair):
        parser().error("--thread-pair values must be unique")
    if args.max_samples < args.min_samples:
        parser().error("--max-samples must be at least --min-samples")
    destination = args.output.expanduser().resolve() if args.output else None
    if destination is not None and destination.exists():
        parser().error(f"refusing to overwrite existing output: {destination}")
    if destination is not None and not destination.parent.is_dir():
        parser().error(f"output parent directory does not exist: {destination.parent}")
    try:
        report = run_elf_benchmark(args) if args.link_format == "elf" else run_benchmark(args)
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
