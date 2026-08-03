#!/usr/bin/env python3
"""Benchmark replayable PE links without including compilation time."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import platform
import random
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest import mock

if os.name == "nt":
    import msvcrt
    from ctypes import wintypes

    resource = None
else:
    import resource

SCHEMA_VERSION = 1
AMD64_MACHINE = 0x8664
PE32_PLUS_MAGIC = 0x20B
WINDOWS = os.name == "nt"

if WINDOWS:
    CREATE_SUSPENDED = 0x00000004
    CREATE_NO_WINDOW = 0x08000000
    STARTF_USESTDHANDLES = 0x00000100
    WAIT_OBJECT_0 = 0x00000000
    WAIT_TIMEOUT = 0x00000102
    INFINITE = 0xFFFFFFFF
    STILL_ACTIVE = 259

    class _StartupInfo(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class _ProcessInformation(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    class _ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]


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
class WindowsExecution:
    sample: Sample
    peak_working_set_kib: int
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class ThreadPair:
    wild: int
    lld_link: int

    def metadata(self) -> dict[str, int]:
        return {"wild": self.wild, "lld-link": self.lld_link}


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _program_files_roots(environ: Mapping[str, str]) -> list[Path]:
    roots: list[Path] = []
    for name in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
        value = environ.get(name)
        if value:
            path = Path(value)
            if path not in roots:
                roots.append(path)
    return roots


def llvm_lld_candidates(
    environ: Mapping[str, str] = os.environ,
) -> list[Path]:
    """Return conventional LLVM lld-link locations in deterministic order."""
    candidates: list[Path] = []
    for root in _program_files_roots(environ):
        candidates.append(root / "LLVM" / "bin" / "lld-link.exe")
        visual_studio = root / "Microsoft Visual Studio"
        if visual_studio.is_dir():
            candidates.extend(
                sorted(
                    visual_studio.glob("*/*/VC/Tools/Llvm/x64/bin/lld-link.exe"),
                    key=lambda path: str(path).casefold(),
                    reverse=True,
                )
            )
    return candidates


def resolve_executable(value: str) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_file():
        return candidate.absolute()
    if WINDOWS and not candidate.suffix:
        executable_candidate = candidate.with_suffix(".exe")
        if executable_candidate.is_file():
            return executable_candidate.absolute()
    found = shutil.which(value)
    if found:
        return Path(found).absolute()
    if WINDOWS and candidate.name.casefold() in {"lld-link", "lld-link.exe"}:
        for llvm_candidate in llvm_lld_candidates():
            if llvm_candidate.is_file():
                return llvm_candidate.absolute()
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
    wild_samples: list[Sample], lld_samples: list[Sample]
) -> dict[str, Any]:
    paired_deltas = [
        wild.elapsed_seconds - lld.elapsed_seconds
        for wild, lld in zip(wild_samples, lld_samples, strict=True)
    ]
    paired_summary = summarize(paired_deltas)
    paired_summary["raw_samples"] = paired_deltas
    return {
        "delta_definition": "wild elapsed seconds minus lld-link elapsed seconds",
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


def windows_affinity_mask(cpu_list: str | None) -> int | None:
    if cpu_list is None:
        return None
    cpus = parse_cpu_list(cpu_list)
    mask_bits = ctypes.sizeof(ctypes.c_size_t) * 8
    if cpus[-1] >= mask_bits:
        raise BenchError(
            f"Windows affinity supports processor indices 0-{mask_bits - 1} in the "
            f"process primary processor group; requested CPU {cpus[-1]}"
        )
    return sum(1 << cpu for cpu in cpus)


def _filetime_seconds(value: Any) -> float:
    ticks = (value.dwHighDateTime << 32) | value.dwLowDateTime
    return ticks / 10_000_000.0


def _start_windows_process(
    kernel32: Any, process_handle: Any, thread_handle: Any, affinity_mask: int | None
) -> None:
    """Apply affinity while suspended, then permit the initial thread to run."""
    if affinity_mask is not None and not kernel32.SetProcessAffinityMask(
        process_handle, ctypes.c_size_t(affinity_mask)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    if kernel32.ResumeThread(thread_handle) == 0xFFFFFFFF:
        raise ctypes.WinError(ctypes.get_last_error())


def _windows_execute(
    command: list[str],
    cwd: Path,
    timeout: float,
    label: str,
    cpu_list: str | None,
) -> WindowsExecution:
    """Launch suspended, apply affinity, then collect native process metrics."""
    if not WINDOWS:
        raise BenchError("native Windows process execution is unavailable on this host")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(_StartupInfo),
        ctypes.POINTER(_ProcessInformation),
    ]
    kernel32.CreateProcessW.restype = wintypes.BOOL
    kernel32.SetProcessAffinityMask.argtypes = [wintypes.HANDLE, ctypes.c_size_t]
    kernel32.SetProcessAffinityMask.restype = wintypes.BOOL
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ProcessMemoryCounters),
        wintypes.DWORD,
    ]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

    affinity_mask = windows_affinity_mask(cpu_list)
    process = _ProcessInformation()
    with (
        tempfile.TemporaryFile() as stdin_file,
        tempfile.TemporaryFile() as stdout_file,
        tempfile.TemporaryFile() as stderr_file,
    ):
        inherited_handles = [
            msvcrt.get_osfhandle(file.fileno())
            for file in (stdin_file, stdout_file, stderr_file)
        ]
        for handle in inherited_handles:
            os.set_handle_inheritable(handle, True)
        startup = _StartupInfo()
        startup.cb = ctypes.sizeof(startup)
        startup.dwFlags = STARTF_USESTDHANDLES
        startup.hStdInput, startup.hStdOutput, startup.hStdError = inherited_handles
        command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
        started = time.perf_counter()
        created = kernel32.CreateProcessW(
            None,
            command_line,
            None,
            None,
            True,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            None,
            str(cwd),
            ctypes.byref(startup),
            ctypes.byref(process),
        )
        if not created:
            raise ctypes.WinError(ctypes.get_last_error())

        process_finished = False
        try:
            _start_windows_process(
                kernel32, process.hProcess, process.hThread, affinity_mask
            )
            wait_milliseconds = min(math.ceil(timeout * 1000), INFINITE - 1)
            wait_result = kernel32.WaitForSingleObject(
                process.hProcess, wait_milliseconds
            )
            elapsed = time.perf_counter() - started
            if wait_result == WAIT_TIMEOUT:
                kernel32.TerminateProcess(process.hProcess, 1)
                kernel32.WaitForSingleObject(process.hProcess, INFINITE)
                process_finished = True
                raise BenchError(f"{label} exceeded {timeout:.3f} seconds")
            if wait_result != WAIT_OBJECT_0:
                raise ctypes.WinError(ctypes.get_last_error())
            process_finished = True

            exit_code = wintypes.DWORD(STILL_ACTIVE)
            if not kernel32.GetExitCodeProcess(
                process.hProcess, ctypes.byref(exit_code)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            creation = wintypes.FILETIME()
            exit_time = wintypes.FILETIME()
            kernel = wintypes.FILETIME()
            user = wintypes.FILETIME()
            if not kernel32.GetProcessTimes(
                process.hProcess,
                ctypes.byref(creation),
                ctypes.byref(exit_time),
                ctypes.byref(kernel),
                ctypes.byref(user),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            memory = _ProcessMemoryCounters()
            memory.cb = ctypes.sizeof(memory)
            if not psapi.GetProcessMemoryInfo(
                process.hProcess, ctypes.byref(memory), memory.cb
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            stdout_file.seek(0)
            stderr_file.seek(0)
            return WindowsExecution(
                sample=Sample(
                    elapsed_seconds=elapsed,
                    user_seconds=_filetime_seconds(user),
                    system_seconds=_filetime_seconds(kernel),
                ),
                peak_working_set_kib=math.ceil(memory.PeakWorkingSetSize / 1024),
                returncode=exit_code.value,
                stdout=stdout_file.read(),
                stderr=stderr_file.read(),
            )
        finally:
            if not process_finished:
                kernel32.TerminateProcess(process.hProcess, 1)
                kernel32.WaitForSingleObject(process.hProcess, INFINITE)
            kernel32.CloseHandle(process.hThread)
            kernel32.CloseHandle(process.hProcess)


def _check_windows_execution(execution: WindowsExecution, label: str) -> None:
    if execution.returncode:
        stderr = execution.stderr.decode(errors="replace")[-4000:]
        stdout = execution.stdout.decode(errors="replace")[-2000:]
        raise BenchError(
            f"{label} exited with {execution.returncode}; "
            f"stdout={stdout!r}; stderr={stderr!r}"
        )


def run_sample(
    command: list[str],
    cwd: Path,
    timeout: float,
    label: str,
    cpu_list: str | None = None,
) -> Sample:
    if WINDOWS:
        execution = _windows_execute(command, cwd, timeout, label, cpu_list)
        _check_windows_execution(execution, label)
        return execution.sample

    assert resource is not None
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


def windows_peak_working_set(
    command: list[str],
    cwd: Path,
    output: Path,
    timeout: float,
    label: str,
    cpu_list: str | None,
) -> int:
    unlink_output(output)
    execution = _windows_execute(command, cwd, timeout, label, cpu_list)
    _check_windows_execution(execution, label)
    return execution.peak_working_set_kib


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
            cpu_list,
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
    thread_pair: ThreadPair | None = None,
) -> dict[str, Any]:
    samples: dict[str, list[Sample]] = {tool.name: [] for tool in tools}
    execution_order: list[list[str]] = []
    if thread_pair is None:
        tool_threads = {tool.name: threads for tool in tools}
        configuration_label = f"threads={threads}"
        output_label = str(threads)
    else:
        tool_threads = {"wild": thread_pair.wild, "lld-link": thread_pair.lld_link}
        configuration_label = (
            f"wild_threads={thread_pair.wild},lld_threads={thread_pair.lld_link}"
        )
        output_label = f"wild-{thread_pair.wild}-lld-{thread_pair.lld_link}"
    outputs = {
        tool.name: work / f"sample-{mode}-{output_label}-{tool.name}.exe"
        for tool in tools
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
            cpu_list,
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

    result: dict[str, Any] = {
        "mode": mode,
        "execution_order": execution_order,
        "tools": {},
    }
    if thread_pair is None:
        result["threads"] = threads
    else:
        result["configuration"] = "direct-thread-pair"
        result["thread_pair"] = thread_pair.metadata()
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
            if not WINDOWS and gnu_time is None:
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
                if WINDOWS:
                    rss_values.append(
                        windows_peak_working_set(
                            command,
                            response.parent,
                            output,
                            timeout,
                            "peak working set measurement",
                            cpu_list,
                        )
                    )
                else:
                    assert gnu_time is not None
                    rss_values.append(
                        gnu_time_rss(
                            gnu_time, command, response.parent, output, timeout
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
    lld_median = result["tools"]["lld-link"]["elapsed_seconds"]["median"]
    result["wild_over_lld_median_ratio"] = wild_median / lld_median
    if thread_pair is not None:
        result["paired_comparison"] = paired_comparison(
            samples["wild"], samples["lld-link"]
        )
    return result


def thread_scaling(configurations: list[dict[str, Any]]) -> dict[str, Any]:
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


def default_modes() -> list[str]:
    return ["warm"] if WINDOWS else ["warm", "cold-input-cache"]


def check_cache_modes(modes: list[str]) -> None:
    if WINDOWS and "cold-input-cache" in modes:
        raise BenchError(
            "cold-input-cache mode is unavailable on Windows: Windows has no "
            "per-file equivalent of POSIX_FADV_DONTNEED with the same advisory "
            "semantics, and this harness will not purge the system-wide standby "
            "list; use --mode warm"
        )


def run_benchmark(args: argparse.Namespace) -> dict[str, Any]:
    check_cache_modes(args.mode)
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
    taskset = resolve_executable("taskset") if args.cpu_list and not WINDOWS else None
    gnu_time = (
        resolve_executable(args.gnu_time) if args.rss_samples and not WINDOWS else None
    )
    cache_paths = sorted({*files, wild.path, lld.path}, key=str)
    rng = random.Random(args.seed)
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "running",
        "benchmark": "PE/COFF link-only lld /reproduce replay",
        "cache_mode_definition": {
            "warm": "ordinary repeated process runs with no explicit cache eviction",
            "cold-input-cache": (
                "unavailable on Windows; on POSIX, advisory POSIX_FADV_DONTNEED for "
                "corpus files and linker executables, not a global cold cache"
            ),
        },
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "logical_cpus": os.cpu_count(),
            "cpu_list": args.cpu_list,
            "affinity_semantics": (
                "SetProcessAffinityMask before ResumeThread in the primary processor "
                "group"
                if WINDOWS and args.cpu_list
                else "taskset --cpu-list wrapper"
                if args.cpu_list
                else "unrestricted"
            ),
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
            "timing_source": (
                "QueryPerformanceCounter/perf_counter wall time and GetProcessTimes"
                if WINDOWS
                else "perf_counter wall time and getrusage(RUSAGE_CHILDREN)"
            ),
            "peak_memory_source": (
                "GetProcessMemoryInfo PeakWorkingSetSize"
                if WINDOWS
                else "GNU time maximum resident set size"
            ),
        },
        "configurations": [],
    }
    if args.thread_pair:
        report["settings"]["thread_pairs"] = [
            thread_pair.metadata() for thread_pair in args.thread_pair
        ]
    with tempfile.TemporaryDirectory(prefix="wild-pe-link-bench-") as directory:
        work = Path(directory)
        for mode in args.mode:
            if args.thread_pair:
                for thread_pair in args.thread_pair:
                    log(
                        f"benchmarking mode={mode}, wild_threads={thread_pair.wild}, "
                        f"lld_threads={thread_pair.lld_link}"
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
        report["thread_scaling"] = thread_scaling(report["configurations"])
        validations: dict[str, Any] = {}
        if args.thread_pair:
            for thread_pair in args.thread_pair:
                key = f"wild-{thread_pair.wild}-lld-{thread_pair.lld_link}"
                validations[key] = {
                    "configuration": "direct-thread-pair",
                    "thread_pair": thread_pair.metadata(),
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
                    )
                    validation["threads"] = threads
                    validations[key]["tools"][tool.name] = validation
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
        help=(
            "repeatable; defaults to warm on Windows, and warm plus "
            "cold-input-cache on POSIX"
        ),
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
            with (
                self.subTest(invalid=invalid),
                self.assertRaises(argparse.ArgumentTypeError),
            ):
                parse_thread_pair(invalid)

    def test_thread_pair_cli_is_mutually_exclusive_with_sweep(self) -> None:
        parsed = parser().parse_args(["--thread-pair", "10:1"])
        self.assertEqual(parsed.thread_pair, [ThreadPair(wild=10, lld_link=1)])
        self.assertIsNone(parsed.threads)

    def test_direct_pair_passes_distinct_threads_and_records_them(self) -> None:
        commands: list[list[str]] = []

        def fake_run_sample(
            command: list[str],
            cwd: Path,
            timeout: float,
            label: str,
            cpu_list: str | None = None,
        ) -> Sample:
            del cwd, timeout, label, cpu_list
            commands.append(command)
            elapsed = 1.0 if command[0] == "/bin/wild" else 2.0
            return Sample(elapsed, 0.0, 0.0)

        tools = [
            Tool("wild", Path("/bin/wild"), ("-flavor", "link")),
            Tool("lld-link", Path("/bin/lld-link"), ()),
        ]
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch(f"{__name__}.run_sample", side_effect=fake_run_sample),
        ):
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
        lld_commands = [
            command for command in commands if command[0] == "/bin/lld-link"
        ]
        self.assertTrue(all("/threads:10" in command for command in wild_commands))
        self.assertTrue(all("/threads:1" in command for command in lld_commands))
        self.assertEqual(result["thread_pair"], {"wild": 10, "lld-link": 1})
        self.assertEqual(result["tools"]["wild"]["threads"], 10)
        self.assertEqual(result["tools"]["lld-link"]["threads"], 1)
        self.assertEqual(result["paired_comparison"]["pair_count"], 2)

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
                str(Path("/bin/wild")),
                "-flavor",
                "link",
                "@response.txt",
                f"/out:{Path('/tmp/out.exe')}",
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

    def test_windows_affinity_mask(self) -> None:
        self.assertEqual(windows_affinity_mask("0,2-3"), 0b1101)
        with (
            mock.patch(f"{__name__}.ctypes.sizeof", return_value=4),
            self.assertRaisesRegex(BenchError, "0-31"),
        ):
            windows_affinity_mask("32")

    def test_windows_affinity_is_applied_before_resume(self) -> None:
        calls: list[tuple[str, int]] = []

        class FakeKernel32:
            def SetProcessAffinityMask(self, process: int, mask: Any) -> bool:
                calls.append(("affinity", mask.value))
                self.assert_process = process
                return True

            def ResumeThread(self, thread: int) -> int:
                calls.append(("resume", thread))
                return 1

        kernel32 = FakeKernel32()
        _start_windows_process(kernel32, 10, 20, 0b101)
        self.assertEqual(calls, [("affinity", 0b101), ("resume", 20)])

    def test_windows_run_sample_dispatch_and_process_metrics(self) -> None:
        execution = WindowsExecution(
            sample=Sample(0.25, 0.1, 0.05),
            peak_working_set_kib=123,
            returncode=0,
            stdout=b"",
            stderr=b"",
        )
        with (
            mock.patch(f"{__name__}.WINDOWS", True),
            mock.patch(
                f"{__name__}._windows_execute", return_value=execution
            ) as execute,
        ):
            sample = run_sample(["lld-link.exe"], Path("C:/corpus"), 2.0, "lld", "1,3")
        self.assertEqual(sample, execution.sample)
        execute.assert_called_once_with(
            ["lld-link.exe"], Path("C:/corpus"), 2.0, "lld", "1,3"
        )

    def test_windows_rss_samples_use_peak_working_set(self) -> None:
        tools = [
            Tool("wild", Path("C:/bin/wild.exe"), ("-flavor", "link")),
            Tool("lld-link", Path("C:/bin/lld-link.exe"), ()),
        ]

        def fake_sample(*args: Any, **kwargs: Any) -> Sample:
            command = args[0]
            return Sample(1.0 if "wild.exe" in command[0] else 2.0, 0.1, 0.1)

        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch(f"{__name__}.WINDOWS", True),
            mock.patch(f"{__name__}.run_sample", side_effect=fake_sample),
            mock.patch(
                f"{__name__}.windows_peak_working_set", side_effect=[100, 200]
            ) as peak,
        ):
            result = benchmark_configuration(
                tools=tools,
                response=Path(directory) / "response.txt",
                work=Path(directory),
                mode="warm",
                threads=1,
                cache_paths=[],
                taskset=None,
                cpu_list="0",
                warmups=0,
                min_samples=1,
                min_seconds=0.0,
                max_samples=1,
                rss_samples=1,
                gnu_time=None,
                timeout=1.0,
                rng=random.Random(1),
            )
        self.assertEqual(peak.call_count, 2)
        rss_values = sorted(
            result["tools"][name]["maximum_rss_kib"]["raw_samples"]
            for name in ("wild", "lld-link")
        )
        self.assertEqual(rss_values, [[100], [200]])

    def test_windows_nonzero_exit_reports_captured_output(self) -> None:
        execution = WindowsExecution(
            sample=Sample(0.1, 0.0, 0.0),
            peak_working_set_kib=1,
            returncode=7,
            stdout=b"out",
            stderr=b"bad",
        )
        with self.assertRaisesRegex(BenchError, "exited with 7.*bad"):
            _check_windows_execution(execution, "link")

    def test_windows_rejects_cold_cache_with_actionable_message(self) -> None:
        with mock.patch(f"{__name__}.WINDOWS", True):
            self.assertEqual(default_modes(), ["warm"])
            with self.assertRaisesRegex(BenchError, "use --mode warm"):
                check_cache_modes(["cold-input-cache"])

    def test_posix_defaults_remain_warm_and_cold(self) -> None:
        with mock.patch(f"{__name__}.WINDOWS", False):
            self.assertEqual(default_modes(), ["warm", "cold-input-cache"])
            check_cache_modes(["warm", "cold-input-cache"])

    def test_windows_discovers_llvm_under_program_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lld = Path(directory) / "LLVM" / "bin" / "lld-link.exe"
            lld.parent.mkdir(parents=True)
            lld.write_bytes(b"lld")
            with (
                mock.patch(f"{__name__}.WINDOWS", True),
                mock.patch(f"{__name__}.shutil.which", return_value=None),
                mock.patch(f"{__name__}.llvm_lld_candidates", return_value=[lld]),
            ):
                self.assertEqual(resolve_executable("lld-link"), lld.absolute())

    @unittest.skipUnless(WINDOWS, "native Win32 smoke test")
    def test_native_windows_process_measurement(self) -> None:
        command = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", "exit", "0"]
        execution = _windows_execute(command, Path.cwd(), 10.0, "smoke", "0")
        self.assertEqual(execution.returncode, 0)
        self.assertGreater(execution.sample.elapsed_seconds, 0.0)
        self.assertGreater(execution.peak_working_set_kib, 0)
        self.assertGreaterEqual(execution.sample.user_seconds, 0.0)
        self.assertGreaterEqual(execution.sample.system_seconds, 0.0)


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
        args.mode = default_modes()
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
