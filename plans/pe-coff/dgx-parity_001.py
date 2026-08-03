#!/usr/bin/env python3
"""Aggregate frozen DGX PE/ELF holdouts and decide Goal 3 parity."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import math
import random
import statistics
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
REQUIRED_CORPORA = ("rust-std", "ripgrep", "rust-analyzer", "uv")
BOOTSTRAP_RESAMPLES = 10_000


class AggregateError(RuntimeError):
    """Invalid, incomplete, or non-authoritative benchmark evidence."""


@dataclass(frozen=True)
class Artifact:
    path: Path
    sha256: str
    report: dict[str, Any]


@dataclass(frozen=True)
class PairSamples:
    wild: tuple[float, ...]
    comparator: tuple[float, ...]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        raise AggregateError("cannot calculate a percentile of no values")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def interval(values: list[float]) -> dict[str, float]:
    return {
        "lower_95": percentile(values, 0.025),
        "upper_95": percentile(values, 0.975),
    }


def geometric_mean(values: list[float]) -> float:
    if not values or any(value <= 0 or not math.isfinite(value) for value in values):
        raise AggregateError("geometric mean inputs must be finite and positive")
    return math.exp(sum(math.log(value) for value in values) / len(values))


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AggregateError(f"invalid JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise AggregateError(f"JSON root must be an object: {path}")
    return value


def load_artifact(
    manifest_dir: Path, reference: dict[str, Any], label: str
) -> Artifact:
    if set(reference) != {"path", "sha256"}:
        raise AggregateError(f"{label} reference must contain only path and sha256")
    path = Path(reference["path"])
    if not path.is_absolute():
        path = manifest_dir / path
    path = path.resolve()
    if not path.is_file():
        raise AggregateError(f"{label} artifact does not exist: {path}")
    actual = sha256_file(path)
    expected = reference["sha256"]
    if actual != expected:
        raise AggregateError(
            f"{label} SHA-256 mismatch: expected {expected}, got {actual}"
        )
    return Artifact(path, actual, load_json(path))


def parse_time(value: Any, label: str) -> datetime.datetime:
    if not isinstance(value, str):
        raise AggregateError(f"{label} timestamp is missing")
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except ValueError as error:
        raise AggregateError(f"{label} timestamp is invalid: {value!r}") from error
    if parsed.tzinfo is None:
        raise AggregateError(f"{label} timestamp must include a timezone")
    return parsed


def tool_identity(report: dict[str, Any], name: str) -> dict[str, str]:
    try:
        tool = report["tools"][name]
        return {"sha256": tool["sha256"], "version": tool["version"]}
    except (KeyError, TypeError) as error:
        raise AggregateError(f"missing {name} provenance") from error


def require_identity(
    report: dict[str, Any], name: str, expected: dict[str, Any], label: str
) -> None:
    actual = tool_identity(report, name)
    required = {"sha256": expected.get("sha256"), "version": expected.get("version")}
    if actual != required:
        raise AggregateError(
            f"{label} {name} identity drift: expected {required}, got {actual}"
        )


def validated_rss_median(
    configuration: dict[str, Any],
    tool_name: str,
    protocol: dict[str, Any],
    label: str,
) -> float:
    try:
        rss = configuration["tools"][tool_name]["maximum_rss_kib"]
        raw_values = rss["raw_samples"]
        if any(isinstance(value, bool) for value in raw_values):
            raise ValueError
        values = [float(value) for value in raw_values]
        reported_median = float(rss["median"])
    except (KeyError, TypeError, ValueError) as error:
        raise AggregateError(f"{label} {tool_name} has invalid RSS evidence") from error
    if len(values) < protocol["rss_samples"]:
        raise AggregateError(f"{label} {tool_name} lacks required RSS samples")
    if any(value <= 0 or not math.isfinite(value) for value in values):
        raise AggregateError(
            f"{label} {tool_name} has a non-positive/non-finite RSS sample"
        )
    calculated_median = statistics.median(values)
    if (
        reported_median <= 0
        or not math.isfinite(reported_median)
        or not math.isclose(
            reported_median, calculated_median, rel_tol=1e-12, abs_tol=1e-12
        )
    ):
        raise AggregateError(f"{label} {tool_name} RSS median does not match raw data")
    return calculated_median


def configuration_samples(
    configuration: dict[str, Any],
    tool_names: tuple[str, str],
    protocol: dict[str, Any],
    label: str,
) -> PairSamples:
    values: list[tuple[float, ...]] = []
    for name in tool_names:
        try:
            raw = configuration["tools"][name]["raw_samples"]
            elapsed = tuple(float(sample["elapsed_seconds"]) for sample in raw)
        except (KeyError, TypeError, ValueError) as error:
            raise AggregateError(f"{label} has invalid {name} raw samples") from error
        if len(elapsed) < protocol["min_samples"]:
            raise AggregateError(f"{label} {name} has too few samples: {len(elapsed)}")
        if sum(elapsed) < protocol["min_accumulated_seconds"]:
            raise AggregateError(f"{label} {name} has too little accumulated time")
        if any(value <= 0 or not math.isfinite(value) for value in elapsed):
            raise AggregateError(f"{label} {name} has a non-positive/non-finite sample")
        validated_rss_median(configuration, name, protocol, label)
        values.append(elapsed)
    if len(values[0]) != len(values[1]):
        raise AggregateError(f"{label} does not contain complete paired blocks")
    orders = configuration.get("execution_order")
    if not isinstance(orders, list) or len(orders) != len(values[0]):
        raise AggregateError(f"{label} execution-order blocks do not match samples")
    expected_names = set(tool_names)
    if any(set(order) != expected_names or len(order) != 2 for order in orders):
        raise AggregateError(f"{label} has a malformed randomized execution block")
    return PairSamples(values[0], values[1])


def common_protocol_check(
    artifact: Artifact,
    protocol: dict[str, Any],
    role: str,
    label: str,
    elf: bool,
) -> None:
    report = artifact.report
    if report.get("schema_version") != SCHEMA_VERSION or report.get("status") != "pass":
        raise AggregateError(f"{label} is not a passing schema-v{SCHEMA_VERSION} report")
    settings = report.get("settings", {})
    if settings.get("benchmark_role") != role:
        raise AggregateError(
            f"{label} has role {settings.get('benchmark_role')!r}, expected {role}"
        )
    if settings.get("modes") != [protocol["mode"]]:
        raise AggregateError(f"{label} must contain only {protocol['mode']!r} mode")
    if report.get("host", {}).get("cpu_list") != protocol["cpu_list"]:
        raise AggregateError(f"{label} CPU affinity differs from the frozen protocol")
    if report.get("host", {}).get("environment_note") != protocol["environment_note"]:
        raise AggregateError(f"{label} interference-control provenance drift")
    if report.get("host", {}).get("machine") not in ("aarch64", "arm64"):
        raise AggregateError(f"{label} was not measured by a native AArch64 process")
    for key in ("min_samples", "rss_samples"):
        if settings.get(key, -1) < protocol[key]:
            raise AggregateError(f"{label} setting {key} is below the protocol floor")
    if settings.get("min_accumulated_seconds", -1) < protocol["min_accumulated_seconds"]:
        raise AggregateError(f"{label} accumulated-time floor is too low")
    if settings.get("output_filesystem") != "tmpfs" or not settings.get(
        "output_directory"
    ):
        raise AggregateError(f"{label} authority output was not written to tmpfs")
    if elf:
        if report.get("link_format") != "elf":
            raise AggregateError(f"{label} is not marked as an ELF replay")


def corpus_and_invocation_check(
    report: dict[str, Any], expected: dict[str, Any], elf: bool, label: str
) -> None:
    corpus_hash = report.get("corpus", {}).get("manifest_sha256")
    if corpus_hash != expected.get("corpus_manifest_sha256"):
        raise AggregateError(f"{label} corpus manifest drift")
    key = "run_with_sha256" if elf else "response_sha256"
    invocation_hash = report.get("invocation", {}).get(key)
    if invocation_hash != expected.get("invocation_sha256"):
        raise AggregateError(f"{label} effective linker invocation drift")
    corpus_invocation_hash = report.get("corpus", {}).get(key)
    if corpus_invocation_hash != invocation_hash:
        raise AggregateError(f"{label} corpus/invocation hash disagreement")
    invocation = report.get("invocation", {})
    if elf:
        if invocation.get("command_template") != (
            "run-with <native-linker> --threads=<selected-count>"
        ) or invocation.get("output_environment") != "OUT=<per-sample-tmpfs-path>":
            raise AggregateError(f"{label} ELF command template drift")
    elif invocation.get("output_override") != "/out:<per-sample-path>" or invocation.get(
        "thread_override"
    ) != "/threads:<selected-count>":
        raise AggregateError(f"{label} PE command override drift")
    frozen_output = report.get("output_expectations", {})
    if not frozen_output.get("path"):
        raise AggregateError(f"{label} output-expectation path is missing")
    if frozen_output.get("sha256") != expected.get("output_expectations_sha256"):
        raise AggregateError(f"{label} output-expectation artifact drift")
    if frozen_output.get("properties") != expected.get("output_properties"):
        raise AggregateError(f"{label} frozen output properties drift")


def validation_signature(result: dict[str, Any], elf: bool) -> dict[str, Any]:
    if elf:
        return {
            "format": "elf",
            "machine": result.get("machine"),
            "type": result.get("type"),
            "entry_point_nonzero": bool(result.get("entry_point")),
        }
    directories = result.get("data_directories", {})
    return {
        "format": "pe",
        "machine": result.get("machine"),
        "subsystem": result.get("subsystem"),
        "entry_point_nonzero": bool(result.get("entry_point_rva")),
        "exports": directories.get("exports", {}).get("present"),
        "imports": directories.get("imports", {}).get("present"),
        "base_relocations": directories.get("base_relocations", {}).get("present"),
    }


def best_threads(
    sweep: Artifact, tool_name: str, protocol: dict[str, Any], label: str
) -> int:
    configurations = sweep.report.get("configurations", [])
    expected_threads = set(protocol["thread_counts"])
    actual_threads = {
        configuration.get("threads")
        for configuration in configurations
        if configuration.get("mode") == protocol["mode"]
    }
    if actual_threads != expected_threads or len(configurations) != len(expected_threads):
        raise AggregateError(f"{label} sweep does not match frozen thread counts")
    try:
        winner = min(
            configurations,
            key=lambda configuration: (
                configuration["tools"][tool_name]["elapsed_seconds"]["median"],
                configuration["threads"],
            ),
        )
        return int(winner["threads"])
    except (KeyError, TypeError, ValueError) as error:
        raise AggregateError(f"{label} sweep lacks {tool_name} medians") from error


def require_determinism(
    report: dict[str, Any],
    tool_names: tuple[str, ...],
    label: str,
    expected_machine: str,
    expected_properties: dict[str, Any],
) -> None:
    validations = report.get("validation")
    if not isinstance(validations, dict) or len(validations) != 1:
        raise AggregateError(f"{label} must have exactly one direct validation")
    validation = next(iter(validations.values()))
    tools = validation.get("tools", validation)
    for name in tool_names:
        result = tools.get(name)
        if not isinstance(result, dict) or not result.get("deterministic"):
            raise AggregateError(f"{label} {name} output is not deterministic")
        if not result.get("sha256") or result.get("sha256") != result.get("second_sha256"):
            raise AggregateError(f"{label} {name} validation hashes disagree")
        if result.get("machine") != expected_machine:
            raise AggregateError(f"{label} {name} output machine drift")
        signature = validation_signature(
            result, expected_properties["format"] == "elf"
        )
        if signature != expected_properties:
            raise AggregateError(f"{label} {name} output properties drift")


def require_sweep_evidence(
    report: dict[str, Any],
    tool_names: tuple[str, str],
    protocol: dict[str, Any],
    label: str,
    require_comparator_determinism: bool,
    expected_machine: str,
    expected_properties: dict[str, Any],
) -> None:
    configurations = report.get("configurations", [])
    for configuration in configurations:
        configuration_samples(configuration, tool_names, protocol, label)
    validations = report.get("validation")
    if not isinstance(validations, dict) or len(validations) != len(configurations):
        raise AggregateError(f"{label} validation count differs from sweep count")
    required = tool_names if require_comparator_determinism else ("wild",)
    for key, validation in validations.items():
        tools = validation.get("tools", validation)
        for name in required:
            result = tools.get(name)
            if not isinstance(result, dict) or not result.get("deterministic"):
                raise AggregateError(f"{label} validation {key} is not deterministic for {name}")
            if result.get("sha256") != result.get("second_sha256"):
                raise AggregateError(f"{label} validation {key} hash mismatch for {name}")
            if result.get("machine") != expected_machine:
                raise AggregateError(f"{label} validation {key} machine drift for {name}")
            if validation_signature(
                result, expected_properties["format"] == "elf"
            ) != expected_properties:
                raise AggregateError(f"{label} validation {key} properties drift for {name}")


def validate_series(
    manifest_dir: Path,
    spec: dict[str, Any],
    protocol: dict[str, Any],
    identities: dict[str, Any],
    family: str,
    label: str,
) -> tuple[PairSamples, dict[str, Any]]:
    elf = family == "elf"
    comparator = "ld.lld" if elf else "lld-link"
    identity_keys = ("wild-elf", "ld.lld") if elf else ("wild-pe", "lld-link")
    sweep = load_artifact(manifest_dir, spec["sweep"], f"{label} sweep")
    direct = load_artifact(manifest_dir, spec["direct"], f"{label} direct")
    common_protocol_check(sweep, protocol, "thread-sweep", f"{label} sweep", elf)
    common_protocol_check(direct, protocol, "direct-holdout", f"{label} direct", elf)
    expected = spec["expected"]
    for artifact in (sweep, direct):
        corpus_and_invocation_check(artifact.report, expected, elf, label)
        require_identity(artifact.report, "wild", identities[identity_keys[0]], label)
        require_identity(artifact.report, comparator, identities[identity_keys[1]], label)
    require_sweep_evidence(
        sweep.report,
        ("wild", comparator),
        protocol,
        f"{label} sweep",
        True,
        "EM_X86_64" if elf else "IMAGE_FILE_MACHINE_AMD64",
        expected["output_properties"],
    )
    if sweep.sha256 == direct.sha256:
        raise AggregateError(f"{label} sweep and holdout are the same artifact")
    selection = direct.report.get("settings", {}).get("selection_sweep", {})
    if selection.get("sha256") != sweep.sha256:
        raise AggregateError(f"{label} direct holdout is not bound to its sweep")
    if parse_time(direct.report.get("started_at_utc"), f"{label} direct") <= parse_time(
        sweep.report.get("finished_at_utc"), f"{label} sweep"
    ):
        raise AggregateError(f"{label} direct holdout did not start after its sweep")
    if direct.report["settings"].get("random_seed") == sweep.report["settings"].get(
        "random_seed"
    ):
        raise AggregateError(f"{label} direct holdout must use a fresh random seed")
    wild_threads = best_threads(sweep, "wild", protocol, label)
    comparator_threads = best_threads(sweep, comparator, protocol, label)
    frozen_threads = expected.get("selected_threads")
    required_threads = {"wild": wild_threads, comparator: comparator_threads}
    if frozen_threads != required_threads:
        raise AggregateError(
            f"{label} selected configuration drift: expected {frozen_threads}, "
            f"sweep selected {required_threads}"
        )
    configurations = direct.report.get("configurations", [])
    if len(configurations) != 1:
        raise AggregateError(f"{label} direct report must contain one configuration")
    configuration = configurations[0]
    if configuration.get("configuration") != "direct-thread-pair":
        raise AggregateError(f"{label} direct report is not a thread-pair holdout")
    if configuration.get("thread_pair") != required_threads:
        raise AggregateError(f"{label} holdout thread pair differs from the sweep selection")
    pairs = configuration_samples(
        configuration, ("wild", comparator), protocol, f"{label} direct"
    )
    require_determinism(
        direct.report,
        ("wild", comparator),
        f"{label} direct",
        "EM_X86_64" if elf else "IMAGE_FILE_MACHINE_AMD64",
        expected["output_properties"],
    )
    rss = {
        "wild_median_kib": validated_rss_median(
            configuration, "wild", protocol, f"{label} direct"
        ),
        "comparator_median_kib": validated_rss_median(
            configuration, comparator, protocol, f"{label} direct"
        ),
    }
    rss["wild_over_comparator"] = rss["wild_median_kib"] / rss["comparator_median_kib"]
    return pairs, rss


def validate_baseline_series(
    manifest_dir: Path,
    spec: dict[str, Any],
    protocol: dict[str, Any],
    identities: dict[str, Any],
    label: str,
) -> tuple[PairSamples, dict[str, float]]:
    baseline_spec = {
        "sweep": spec["baseline_sweep"],
        "direct": spec["baseline_direct"],
        "expected": spec["baseline_expected"],
    }
    sweep = load_artifact(manifest_dir, baseline_spec["sweep"], f"{label} baseline sweep")
    direct = load_artifact(manifest_dir, baseline_spec["direct"], f"{label} baseline direct")
    for artifact, role in ((sweep, "thread-sweep"), (direct, "direct-holdout")):
        common_protocol_check(artifact, protocol, role, f"{label} baseline {role}", False)
        corpus_and_invocation_check(
            artifact.report, baseline_spec["expected"], False, f"{label} baseline"
        )
        require_identity(artifact.report, "wild", identities["wild-pe"], label)
        require_identity(
            artifact.report, "baseline-wild", identities["baseline-wild-pe"], label
        )
    require_sweep_evidence(
        sweep.report,
        ("wild", "baseline-wild"),
        protocol,
        f"{label} baseline sweep",
        True,
        "IMAGE_FILE_MACHINE_AMD64",
        baseline_spec["expected"]["output_properties"],
    )
    if sweep.sha256 == direct.sha256:
        raise AggregateError(f"{label} baseline sweep and holdout are identical")
    selection = direct.report.get("settings", {}).get("selection_sweep", {})
    if selection.get("sha256") != sweep.sha256:
        raise AggregateError(f"{label} baseline holdout is not bound to its sweep")
    if parse_time(direct.report.get("started_at_utc"), label) <= parse_time(
        sweep.report.get("finished_at_utc"), label
    ):
        raise AggregateError(f"{label} baseline holdout predates its sweep")
    if direct.report["settings"].get("random_seed") == sweep.report["settings"].get(
        "random_seed"
    ):
        raise AggregateError(f"{label} baseline holdout must use a fresh seed")
    wild_threads = best_threads(sweep, "wild", protocol, label)
    baseline_threads = best_threads(sweep, "baseline-wild", protocol, label)
    required_threads = {"wild": wild_threads, "baseline-wild": baseline_threads}
    if baseline_spec["expected"].get("selected_threads") != required_threads:
        raise AggregateError(f"{label} baseline selected configuration drift")
    configurations = direct.report.get("configurations", [])
    if len(configurations) != 1 or configurations[0].get("thread_pair") != required_threads:
        raise AggregateError(f"{label} baseline direct configuration drift")
    pairs = configuration_samples(
        configurations[0], ("wild", "baseline-wild"), protocol, label
    )
    require_determinism(
        direct.report,
        ("wild", "baseline-wild"),
        label,
        "IMAGE_FILE_MACHINE_AMD64",
        baseline_spec["expected"]["output_properties"],
    )
    configuration = configurations[0]
    rss = {
        "final_wild_median_kib": validated_rss_median(
            configuration, "wild", protocol, label
        ),
        "baseline_wild_median_kib": validated_rss_median(
            configuration, "baseline-wild", protocol, label
        ),
    }
    rss["final_over_baseline"] = (
        rss["final_wild_median_kib"] / rss["baseline_wild_median_kib"]
    )
    return pairs, rss


def resampled_ratio(
    pairs: PairSamples, rng: random.Random, comparator_over_wild: bool
) -> float:
    indices = [rng.randrange(len(pairs.wild)) for _ in pairs.wild]
    wild = statistics.median(pairs.wild[index] for index in indices)
    comparator = statistics.median(pairs.comparator[index] for index in indices)
    return comparator / wild if comparator_over_wild else wild / comparator


def point_ratio(pairs: PairSamples, comparator_over_wild: bool) -> float:
    wild = statistics.median(pairs.wild)
    comparator = statistics.median(pairs.comparator)
    return comparator / wild if comparator_over_wild else wild / comparator


def compute_statistics(
    series: dict[str, dict[str, PairSamples]], seed: int, resamples: int
) -> dict[str, Any]:
    pe_rng = random.Random(seed ^ 0x5045_5045)
    elf_rng = random.Random(seed ^ 0x454C_4600)
    baseline_rng = random.Random(seed ^ 0x4241_5345)
    distributions: dict[str, Any] = {
        name: {"pe": [], "elf": [], "baseline_time_ratio": []}
        for name in REQUIRED_CORPORA
    }
    pe_aggregate: list[float] = []
    elf_aggregate: list[float] = []
    parity: list[float] = []
    for _ in range(resamples):
        pe_values = []
        elf_values = []
        for name in REQUIRED_CORPORA:
            pe_value = resampled_ratio(series[name]["pe"], pe_rng, True)
            elf_value = resampled_ratio(series[name]["elf"], elf_rng, True)
            baseline_value = resampled_ratio(
                series[name]["baseline"], baseline_rng, False
            )
            distributions[name]["pe"].append(pe_value)
            distributions[name]["elf"].append(elf_value)
            distributions[name]["baseline_time_ratio"].append(baseline_value)
            pe_values.append(pe_value)
            elf_values.append(elf_value)
        pe_gm = geometric_mean(pe_values)
        elf_gm = geometric_mean(elf_values)
        pe_aggregate.append(pe_gm)
        elf_aggregate.append(elf_gm)
        parity.append(pe_gm / elf_gm)

    per_corpus: dict[str, Any] = {}
    for name in REQUIRED_CORPORA:
        pe_point = point_ratio(series[name]["pe"], True)
        elf_point = point_ratio(series[name]["elf"], True)
        baseline_point = point_ratio(series[name]["baseline"], False)
        pe_ci = interval(distributions[name]["pe"])
        pe_time_distribution = [1.0 / value for value in distributions[name]["pe"]]
        per_corpus[name] = {
            "pe_speedup": {"point": pe_point, **pe_ci},
            "pe_wild_over_lld_time_ratio": {
                "point": 1.0 / pe_point,
                **interval(pe_time_distribution),
            },
            "elf_speedup": {
                "point": elf_point,
                **interval(distributions[name]["elf"]),
            },
            "final_over_baseline_wild_time_ratio": {
                "point": baseline_point,
                **interval(distributions[name]["baseline_time_ratio"]),
            },
        }
    pe_points = [per_corpus[name]["pe_speedup"]["point"] for name in REQUIRED_CORPORA]
    elf_points = [per_corpus[name]["elf_speedup"]["point"] for name in REQUIRED_CORPORA]
    aggregate = {
        "pe_speedup": {"point": geometric_mean(pe_points), **interval(pe_aggregate)},
        "elf_speedup": {"point": geometric_mean(elf_points), **interval(elf_aggregate)},
        "parity": {
            "point": geometric_mean(pe_points) / geometric_mean(elf_points),
            **interval(parity),
        },
    }
    checks = {
        "pe_speedup_lower_95_gt_1": aggregate["pe_speedup"]["lower_95"] > 1.0,
        "parity_lower_95_gte_1": aggregate["parity"]["lower_95"] >= 1.0,
        "rust_analyzer_pe_lower_95_gt_1": (
            per_corpus["rust-analyzer"]["pe_speedup"]["lower_95"] > 1.0
        ),
        "uv_pe_lower_95_gt_1": per_corpus["uv"]["pe_speedup"]["lower_95"] > 1.0,
        "all_pe_time_upper_95_lte_1_03": all(
            per_corpus[name]["pe_wild_over_lld_time_ratio"]["upper_95"] <= 1.03
            for name in REQUIRED_CORPORA
        ),
        "all_baseline_time_upper_95_lte_1_03": all(
            per_corpus[name]["final_over_baseline_wild_time_ratio"]["upper_95"]
            <= 1.03
            for name in REQUIRED_CORPORA
        ),
    }
    return {
        "estimator": (
            "ratio of direct-holdout tool medians; unweighted four-corpus "
            "geometric means"
        ),
        "bootstrap": {
            "method": "paired-block percentile, PE/ELF/baseline independently resampled",
            "resamples": resamples,
            "seed": seed,
            "interval": "two-sided 95%",
        },
        "per_corpus": per_corpus,
        "aggregate": aggregate,
        "checks": checks,
        "goal_pass": all(checks.values()),
    }


def aggregate(manifest_path: Path) -> dict[str, Any]:
    manifest_path = manifest_path.expanduser().resolve()
    manifest = load_json(manifest_path)
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise AggregateError(f"matrix manifest schema must be {SCHEMA_VERSION}")
    bootstrap = manifest.get("bootstrap", {})
    if bootstrap.get("resamples") != BOOTSTRAP_RESAMPLES:
        raise AggregateError(f"bootstrap resamples must be {BOOTSTRAP_RESAMPLES}")
    if not isinstance(bootstrap.get("seed"), int):
        raise AggregateError("bootstrap seed must be a frozen integer")
    protocol = manifest.get("protocol", {})
    required_protocol = {
        "mode",
        "cpu_list",
        "thread_counts",
        "min_samples",
        "min_accumulated_seconds",
        "rss_samples",
        "environment_note",
    }
    if not required_protocol.issubset(protocol):
        raise AggregateError("matrix manifest has an incomplete protocol")
    if (
        protocol["mode"] != "warm"
        or not protocol["cpu_list"]
        or not protocol["environment_note"]
    ):
        raise AggregateError("authoritative parity requires warm mode and fixed CPU affinity")
    if protocol["min_samples"] < 15 or protocol["min_accumulated_seconds"] < 5:
        raise AggregateError("protocol floors must be at least 15 samples and five seconds")
    if protocol["rss_samples"] <= 0:
        raise AggregateError("authoritative parity requires RSS samples")
    if not protocol["thread_counts"] or len(set(protocol["thread_counts"])) != len(
        protocol["thread_counts"]
    ):
        raise AggregateError("thread-count sweep must be non-empty and unique")
    identities = manifest.get("identities", {})
    required_identities = {
        "wild-pe",
        "wild-elf",
        "baseline-wild-pe",
        "lld-link",
        "ld.lld",
    }
    if set(identities) != required_identities:
        raise AggregateError(f"identities must be exactly {sorted(required_identities)}")
    corpus_specs = manifest.get("corpora")
    if not isinstance(corpus_specs, list):
        raise AggregateError("corpora must be a list")
    by_name = {entry.get("name"): entry for entry in corpus_specs}
    if set(by_name) != set(REQUIRED_CORPORA) or len(corpus_specs) != len(REQUIRED_CORPORA):
        raise AggregateError(f"corpora must be exactly {list(REQUIRED_CORPORA)}")

    artifact_locations: set[str] = set()
    pe_corpus_hashes: set[str] = set()
    elf_corpus_hashes: set[str] = set()
    for name in REQUIRED_CORPORA:
        spec = by_name[name]
        try:
            workload = spec["workload"]
            required_workload = {
                "project_revision",
                "rust_toolchain",
                "profile",
                "feature_set",
                "pe_target",
                "elf_target",
            }
            if set(workload) != required_workload or any(
                not isinstance(workload[key], str) or not workload[key]
                for key in required_workload
            ):
                raise AggregateError(f"{name} workload provenance is incomplete")
            if workload["profile"] != "release":
                raise AggregateError(f"{name} is not a release-mode workload")
            pe_corpus_hashes.add(spec["pe"]["expected"]["corpus_manifest_sha256"])
            elf_corpus_hashes.add(spec["elf"]["expected"]["corpus_manifest_sha256"])
            references = (
                spec["pe"]["sweep"],
                spec["pe"]["direct"],
                spec["pe"]["baseline_sweep"],
                spec["pe"]["baseline_direct"],
                spec["elf"]["sweep"],
                spec["elf"]["direct"],
            )
        except (KeyError, TypeError) as error:
            raise AggregateError(f"{name} matrix entry is incomplete") from error
        for reference in references:
            location = str((manifest_path.parent / reference["path"]).resolve())
            if location in artifact_locations:
                raise AggregateError(f"benchmark artifact is reused in the matrix: {location}")
            artifact_locations.add(location)
    if len(pe_corpus_hashes) != len(REQUIRED_CORPORA) or len(elf_corpus_hashes) != len(
        REQUIRED_CORPORA
    ):
        raise AggregateError("each workload must use a distinct frozen PE and ELF corpus")

    series: dict[str, dict[str, PairSamples]] = {}
    rss: dict[str, Any] = {}
    for name in REQUIRED_CORPORA:
        spec = by_name[name]
        pe, pe_rss = validate_series(
            manifest_path.parent, spec["pe"], protocol, identities, "pe", f"{name} PE"
        )
        elf, elf_rss = validate_series(
            manifest_path.parent, spec["elf"], protocol, identities, "elf", f"{name} ELF"
        )
        baseline, baseline_rss = validate_baseline_series(
            manifest_path.parent, spec["pe"], protocol, identities, f"{name} PE"
        )
        series[name] = {"pe": pe, "elf": elf, "baseline": baseline}
        rss[name] = {"pe": pe_rss, "elf": elf_rss, "baseline": baseline_rss}
    rss_geometric_means = {
        "pe_wild_over_lld_link": geometric_mean(
            [rss[name]["pe"]["wild_over_comparator"] for name in REQUIRED_CORPORA]
        ),
        "elf_wild_over_ld_lld": geometric_mean(
            [rss[name]["elf"]["wild_over_comparator"] for name in REQUIRED_CORPORA]
        ),
        "pe_final_wild_over_baseline_wild": geometric_mean(
            [rss[name]["baseline"]["final_over_baseline"] for name in REQUIRED_CORPORA]
        ),
    }
    statistics_report = compute_statistics(
        series, bootstrap["seed"], bootstrap["resamples"]
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        "matrix_manifest": {
            "path": str(manifest_path),
            "sha256": sha256_file(manifest_path),
        },
        "protocol": protocol,
        "identities": identities,
        "rss": {
            "estimator": (
                "unweighted geometric mean of four per-corpus ratios of "
                "validated median peak-RSS KiB"
            ),
            "per_corpus": rss,
            "geometric_mean_ratios": rss_geometric_means,
            "decision_threshold": None,
        },
        "statistics": statistics_report,
    }


class AggregatorTests(unittest.TestCase):
    @staticmethod
    def _write_report(root: Path, name: str, report: dict[str, Any]) -> dict[str, str]:
        path = root / f"{name}.json"
        path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
        return {"path": path.name, "sha256": sha256_file(path)}

    @staticmethod
    def _synthetic_report(
        family: str,
        role: str,
        tool_names: tuple[str, str],
        identities: dict[str, dict[str, str]],
        corpus_hash: str,
        invocation_hash: str,
        seed: int,
        selection_sha256: str | None = None,
    ) -> dict[str, Any]:
        elf = family == "elf"
        identity_keys = (
            ("wild-elf", "ld.lld")
            if elf
            else (
                "wild-pe",
                "baseline-wild-pe" if tool_names[1] == "baseline-wild" else "lld-link",
            )
        )

        def tool_result(value: float) -> dict[str, Any]:
            samples = [
                {"elapsed_seconds": value, "user_seconds": 0.0, "system_seconds": 0.0}
                for _ in range(15)
            ]
            return {
                "elapsed_seconds": {"median": value},
                "raw_samples": samples,
                "maximum_rss_kib": {"median": 100.0, "raw_samples": [100]},
            }

        properties = (
            {
                "format": "elf",
                "machine": "EM_X86_64",
                "type": 2,
                "entry_point_nonzero": True,
            }
            if elf
            else {
                "format": "pe",
                "machine": "IMAGE_FILE_MACHINE_AMD64",
                "subsystem": 3,
                "entry_point_nonzero": True,
                "exports": False,
                "imports": True,
                "base_relocations": True,
            }
        )
        machine = properties["machine"]
        validation = {
            name: {
                "deterministic": True,
                "sha256": "d" * 64,
                "second_sha256": "d" * 64,
                "machine": machine,
                **(
                    {"type": 2, "entry_point": 0x401000}
                    if elf
                    else {
                        "subsystem": 3,
                        "entry_point_rva": 0x1000,
                        "data_directories": {
                            "exports": {"present": False},
                            "imports": {"present": True},
                            "base_relocations": {"present": True},
                        },
                    }
                ),
            }
            for name in tool_names
        }
        if role == "thread-sweep":
            configurations = []
            validations = {}
            for threads in (1, 2):
                wild_time = 1.0 if threads == 1 else 0.9
                comparator_time = 1.0 if threads == 1 else 1.1
                configurations.append(
                    {
                        "mode": "warm",
                        "threads": threads,
                        "execution_order": [list(tool_names) for _ in range(15)],
                        "tools": {
                            "wild": tool_result(wild_time),
                            tool_names[1]: tool_result(comparator_time),
                        },
                    }
                )
                validations[str(threads)] = validation
            started = "2026-08-03T00:00:00+00:00"
            finished = "2026-08-03T00:01:00+00:00"
        else:
            comparator_time = 1.5 if elf else (1.0 if tool_names[1] == "baseline-wild" else 2.0)
            configurations = [
                {
                    "mode": "warm",
                    "configuration": "direct-thread-pair",
                    "thread_pair": {"wild": 2, tool_names[1]: 1},
                    "execution_order": [list(tool_names) for _ in range(15)],
                    "tools": {
                        "wild": tool_result(0.9),
                        tool_names[1]: tool_result(comparator_time),
                    },
                }
            ]
            validations = {
                "direct": {
                    "configuration": "direct-thread-pair",
                    "tools": validation,
                }
            }
            started = "2026-08-03T00:02:00+00:00"
            finished = "2026-08-03T00:03:00+00:00"
        invocation_key = "run_with_sha256" if elf else "response_sha256"
        invocation = {
            invocation_key: invocation_hash,
            **(
                {
                    "command_template": "run-with <native-linker> --threads=<selected-count>",
                    "output_environment": "OUT=<per-sample-tmpfs-path>",
                }
                if elf
                else {
                    "output_override": "/out:<per-sample-path>",
                    "thread_override": "/threads:<selected-count>",
                }
            ),
        }
        settings: dict[str, Any] = {
            "benchmark_role": role,
            "modes": ["warm"],
            "min_samples": 15,
            "min_accumulated_seconds": 5.0,
            "rss_samples": 1,
            "random_seed": seed,
            "output_filesystem": "tmpfs",
            "output_directory": "/synthetic-tmpfs",
        }
        if selection_sha256 is not None:
            settings["selection_sweep"] = {"sha256": selection_sha256}
        return {
            "schema_version": 1,
            "status": "pass",
            "started_at_utc": started,
            "finished_at_utc": finished,
            "link_format": "elf" if elf else "pe",
            "host": {
                "cpu_list": "0,1",
                "machine": "aarch64",
                "environment_note": "synthetic idle runner",
            },
            "settings": settings,
            "corpus": {
                "manifest_sha256": corpus_hash,
                invocation_key: invocation_hash,
            },
            "invocation": invocation,
            "output_expectations": {
                "path": f"/synthetic/{family}-expectations.json",
                "sha256": hashlib.sha256(
                    f"{family}:{corpus_hash}".encode()
                ).hexdigest(),
                "properties": properties,
            },
            "tools": {
                name: identities[key]
                for name, key in zip(tool_names, identity_keys, strict=True)
            },
            "configurations": configurations,
            "validation": validations,
        }

    def test_bootstrap_is_deterministic_and_passes_clear_win(self) -> None:
        series = {}
        for name in REQUIRED_CORPORA:
            series[name] = {
                "pe": PairSamples((1.0, 1.01, 0.99) * 5, (2.0, 2.01, 1.99) * 5),
                "elf": PairSamples((1.0, 1.01, 0.99) * 5, (1.5, 1.51, 1.49) * 5),
                "baseline": PairSamples(
                    (0.9, 0.91, 0.89) * 5, (1.0, 1.01, 0.99) * 5
                ),
            }
        first = compute_statistics(series, 8675309, 100)
        second = compute_statistics(series, 8675309, 100)
        self.assertEqual(first, second)
        self.assertTrue(first["goal_pass"])
        self.assertGreater(first["aggregate"]["parity"]["lower_95"], 1.0)

    def test_inconclusive_interval_does_not_pass(self) -> None:
        alternating = PairSamples((1.0, 2.0) * 8, (2.0, 1.0) * 8)
        series = {
            name: {
                "pe": alternating,
                "elf": PairSamples((1.0,) * 16, (1.0,) * 16),
                "baseline": PairSamples((1.0,) * 16, (1.0,) * 16),
            }
            for name in REQUIRED_CORPORA
        }
        result = compute_statistics(series, 1, 200)
        self.assertFalse(result["goal_pass"])
        self.assertFalse(result["checks"]["pe_speedup_lower_95_gt_1"])

    def test_artifact_hash_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "report.json"
            artifact.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(AggregateError, "SHA-256 mismatch"):
                load_artifact(
                    root,
                    {"path": "report.json", "sha256": "0" * 64},
                    "synthetic",
                )

    def test_non_tmpfs_authority_report_is_rejected(self) -> None:
        report = {
            "schema_version": 1,
            "status": "pass",
            "settings": {
                "benchmark_role": "thread-sweep",
                "modes": ["warm"],
                "min_samples": 15,
                "min_accumulated_seconds": 5.0,
                "rss_samples": 5,
                "output_directory": "/tmp",
                "output_filesystem": "ext2/ext3",
            },
            "host": {
                "cpu_list": "0,1",
                "machine": "aarch64",
                "environment_note": "idle",
            },
        }
        protocol = {
            "mode": "warm",
            "cpu_list": "0,1",
            "min_samples": 15,
            "min_accumulated_seconds": 5.0,
            "rss_samples": 5,
            "environment_note": "idle",
        }
        with self.assertRaisesRegex(AggregateError, "not written to tmpfs"):
            common_protocol_check(
                Artifact(Path("synthetic"), "a" * 64, report),
                protocol,
                "thread-sweep",
                "synthetic PE",
                False,
            )

    def test_frozen_output_property_drift_is_rejected(self) -> None:
        report = {
            "corpus": {
                "manifest_sha256": "a" * 64,
                "response_sha256": "b" * 64,
            },
            "invocation": {
                "response_sha256": "b" * 64,
                "output_override": "/out:<per-sample-path>",
                "thread_override": "/threads:<selected-count>",
            },
            "output_expectations": {
                "path": "/frozen/pe.json",
                "sha256": "c" * 64,
                "properties": {"format": "pe", "imports": False},
            },
        }
        expected = {
            "corpus_manifest_sha256": "a" * 64,
            "invocation_sha256": "b" * 64,
            "output_expectations_sha256": "c" * 64,
            "output_properties": {"format": "pe", "imports": True},
        }
        with self.assertRaisesRegex(AggregateError, "properties drift"):
            corpus_and_invocation_check(report, expected, False, "synthetic PE")

    def test_nonpositive_and_forged_rss_are_rejected(self) -> None:
        protocol = {"rss_samples": 2}
        configuration = {
            "tools": {
                "wild": {
                    "maximum_rss_kib": {
                        "raw_samples": [100, 0],
                        "median": 50,
                    }
                }
            }
        }
        with self.assertRaisesRegex(AggregateError, "non-positive"):
            validated_rss_median(configuration, "wild", protocol, "synthetic")
        configuration["tools"]["wild"]["maximum_rss_kib"] = {
            "raw_samples": [100, 200],
            "median": 100,
        }
        with self.assertRaisesRegex(AggregateError, "does not match"):
            validated_rss_median(configuration, "wild", protocol, "synthetic")

    def test_full_synthetic_matrix_smoke(self) -> None:
        identities = {
            "wild-pe": {"sha256": "1" * 64, "version": "wild final"},
            "wild-elf": {"sha256": "2" * 64, "version": "wild final elf"},
            "baseline-wild-pe": {"sha256": "3" * 64, "version": "wild baseline"},
            "lld-link": {"sha256": "4" * 64, "version": "lld-link frozen"},
            "ld.lld": {"sha256": "5" * 64, "version": "ld.lld frozen"},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus_entries = []
            for index, name in enumerate(REQUIRED_CORPORA, start=1):
                pe_corpus_hash = f"{index:x}" * 64
                elf_corpus_hash = f"{index + 4:x}" * 64
                pe_invocation_hash = f"{index + 8:x}" * 64
                elf_invocation_hash = f"{index + 12:x}" * 64
                pe_sweep_report = self._synthetic_report(
                    "pe",
                    "thread-sweep",
                    ("wild", "lld-link"),
                    identities,
                    pe_corpus_hash,
                    pe_invocation_hash,
                    10,
                )
                pe_sweep = self._write_report(root, f"{name}-pe-sweep", pe_sweep_report)
                pe_direct = self._write_report(
                    root,
                    f"{name}-pe-direct",
                    self._synthetic_report(
                        "pe",
                        "direct-holdout",
                        ("wild", "lld-link"),
                        identities,
                        pe_corpus_hash,
                        pe_invocation_hash,
                        11,
                        pe_sweep["sha256"],
                    ),
                )
                baseline_sweep = self._write_report(
                    root,
                    f"{name}-baseline-sweep",
                    self._synthetic_report(
                        "pe",
                        "thread-sweep",
                        ("wild", "baseline-wild"),
                        identities,
                        pe_corpus_hash,
                        pe_invocation_hash,
                        20,
                    ),
                )
                baseline_direct = self._write_report(
                    root,
                    f"{name}-baseline-direct",
                    self._synthetic_report(
                        "pe",
                        "direct-holdout",
                        ("wild", "baseline-wild"),
                        identities,
                        pe_corpus_hash,
                        pe_invocation_hash,
                        21,
                        baseline_sweep["sha256"],
                    ),
                )
                elf_sweep = self._write_report(
                    root,
                    f"{name}-elf-sweep",
                    self._synthetic_report(
                        "elf",
                        "thread-sweep",
                        ("wild", "ld.lld"),
                        identities,
                        elf_corpus_hash,
                        elf_invocation_hash,
                        30,
                    ),
                )
                elf_direct = self._write_report(
                    root,
                    f"{name}-elf-direct",
                    self._synthetic_report(
                        "elf",
                        "direct-holdout",
                        ("wild", "ld.lld"),
                        identities,
                        elf_corpus_hash,
                        elf_invocation_hash,
                        31,
                        elf_sweep["sha256"],
                    ),
                )
                corpus_entries.append(
                    {
                        "name": name,
                        "workload": {
                            "project_revision": f"{name}-revision",
                            "rust_toolchain": "1.95.0-aarch64-unknown-linux-gnu",
                            "profile": "release",
                            "feature_set": "frozen-default",
                            "pe_target": "x86_64-pc-windows-msvc",
                            "elf_target": "x86_64-unknown-linux-gnu",
                        },
                        "pe": {
                            "sweep": pe_sweep,
                            "direct": pe_direct,
                            "baseline_sweep": baseline_sweep,
                            "baseline_direct": baseline_direct,
                            "expected": {
                                "corpus_manifest_sha256": pe_corpus_hash,
                                "invocation_sha256": pe_invocation_hash,
                                "selected_threads": {"wild": 2, "lld-link": 1},
                                "output_expectations_sha256": hashlib.sha256(
                                    f"pe:{pe_corpus_hash}".encode()
                                ).hexdigest(),
                                "output_properties": {
                                    "format": "pe",
                                    "machine": "IMAGE_FILE_MACHINE_AMD64",
                                    "subsystem": 3,
                                    "entry_point_nonzero": True,
                                    "exports": False,
                                    "imports": True,
                                    "base_relocations": True,
                                },
                            },
                            "baseline_expected": {
                                "corpus_manifest_sha256": pe_corpus_hash,
                                "invocation_sha256": pe_invocation_hash,
                                "selected_threads": {
                                    "wild": 2,
                                    "baseline-wild": 1,
                                },
                                "output_expectations_sha256": hashlib.sha256(
                                    f"pe:{pe_corpus_hash}".encode()
                                ).hexdigest(),
                                "output_properties": {
                                    "format": "pe",
                                    "machine": "IMAGE_FILE_MACHINE_AMD64",
                                    "subsystem": 3,
                                    "entry_point_nonzero": True,
                                    "exports": False,
                                    "imports": True,
                                    "base_relocations": True,
                                },
                            },
                        },
                        "elf": {
                            "sweep": elf_sweep,
                            "direct": elf_direct,
                            "expected": {
                                "corpus_manifest_sha256": elf_corpus_hash,
                                "invocation_sha256": elf_invocation_hash,
                                "selected_threads": {"wild": 2, "ld.lld": 1},
                                "output_expectations_sha256": hashlib.sha256(
                                    f"elf:{elf_corpus_hash}".encode()
                                ).hexdigest(),
                                "output_properties": {
                                    "format": "elf",
                                    "machine": "EM_X86_64",
                                    "type": 2,
                                    "entry_point_nonzero": True,
                                },
                            },
                        },
                    }
                )
            manifest = {
                "schema_version": 1,
                "bootstrap": {"resamples": 10_000, "seed": 8675309},
                "protocol": {
                    "mode": "warm",
                    "cpu_list": "0,1",
                    "thread_counts": [1, 2],
                    "min_samples": 15,
                    "min_accumulated_seconds": 5.0,
                    "rss_samples": 1,
                    "environment_note": "synthetic idle runner",
                },
                "identities": identities,
                "corpora": corpus_entries,
            }
            manifest_path = root / "matrix.json"
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
            )
            report = aggregate(manifest_path)
            self.assertEqual(report["status"], "pass")
            self.assertTrue(report["statistics"]["goal_pass"])
            self.assertEqual(
                report["rss"]["geometric_mean_ratios"],
                {
                    "pe_wild_over_lld_link": 1.0,
                    "elf_wild_over_ld_lld": 1.0,
                    "pe_final_wild_over_baseline_wild": 1.0,
                },
            )
            self.assertIsNone(report["rss"]["decision_threshold"])


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--matrix", type=Path, help="frozen four-corpus matrix JSON")
    result.add_argument("--output", type=Path, help="write aggregate JSON here")
    result.add_argument("--require-pass", action="store_true")
    result.add_argument("--self-test", action="store_true")
    return result


def main() -> int:
    args = parser().parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(AggregatorTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    if args.matrix is None:
        parser().error("--matrix is required unless --self-test is used")
    destination = args.output.expanduser().resolve() if args.output else None
    if destination is not None and destination.exists():
        parser().error(f"refusing to overwrite existing output: {destination}")
    try:
        report = aggregate(args.matrix)
        exit_code = 0
        if args.require_pass and not report["statistics"]["goal_pass"]:
            exit_code = 3
    except (AggregateError, OSError, KeyError, TypeError, ValueError) as error:
        report = {"schema_version": SCHEMA_VERSION, "status": "error", "error": str(error)}
        exit_code = 2
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if destination is not None:
        if not destination.parent.is_dir():
            parser().error(f"output parent does not exist: {destination.parent}")
        destination.write_text(encoded, encoding="utf-8")
    else:
        sys.stdout.write(encoded)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
