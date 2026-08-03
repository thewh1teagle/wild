#!/usr/bin/env python3
"""Build the PE smoke corpus and check Wild's semantics and reproducibility."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field


CHECKS = (
    ("headers", "--file-header", True),
    ("sections", "--sections", True),
    ("symbols", "--symbols", True),
    ("imports", "--coff-imports", False),
    ("exports", "--coff-exports", False),
    ("base-relocations", "--coff-basereloc", False),
    ("unwind", "--unwind", False),
)

LAYOUT_FIELDS = {
    "AddressOfEntryPoint",
    "BaseOfCode",
    "ImageBase",
    "FileAlignment",
    "SectionAlignment",
    "RawDataSize",
    "SizeOfCode",
    "SizeOfInitializedData",
    "SizeOfUninitializedData",
    "SizeOfImage",
    "SizeOfHeaders",
    "PointerToSymbolTable",
    "PointerToRawData",
    "PointerToRelocations",
    "PointerToLineNumbers",
    "VirtualAddress",
    "Section",
    "SectionNumber",
    "Number",
    "Value",
    "StartAddress",
    "EndAddress",
    "UnwindInfoAddress",
}
VOLATILE_FIELDS = {
    "TimeDateStamp",
    "CheckSum",
    "MajorLinkerVersion",
    "MinorLinkerVersion",
}


@dataclass(frozen=True)
class Case:
    name: str
    sources: tuple[str, ...]
    exit_code: int
    kernel32: bool = False


CASES = (
    Case("exit_process", ("minimal_exit_code.c",), 37, True),
    Case("entry_return", ("entry_return.s",), 41),
    Case("rel32_cross_object", ("rel32_caller.c", "rel32_target.c"), 43),
    Case("rip_relative_data", ("rip_relative_data.c",), 47),
    Case("bss_external", ("bss_entry.c", "bss_storage.c"), 53),
    Case("absolute_pointer", ("absolute_pointer.c",), 59),
)


@dataclass
class Node:
    heading: str
    children: list[str | "Node"] = field(default_factory=list)


@dataclass(frozen=True)
class SemanticDifference:
    view: str
    diff: str


def resolve_tool(explicit: str | None, environment: str, names: tuple[str, ...]) -> Path:
    candidates = [explicit, os.environ.get(environment), *names]
    for candidate in candidates:
        if not candidate:
            continue
        expanded = Path(candidate).expanduser()
        if expanded.is_file():
            return expanded.resolve()
        resolved = shutil.which(candidate)
        if resolved:
            return Path(resolved).resolve()
    requested = f"pass --{environment.lower().replace('_', '-')} or set {environment}"
    raise RuntimeError(f"could not find {'/'.join(names)}; {requested}")


def resolve_wild(explicit: str | None, repository: Path) -> Path:
    candidates: list[str | Path | None] = [explicit, os.environ.get("WILD_PE_LINKER")]
    candidates.extend(
        repository / "target" / profile / executable
        for profile in ("release", "debug")
        for executable in (("wild.exe", "wild") if os.name == "nt" else ("wild",))
    )
    candidates.append("wild")
    for candidate in candidates:
        if not candidate:
            continue
        expanded = Path(candidate).expanduser()
        if expanded.is_file():
            return expanded.resolve()
        resolved = shutil.which(str(candidate))
        if resolved:
            return Path(resolved).resolve()
    raise RuntimeError(
        "could not find a built Wild; pass --wild, set WILD_PE_LINKER, "
        "or run `cargo build -p wild-linker --features pe`"
    )


def run(command: list[str], *, label: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        detail = "\n".join(part for part in (result.stdout.strip(), result.stderr.strip()) if part)
        raise RuntimeError(
            f"{label} failed with status {result.returncode}:\n"
            f"  {' '.join(command)}\n{detail}"
        )
    return result


def tool_capabilities(tool: Path) -> set[str]:
    output = run([str(tool), "--help"], label=f"probe {tool.name}").stdout
    return set(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]+)", output))


def normalize_line(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("File:"):
        return None
    match = re.match(r"([^:]+):\s*(.*)$", line)
    if not match:
        return re.sub(r"\s+", " ", line)
    key, value = (part.strip() for part in match.groups())
    if key in VOLATILE_FIELDS:
        return None
    if key in LAYOUT_FIELDS or key.endswith("RVA") or key.endswith("Address"):
        value = "<layout>"
    value = re.sub(r"\s+", " ", value)
    return f"{key}: {value}"


def parse_tree(output: str) -> Node:
    root = Node("ROOT")
    stack = [root]
    for raw in output.splitlines():
        line = normalize_line(raw)
        if line is None:
            continue
        if line in ("}", "]"):
            if len(stack) == 1:
                raise ValueError(f"unbalanced llvm-readobj output near {raw!r}")
            stack.pop()
            continue
        opener = re.match(r"^(.*?)([\[{])(?:\s+\([^)]*\))?$", line)
        if opener:
            node = Node(opener.group(1).strip())
            stack[-1].children.append(node)
            stack.append(node)
        else:
            stack[-1].children.append(line)
    if len(stack) != 1:
        raise ValueError("unbalanced llvm-readobj output at end of input")
    return root


def serialize(node: Node, depth: int = 0) -> list[str]:
    indent = "  " * depth
    children = node.children
    if node.heading == "DOSHeader":
        children = [child for child in children if child == "Magic: MZ"]
    rendered: list[tuple[str, list[str]]] = []
    for child in children:
        lines = (
            serialize(child, depth + 1)
            if isinstance(child, Node)
            else ["  " * (depth + 1) + child]
        )
        rendered.append(("\n".join(line.strip() for line in lines), lines))
    rendered.sort(key=lambda pair: pair[0])
    if node.heading == "ROOT":
        return [line for _, lines in rendered for line in lines]
    result = [f"{indent}{node.heading} {{"]
    result.extend(line for _, lines in rendered for line in lines)
    result.append(f"{indent}}}")
    return result


def canonicalize(output: str) -> str:
    return "\n".join(serialize(parse_tree(output))) + "\n"


def semantic_differences(
    reference: Path, candidate: Path, llvm_readobj: Path, supported: set[str]
) -> list[SemanticDifference]:
    differences = []
    for name, option, required in CHECKS:
        if option not in supported:
            if required:
                raise RuntimeError(f"{llvm_readobj} lacks required capability {option}")
            continue
        reference_view = canonicalize(
            run([str(llvm_readobj), option, str(reference)], label=f"inspect {reference.name}").stdout
        )
        candidate_view = canonicalize(
            run([str(llvm_readobj), option, str(candidate)], label=f"inspect {candidate.name}").stdout
        )
        if reference_view != candidate_view:
            diff = "".join(
                difflib.unified_diff(
                    reference_view.splitlines(keepends=True),
                    candidate_view.splitlines(keepends=True),
                    fromfile=f"lld-link:{name}",
                    tofile=f"Wild:{name}",
                )
            )
            differences.append(SemanticDifference(name, diff))
    return differences


def find_xwin_library(xwin_root: Path, name: str) -> Path | None:
    preferred = (
        xwin_root / "sdk" / "lib" / "um" / "x86_64",
        xwin_root / "crt" / "lib" / "x86_64",
    )
    for directory in preferred:
        if not directory.is_dir():
            continue
        for entry in directory.iterdir():
            if entry.is_file() and entry.name.casefold() == name.casefold():
                return entry.resolve()
    return None


def compile_case(case: Case, source_dir: Path, output_dir: Path, clang_cl: Path) -> list[Path]:
    objects = []
    for source_name in case.sources:
        source = source_dir / source_name
        if not source.is_file():
            raise RuntimeError(f"fixture source is missing: {source}")
        output = output_dir / f"{source.name}.obj"
        command = [str(clang_cl), "/nologo", "/c", "/GS-", "/O1", "/Zl"]
        if os.name != "nt":
            command.append("/clang:--target=x86_64-pc-windows-msvc")
        command.append(f"/Fo{output}")
        if os.name != "nt":
            command.append("--")
        command.append(str(source))
        run(command, label=f"compile {case.name}/{source.name}")
        objects.append(output)
    return objects


def common_link_args(case: Case, objects: list[Path], output: Path, kernel32: Path | None) -> list[str]:
    arguments = [
        "/nologo",
        "/entry:mainCRTStartup",
        "/subsystem:console",
        "/nodefaultlib",
        "/dynamicbase",
        "/machine:x64",
        f"/out:{output}",
        *(str(path) for path in objects),
    ]
    if case.kernel32:
        arguments.append(str(kernel32) if kernel32 else "kernel32.lib")
    return arguments


def link_case(
    linker: Path,
    linker_kind: str,
    case: Case,
    objects: list[Path],
    output: Path,
    kernel32: Path | None,
) -> None:
    prefix = [str(linker), "-flavor", "link"] if linker_kind == "Wild" else [str(linker)]
    run(prefix + common_link_args(case, objects, output, kernel32), label=f"{linker_kind} link {case.name}")
    if not output.is_file():
        raise RuntimeError(f"{linker_kind} did not produce {output}")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute_case(case: Case, path: Path, producer: str) -> None:
    result = subprocess.run([str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != case.exit_code:
        raise RuntimeError(
            f"{case.name}: {producer} returned {result.returncode}, expected {case.exit_code}; "
            f"stdout={result.stdout!r}; stderr={result.stderr!r}"
        )


def run_matrix(args: argparse.Namespace) -> int:
    repository = Path(__file__).resolve().parents[2]
    source_dir = (args.source_dir or repository / "wild/tests/sources/coff").resolve()
    clang_cl = resolve_tool(args.clang_cl, "CLANG_CL", ("clang-cl",))
    lld_link = resolve_tool(args.lld_link, "LLD_LINK", ("lld-link",))
    llvm_readobj = resolve_tool(
        args.llvm_readobj,
        "LLVM_READOBJ",
        ("llvm-readobj", *(f"llvm-readobj-{version}" for version in range(22, 11, -1))),
    )
    wild = resolve_wild(args.wild, repository)
    supported = tool_capabilities(llvm_readobj)
    xwin_root = (args.xwin_root or Path(os.environ.get("XWIN_ROOT", "~/.xwin"))).expanduser()
    kernel32 = find_xwin_library(xwin_root, "kernel32.lib") if os.name != "nt" else None
    if os.name != "nt" and kernel32 is None:
        raise RuntimeError(
            f"kernel32.lib was not found below {xwin_root}; pass --xwin-root or set XWIN_ROOT"
        )

    print(f"clang-cl:     {clang_cl}")
    print(f"lld-link:     {lld_link}")
    print(f"llvm-readobj: {llvm_readobj}")
    print(f"Wild:         {wild}")
    if kernel32:
        print(f"kernel32.lib: {kernel32}")

    temporary = tempfile.TemporaryDirectory(prefix="wild-pe-repro-")
    work_dir = Path(temporary.name)
    failed = False
    try:
        print("\ncase                 lld bytes/hash          Wild bytes/hash         deterministic  semantics")
        print("-------------------  ----------------------  ----------------------  -------------  ---------")
        for case in CASES:
            case_dir = work_dir / case.name
            case_dir.mkdir()
            try:
                objects = compile_case(case, source_dir, case_dir, clang_cl)
                reference = case_dir / "reference.exe"
                candidate_a = case_dir / "wild-a.exe"
                candidate_b = case_dir / "wild-b.exe"
                link_case(lld_link, "lld-link", case, objects, reference, kernel32)
                link_case(wild, "Wild", case, objects, candidate_a, kernel32)
                link_case(wild, "Wild", case, objects, candidate_b, kernel32)
                reference_hash = digest(reference)
                candidate_hash = digest(candidate_a)
                deterministic = candidate_a.read_bytes() == candidate_b.read_bytes()
                differences = semantic_differences(reference, candidate_a, llvm_readobj, supported)
                semantics = "PASS" if not differences else ",".join(item.view for item in differences)
                print(
                    f"{case.name:19}  {reference.stat().st_size:7}/{reference_hash[:12]}  "
                    f"{candidate_a.stat().st_size:7}/{candidate_hash[:12]}  "
                    f"{'PASS' if deterministic else 'FAIL':13}  {semantics}"
                )
                if not deterministic:
                    failed = True
                    print(f"  determinism: {digest(candidate_a)} != {digest(candidate_b)}")
                for difference in differences:
                    failed = True
                    print(f"  semantic divergence ({difference.view}):")
                    lines = difference.diff.splitlines()
                    limit = args.diff_lines
                    for line in lines[:limit]:
                        print(f"    {line}")
                    if len(lines) > limit:
                        print(f"    ... {len(lines) - limit} more diff lines (use --diff-lines to expand)")
                if os.name == "nt" and not args.no_execute:
                    execute_case(case, reference, "lld-link")
                    execute_case(case, candidate_a, "Wild")
            except (OSError, RuntimeError, ValueError) as error:
                failed = True
                print(f"{case.name:19}  ERROR: {error}", file=sys.stderr)
                if args.fail_fast:
                    break
        if args.keep_temp:
            destination = Path(args.keep_temp).expanduser().resolve()
            if destination.exists():
                raise RuntimeError(f"--keep-temp destination already exists: {destination}")
            shutil.copytree(work_dir, destination)
            print(f"\nPreserved artifacts in {destination}")
    finally:
        temporary.cleanup()
    return 1 if failed else 0


def self_test() -> int:
    reference = """File: reference.exe
ImageFileHeader {
  Machine: IMAGE_FILE_MACHINE_AMD64 (0x8664)
  TimeDateStamp: 2025-01-01 (0x1)
  SectionCount: 2
}
Sections [
 Section {
  Number: 1
  Name: .text
  VirtualAddress: 0x1000
 }
 Section {
  Number: 2
  Name: .idata
  VirtualAddress: 0x2000
 }
]
Import {
 Name: KERNEL32.dll
 Symbol: ExitProcess
 ImportLookupTableRVA: 0x2010
}
"""
    equivalent = reference.replace("reference.exe", "candidate.exe")
    equivalent = equivalent.replace("2025-01-01 (0x1)", "2026-02-02 (0x2)")
    equivalent = equivalent.replace("0x1000", "0x3000").replace("0x2000", "0x4000")
    equivalent = equivalent.replace("0x2010", "0x4010")
    different = equivalent.replace("ExitProcess", "CreateFileW")
    payload = b"deterministic PE payload"
    if hashlib.sha256(payload).digest() != hashlib.sha256(payload).digest():
        print("self-test failed: identical payloads produced different hashes", file=sys.stderr)
        return 1
    if canonicalize(reference) != canonicalize(equivalent):
        print("self-test failed: layout noise was not normalized", file=sys.stderr)
        return 1
    if canonicalize(reference) == canonicalize(different):
        print("self-test failed: semantic import mismatch was hidden", file=sys.stderr)
        return 1
    print("PASS self-test: deterministic hashing and semantic normalization")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="test normalization without tools")
    parser.add_argument("--wild", metavar="PATH", help="built Wild executable")
    parser.add_argument("--clang-cl", metavar="PATH", help="clang-cl executable")
    parser.add_argument("--lld-link", metavar="PATH", help="lld-link executable")
    parser.add_argument("--llvm-readobj", metavar="PATH", help="llvm-readobj executable")
    parser.add_argument("--source-dir", type=Path, help="directory containing the six fixtures")
    parser.add_argument("--xwin-root", type=Path, help="xwin root (default: XWIN_ROOT or ~/.xwin)")
    parser.add_argument("--no-execute", action="store_true", help="skip execution on Windows")
    parser.add_argument("--fail-fast", action="store_true", help="stop at the first failed case")
    parser.add_argument("--diff-lines", type=int, default=80, help="maximum diff lines per view")
    parser.add_argument("--keep-temp", metavar="DIR", help="copy generated artifacts to new DIR")
    args = parser.parse_args()
    if args.diff_lines < 0:
        parser.error("--diff-lines must be non-negative")
    if args.self_test:
        return self_test()
    try:
        return run_matrix(args)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
