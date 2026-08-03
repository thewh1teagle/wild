#!/usr/bin/env python3
"""Compare the semantic PE/COFF structure reported by llvm-readobj."""

from __future__ import annotations

import argparse
import difflib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
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

# These describe placement chosen by a linker, rather than the relationship
# between PE entities. Retain sizes, flags, names, counts, ordinals and types.
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


@dataclass
class Node:
    heading: str
    closing: str
    children: list[str | "Node"] = field(default_factory=list)


def tool_path(explicit: str | None) -> str:
    candidates = [explicit, os.environ.get("LLVM_READOBJ"), "llvm-readobj"]
    candidates.extend(f"llvm-readobj-{version}" for version in range(22, 11, -1))
    for candidate in candidates:
        if not candidate:
            continue
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise RuntimeError("llvm-readobj was not found; pass --llvm-readobj or set LLVM_READOBJ")


def capabilities(tool: str) -> set[str]:
    result = subprocess.run(
        [tool, "--help"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    if result.returncode:
        raise RuntimeError(f"{tool} --help failed:\n{result.stdout.rstrip()}")
    return set(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]+)", result.stdout))


def inspect(tool: str, option: str, path: Path) -> str:
    result = subprocess.run(
        [tool, option, str(path)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{option} failed for {path}: {detail}")
    return result.stdout


def normalize_line(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("File:"):
        return None
    match = re.match(r"([^:]+):\s*(.*)$", line)
    if not match:
        return re.sub(r"\s+", " ", line)
    key, value = match.groups()
    key = key.strip()
    if key in VOLATILE_FIELDS:
        return None
    # LLVM spells most directory positions *RVA; some versions spell them
    # *Address. Both are placement details and are normalized consistently.
    if key in LAYOUT_FIELDS or key.endswith("RVA") or key.endswith("Address"):
        value = "<layout>"
    value = re.sub(r"\s+", " ", value).strip()
    return f"{key}: {value}"


def parse_tree(output: str) -> Node:
    root = Node("ROOT", "")
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
            node = Node(opener.group(1).strip(), "}" if opener.group(2) == "{" else "]")
            stack[-1].children.append(node)
            stack.append(node)
        else:
            stack[-1].children.append(line)
    if len(stack) != 1:
        raise ValueError("unbalanced llvm-readobj output at end of input")
    return root


def serialize(node: Node, depth: int = 0) -> list[str]:
    """Canonicalize LLVM's structured text as unordered semantic records."""
    indent = "  " * depth
    rendered: list[tuple[str, list[str]]] = []
    children = node.children
    # The DOS compatibility stub is producer-selected and is not involved once
    # Windows reaches the PE header. Ensure it is valid, but ignore its layout.
    if node.heading == "DOSHeader":
        children = [child for child in children if child == "Magic: MZ"]
    for child in children:
        lines = serialize(child, depth + 1) if isinstance(child, Node) else ["  " * (depth + 1) + child]
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


def compare(reference: Path, candidate: Path, tool: str, verbose: bool) -> int:
    for path in (reference, candidate):
        if not path.is_file():
            raise RuntimeError(f"not a file: {path}")

    supported = capabilities(tool)
    meaningful_mismatch = False
    ran = 0
    for name, option, required in CHECKS:
        if option not in supported:
            if required:
                raise RuntimeError(f"{tool} lacks required capability {option}")
            print(f"SKIP {name}: {option} is unavailable in this LLVM", file=sys.stderr)
            continue
        ran += 1
        left = canonicalize(inspect(tool, option, reference))
        right = canonicalize(inspect(tool, option, candidate))
        if left == right:
            if verbose:
                print(f"PASS {name}")
            continue
        meaningful_mismatch = True
        print(f"MISMATCH {name}")
        print(
            "".join(
                difflib.unified_diff(
                    left.splitlines(keepends=True),
                    right.splitlines(keepends=True),
                    fromfile=f"reference:{name}",
                    tofile=f"candidate:{name}",
                )
            ),
            end="",
        )
    print(f"Compared {ran} semantic PE views with {Path(tool).name}")
    return 1 if meaningful_mismatch else 0


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
  Characteristics [ (0x20)
   IMAGE_SCN_CNT_CODE (0x20)
  ]
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
    if canonicalize(reference) != canonicalize(equivalent):
        print("self-test failed: nondeterministic/layout fields were not normalized", file=sys.stderr)
        return 1
    if canonicalize(reference) == canonicalize(different):
        print("self-test failed: semantic import mismatch was hidden", file=sys.stderr)
        return 1
    print("PASS self-test: layout noise ignored and semantic changes detected")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", nargs="?", type=Path, help="trusted PE, usually from lld-link")
    parser.add_argument("candidate", nargs="?", type=Path, help="candidate PE, usually from Wild")
    parser.add_argument("--llvm-readobj", metavar="PATH", help="llvm-readobj executable")
    parser.add_argument("--self-test", action="store_true", help="test normalization without LLVM")
    parser.add_argument("--verbose", action="store_true", help="print successful views")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.reference is None or args.candidate is None:
        parser.error("reference and candidate are required unless --self-test is used")
    try:
        return compare(args.reference, args.candidate, tool_path(args.llvm_readobj), args.verbose)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
