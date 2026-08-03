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
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field, replace


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


@dataclass(frozen=True)
class PeSection:
    name: bytes
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int


@dataclass(frozen=True)
class PeLayout:
    data: bytes
    sections: tuple[PeSection, ...]
    directories: tuple[tuple[int, int], ...]

    def section(self, name: bytes) -> PeSection:
        matches = [section for section in self.sections if section.name == name]
        if len(matches) != 1:
            raise ValueError(f"expected exactly one {name!r} section, found {len(matches)}")
        return matches[0]

    def section_data(self, section: PeSection) -> bytes:
        end = section.raw_offset + min(section.raw_size, section.virtual_size)
        return self.data[section.raw_offset:end]


def parse_pe_layout(path: Path) -> PeLayout:
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError(f"{path} lacks a DOS header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError(f"{path} lacks a valid PE signature")
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional_offset = pe_offset + 24
    optional_end = optional_offset + optional_size
    if optional_end > len(data) or optional_size < 112:
        raise ValueError(f"{path} has a truncated PE32+ optional header")
    if struct.unpack_from("<H", data, optional_offset)[0] != 0x20B:
        raise ValueError(f"{path} is not a PE32+ image")
    directory_count = min(struct.unpack_from("<I", data, optional_offset + 108)[0], 16)
    if optional_offset + 112 + directory_count * 8 > optional_end:
        raise ValueError(f"{path} has truncated data directories")
    directories = tuple(
        struct.unpack_from("<II", data, optional_offset + 112 + index * 8)
        for index in range(directory_count)
    )
    section_table = optional_end
    if section_table + section_count * 40 > len(data):
        raise ValueError(f"{path} has a truncated section table")
    sections = []
    for index in range(section_count):
        offset = section_table + index * 40
        name = data[offset : offset + 8].rstrip(b"\0")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        if raw_size and raw_offset + raw_size > len(data):
            raise ValueError(f"{path} section {name!r} has out-of-bounds raw data")
        sections.append(
            PeSection(name, virtual_size, virtual_address, raw_size, raw_offset, characteristics)
        )
    return PeLayout(data, tuple(sections), directories)


def directory(layout: PeLayout, index: int) -> tuple[int, int]:
    return layout.directories[index] if index < len(layout.directories) else (0, 0)


def contains_rva(section: PeSection, region: tuple[int, int]) -> bool:
    rva, size = region
    return (
        size > 0
        and section.virtual_address <= rva
        and rva + size <= section.virtual_address + section.virtual_size
    )


def accepts_zero_fill_section_equivalence(reference: PeLayout, candidate: PeLayout) -> bool:
    """Accept lld's initialized `.data` spelling for an input `.bss` section.

    PE maps the portion where VirtualSize exceeds SizeOfRawData as zeroes. The
    initialized/uninitialized content flags do not change that loader rule.
    This policy is deliberately exact to the two-section bss_external fixture.
    """

    if tuple(section.name for section in reference.sections) != (b".text", b".data"):
        return False
    if tuple(section.name for section in candidate.sections) != (b".text", b".bss"):
        return False
    reference_text, reference_zero = reference.sections
    candidate_text, candidate_zero = candidate.sections
    relevant = 0xE00000E0  # content kind plus R/W/X permissions
    if (
        reference_text.virtual_size != candidate_text.virtual_size
        or reference_text.raw_size != candidate_text.raw_size
        or reference_text.characteristics & relevant != candidate_text.characteristics & relevant
    ):
        return False
    initialized_rw = 0xC0000040
    uninitialized_rw = 0xC0000080
    if (
        reference_zero.virtual_size == 0
        or reference_zero.virtual_size != candidate_zero.virtual_size
        or reference_zero.raw_size != 0
        or candidate_zero.raw_size != 0
        or reference_zero.characteristics & relevant != initialized_rw
        or candidate_zero.characteristics & relevant != uninitialized_rw
    ):
        return False
    # This fixture has no loader data directories; accepting a section-kind
    # spelling difference must not mask movement of any loader-owned structure.
    return all(region == (0, 0) for region in reference.directories) and all(
        region == (0, 0) for region in candidate.directories
    )


def accepts_split_import_section_equivalence(reference: PeLayout, candidate: PeLayout) -> bool:
    """Accept Wild's conventional writable `.idata` split from lld's `.rdata`.

    The import and IAT directories must stay wholly inside the respective
    import-bearing section, exception data must stay in `.pdata`, and the
    non-import unwind payload must be byte-identical. Other section shapes are
    rejected rather than broadly ignoring `.rdata`/`.idata` differences.
    """

    if tuple(section.name for section in reference.sections) != (b".text", b".rdata", b".pdata"):
        return False
    if tuple(section.name for section in candidate.sections) != (
        b".text",
        b".rdata",
        b".pdata",
        b".idata",
    ):
        return False
    reference_text = reference.section(b".text")
    candidate_text = candidate.section(b".text")
    reference_pdata = reference.section(b".pdata")
    candidate_pdata = candidate.section(b".pdata")
    reference_rdata = reference.section(b".rdata")
    candidate_rdata = candidate.section(b".rdata")
    candidate_idata = candidate.section(b".idata")
    relevant = 0xE00000E0
    code_rx = 0x60000020
    initialized_r = 0x40000040
    initialized_rw = 0xC0000040
    if (
        reference_text.virtual_size != candidate_text.virtual_size
        or reference_text.characteristics & relevant != code_rx
        or candidate_text.characteristics & relevant != code_rx
        or reference_pdata.virtual_size != candidate_pdata.virtual_size
        or reference_pdata.characteristics & relevant != initialized_r
        or candidate_pdata.characteristics & relevant != initialized_r
        or reference_rdata.characteristics & relevant != initialized_r
        or candidate_rdata.characteristics & relevant != initialized_r
        or candidate_idata.characteristics & relevant != initialized_rw
    ):
        return False
    # Import directory index 1, exception directory index 3, and IAT index 12.
    if not (
        contains_rva(reference_rdata, directory(reference, 1))
        and contains_rva(reference_rdata, directory(reference, 12))
        and contains_rva(candidate_idata, directory(candidate, 1))
        and contains_rva(candidate_idata, directory(candidate, 12))
        and contains_rva(reference_pdata, directory(reference, 3))
        and contains_rva(candidate_pdata, directory(candidate, 3))
    ):
        return False
    reference_rdata_bytes = reference.section_data(reference_rdata)
    candidate_rdata_bytes = candidate.section_data(candidate_rdata)
    if not candidate_rdata_bytes or not reference_rdata_bytes.endswith(candidate_rdata_bytes):
        return False
    import_prefix_size = len(reference_rdata_bytes) - len(candidate_rdata_bytes)
    padding = import_prefix_size - candidate_idata.virtual_size
    if padding not in range(8):
        return False
    return not padding or reference_rdata_bytes[import_prefix_size - padding : import_prefix_size] == bytes(
        padding
    )


def accepted_layout_views(
    case: Case, reference: Path, candidate: Path, differences: list[SemanticDifference]
) -> set[str]:
    views = {difference.view for difference in differences}
    reference_layout = parse_pe_layout(reference)
    candidate_layout = parse_pe_layout(candidate)
    if (
        case.name == "bss_external"
        and views == {"sections"}
        and accepts_zero_fill_section_equivalence(reference_layout, candidate_layout)
    ):
        return views
    if (
        case.name == "exit_process"
        and views == {"headers", "sections"}
        and accepts_split_import_section_equivalence(reference_layout, candidate_layout)
    ):
        return views
    return set()


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
                accepted = accepted_layout_views(case, reference, candidate_a, differences)
                differences = [item for item in differences if item.view not in accepted]
                semantics = "PASS" if not differences else ",".join(item.view for item in differences)
                if accepted:
                    semantics += f" ({'+'.join(sorted(accepted))} layout equivalent)"
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
    empty_directories = ((0, 0),) * 16
    text = PeSection(b".text", 16, 0x1000, 512, 0, 0x60000020)
    lld_bss = PeLayout(
        b"",
        (text, PeSection(b".data", 4, 0x2000, 0, 0, 0xC0000040)),
        empty_directories,
    )
    wild_bss = PeLayout(
        b"",
        (text, PeSection(b".bss", 4, 0x2000, 0, 0, 0xC0000080)),
        empty_directories,
    )
    if not accepts_zero_fill_section_equivalence(lld_bss, wild_bss):
        print("self-test failed: exact zero-fill section equivalence was rejected", file=sys.stderr)
        return 1
    bad_bss = replace(wild_bss, sections=(text, replace(wild_bss.sections[1], raw_size=4)))
    if accepts_zero_fill_section_equivalence(lld_bss, bad_bss):
        print("self-test failed: raw-data section was accepted as zero-fill equivalent", file=sys.stderr)
        return 1

    unwind = b"UNWIND!!"
    lld_directories = list(empty_directories)
    lld_directories[1] = (0x2000, 40)
    lld_directories[3] = (0x3000, 12)
    lld_directories[12] = (0x2038, 16)
    lld_split = PeLayout(
        bytes(100) + unwind,
        (
            text,
            PeSection(b".rdata", 108, 0x2000, 108, 0, 0x40000040),
            PeSection(b".pdata", 12, 0x3000, 12, 0, 0x40000040),
        ),
        tuple(lld_directories),
    )
    wild_directories = list(empty_directories)
    wild_directories[1] = (0x4000, 40)
    wild_directories[3] = (0x3000, 12)
    wild_directories[12] = (0x4038, 16)
    wild_split = PeLayout(
        unwind + bytes(99),
        (
            text,
            PeSection(b".rdata", 8, 0x2000, 8, 0, 0x40000040),
            PeSection(b".pdata", 12, 0x3000, 12, 0, 0x40000040),
            PeSection(b".idata", 99, 0x4000, 99, 8, 0xC0000040),
        ),
        tuple(wild_directories),
    )
    if not accepts_split_import_section_equivalence(lld_split, wild_split):
        print("self-test failed: exact split import-section equivalence was rejected", file=sys.stderr)
        return 1
    bad_split = replace(
        wild_split,
        sections=(*wild_split.sections[:3], replace(wild_split.sections[3], characteristics=0x40000040)),
    )
    if accepts_split_import_section_equivalence(lld_split, bad_split):
        print("self-test failed: read-only candidate IAT was accepted", file=sys.stderr)
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
