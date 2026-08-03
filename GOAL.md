# Goal

Implement production-usable, experimental x86-64 PE/COFF support for Wild on one feature branch.

- Link representative MSVC C/C++ and Rust executables and DLLs.
- Verify locally against `lld-link` and execute on real Windows through GitHub Actions.
- Exclude PDB, LTO, incremental linking, and non-x86-64 targets.
- Use parallel subagents in worktrees; the manager reviews and merges their work.
- Work only in our fork. Do not open a pull request.
