# Goal

Implement production-usable, experimental x86-64 PE/COFF support for Wild on one feature branch.

- Link representative MSVC C/C++ and Rust executables and DLLs.
- Verify locally against `lld-link` and execute on real Windows through GitHub Actions.
- After the core PE/COFF runtime suite passes, build and run a minimal Tauri app in both
  debug and release modes with Wild as the linker.
- Then build the real [`thewh1teagle/vibe`](https://github.com/thewh1teagle/vibe) app
  completely in both debug and release modes with Wild as the linker, and verify the
  resulting applications on real Windows.
- Exclude PDB, LTO, incremental linking, and non-x86-64 targets.
- Use parallel subagents in worktrees; the manager reviews and merges their work.
- Work only in our fork. Do not open a pull request.
