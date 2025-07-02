# GhostPE

**GhostPE** is an in-memory Portable Executable (PE) loader written in Rust. It demonstrates how to manually map and execute Windows PE files (EXEs and DLLs) without touching disk—a technique often used in offensive security and red team engagements.

---

## 🎯 Project Goals

- Learn Windows PE internals by implementing a loader from scratch
- Understand how manual mapping bypasses traditional file-based detection
- Build foundational skills for developing advanced techniques:
    - Reflective DLL injection
    - Process hollowing
    - EDR evasion

---

## 🚀 Features (Planned)

- PE file parsing (DOS header, NT headers, section headers)
- Memory allocation and section mapping
- Relocation handling
- Import table resolution
- Entry point execution