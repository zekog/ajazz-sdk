#!/usr/bin/env python3
"""Extract a complete, address-mapped symbol table from a PE + its PDB.

For each public symbol we resolve the `section:offset` address printed by
`llvm-pdbutil dump --publics` to a real virtual address (VA) using the PE
section headers, then demangle the name with llvm-cxxfilt.

Output: JSON file  { "0x140001234": ["mangled", "demangled"], ... }
"""
import json
import re
import subprocess
import sys
from pathlib import Path

import pefile

PUB_RE = re.compile(
    r"^\s*\d+\s*\| S_PUB32 .*?`([^`]+)`\s*$\n\s*flags = (\w+), addr = (\w+):(\w+)",
    re.M,
)


def load_publics(pdb: Path):
    out = subprocess.run(
        ["llvm-pdbutil", "dump", "--publics", str(pdb)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    recs = []
    for m in PUB_RE.finditer(out):
        name, flags, sec, off = m.group(1), m.group(2), m.group(3), m.group(4)
        recs.append((name, flags, int(sec), int(off)))
    return recs


def demangle(name: str) -> str:
    if not name.startswith("?"):
        return name
    r = subprocess.run(
        ["llvm-cxxfilt", name], capture_output=True, text=True
    )
    return r.stdout.strip() if r.returncode == 0 else name


def main(pe_path: Path, pdb_path: Path, out_path: Path):
    pe = pefile.PE(str(pe_path), fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase

    # section number -> (virtual_address, raw_data_ptr) for RVAs
    sec_va = {}
    sec_raw = {}
    for i, sec in enumerate(pe.sections, start=1):
        sec_va[i] = sec.VirtualAddress
        sec_raw[i] = sec.PointerToRawData

    recs = load_publics(pdb_path)
    print(f"{pdb_path.name}: {len(recs)} public symbols", file=sys.stderr)

    syms = {}
    for name, flags, sec, off in recs:
        if sec not in sec_va:
            continue
        # PDB `section:offset` stores the offset relative to the section's
        # *virtual* base, so RVA = sec_va + off (verified against the DLL
        # export table).
        rva = sec_va[sec] + off
        va = base + rva
        key = hex(va)
        if key not in syms or flags == "function":
            syms[key] = [name, demangle(name)]

    out_path.write_text(json.dumps(syms, indent=1))
    print(f"wrote {len(syms)} symbols -> {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
