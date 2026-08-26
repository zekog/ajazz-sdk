#!/usr/bin/env python3
"""Annotate a disassembly with symbol names.

Usage: annotate_asm.py <pe> <asm-file> <syms-json> <out-file>

- Resolves direct call targets using the symbol map (publics from PDB).
- Resolves indirect `call qword ptr [rip+X] # 0x14047abcd` targets through the
  PE import table (IAT) so every imported function call gets a name.
"""
import json
import re
import sys
from pathlib import Path

import pefile

CALL_RE = re.compile(r"^([0-9a-f]+):.*?call\s+(.*)$", re.I)
IAT_RE = re.compile(r"# (0x[0-9a-f]+)")

def build_iat(pe_path: Path):
    pe = pefile.PE(str(pe_path), fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )
    iat = {}
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode(errors="replace")
        for imp in entry.imports:
            if imp.address:
                va = imp.address
                if imp.name:
                    name = imp.name.decode(errors="replace")
                else:
                    name = f"{dll}!ordinal_{imp.ordinal}"
                iat[va] = f"{dll}!{name}"
    return iat


def main():
    pe_path, asm_path, syms_path, out_path = map(Path, sys.argv[1:5])
    iat = build_iat(pe_path)
    syms = json.load(open(syms_path))
    sym_map = {}
    for addr, (m, d) in syms.items():
        sym_map[addr.lower()] = (m, d)

    out = []
    for line in asm_path.read_text(errors="replace").splitlines():
        m = CALL_RE.match(line.strip())
        if m and "call" in line:
            addr_s, rest = m.group(1), m.group(2)
            ia = IAT_RE.search(rest)
            if ia:
                slot = ia.group(1)
                name = iat.get(int(slot, 16))
                if name:
                    line = line.rstrip() + f"   ; {name}"
                else:
                    line = line.rstrip() + f"   ; IAT?{slot}"
            else:
                tgt = re.search(r"call\s+(0x[0-9a-f]+)", rest)
                if tgt:
                    hit = sym_map.get(tgt.group(1).lower())
                    if hit:
                        line = line.rstrip() + f"   ; {hit[1]}"
            out.append(line)
        else:
            out.append(line)
    out_path.write_text("\n".join(out) + "\n")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
