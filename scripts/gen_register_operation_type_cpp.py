#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import re
import sys
from pathlib import Path

def sanitize_macro_suffix(name: str) -> str:
    """
    Convert operation name to a macro-friendly suffix:
    - Uppercase
    - Replace non-alnum with underscore
    - Collapse underscores
    - Ensure it doesn't start with a digit
    """
    s = name.strip().upper()
    # Replace non-alnum with underscore
    s = re.sub(r'[^A-Z0-9]+', '_', s)
    s = re.sub(r'_+', '_', s).strip('_')
    if not s:
        s = "OP"
    if re.match(r'^\d', s):
        s = "_" + s
    return s

def parse_hex_field(s: str) -> int:
    s = (s or "").strip()
    if not s:
        raise ValueError("empty hex field")
    # accept "0x...." or plain hex digits
    return int(s, 16) if s.lower().startswith("0x") else int("0x" + s, 16)

def c_escape(s: str) -> str:
    """Escape for C++ string literal."""
    return (
        s.replace("\\", "\\\\")
         .replace('"', '\\"')
         .replace("\n", "\\n")
         .replace("\r", "\\r")
         .replace("\t", "\\t")
    )

def main():
    want_sort_by_call_ea = False
    argv = [a for a in sys.argv[1:]]
    if "--sort-by-call-ea" in argv:
        want_sort_by_call_ea = True
        argv.remove("--sort-by-call-ea")

    if len(argv) < 1:
        print(
            "Usage: gen_register_operation_type_cpp.py [--sort-by-call-ea] ParamOp_RegisterOperationType.csv [out.cpp]",
            file=sys.stderr,
        )
        sys.exit(2)

    in_csv = Path(argv[0])
    out_cpp = Path(argv[1]) if len(argv) >= 2 else in_csv.with_suffix(".generated.cpp")

    rows = []
    with in_csv.open("r", encoding="utf-8-sig", newline="") as fp:
        reader = csv.DictReader(fp)
        required = {"call_ea", "guid_d1", "guid_d2", "name"}
        if not required.issubset(set(reader.fieldnames or [])):
            raise RuntimeError(f"CSV missing required columns. Need {sorted(required)}, got {reader.fieldnames}")

        for r in reader:
            call_ea = parse_hex_field(r["call_ea"])
            d1 = parse_hex_field(r["guid_d1"])
            d2 = parse_hex_field(r["guid_d2"])
            name = (r["name"] or "").strip()
            if not name:
                # if name is empty, still generate something deterministic
                name = f"OP_{call_ea:08X}"
            rows.append((call_ea, d1 & 0xFFFFFFFF, d2 & 0xFFFFFFFF, name))

    # Default: preserve CSV order (first-seen).
    # Optional: stable order by call address (old behavior)
    if want_sort_by_call_ea:
        rows.sort(key=lambda x: x[0])

    # Deduplicate macro names; also avoid emitting identical GUID+name duplicates
    used_macro = {}  # base_macro -> count
    seen = set()     # (d1,d2,name) to avoid exact duplicates

    defines = []
    calls = []

    for call_ea, d1, d2, name in rows:
        key = (d1, d2, name)
        if key in seen:
            continue
        seen.add(key)

        suffix = sanitize_macro_suffix(name)
        base_macro = f"CKOGUID_{suffix}"

        cnt = used_macro.get(base_macro, 0) + 1
        used_macro[base_macro] = cnt
        macro = base_macro if cnt == 1 else f"{base_macro}_{cnt}"

        defines.append(f"#define {macro} CKGUID(0x{d1:08X},0x{d2:08X})  // {name}")
        calls.append(f'    pm->RegisterOperationType({macro}, "{c_escape(name)}");')

    # Compose output
    out_lines = []
    out_lines.append("// Auto-generated from ParamOp_RegisterOperationType.csv")
    out_lines.append("// Do not edit manually.")
    out_lines.append("")
    out_lines.append("// GUID macros")
    out_lines.extend(defines)
    out_lines.append("")
    out_lines.append("void CKInitializeOperationTypes(CKContext *context)")
    out_lines.append("{")
    out_lines.append("    CKParameterManager *pm = context->GetParameterManager();")
    out_lines.append("")
    out_lines.extend(calls)
    out_lines.append("}")
    out_lines.append("")

    out_cpp.write_text("\n".join(out_lines), encoding="utf-8")
    print(f"Wrote: {out_cpp}")

if __name__ == "__main__":
    main()
