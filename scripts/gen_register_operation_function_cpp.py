#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import re
import sys
from pathlib import Path
from typing import Dict, Tuple, Optional, Set, List

# Optional (IDA/Hex-Rays) imports are loaded lazily.

Guid = Tuple[int, int]

# ---------- Parsing helpers ----------

GUID_RE = re.compile(
    r'CKGUID\s*\(\s*(0x[0-9A-Fa-f]+|\d+)\s*,\s*(0x[0-9A-Fa-f]+|\d+)\s*\)'
)

def parse_int_auto(s: str) -> int:
    s = (s or "").strip()
    if not s:
        raise ValueError("empty int string")
    if s.lower().startswith("0x"):
        return int(s, 16)
    # allow decimal
    return int(s, 10)

def parse_guid_str(s: str) -> Guid:
    """
    Input like: CKGUID(0x68EC3C11,0x41F36A69) or with spaces.
    """
    m = GUID_RE.search(s or "")
    if not m:
        raise ValueError(f"cannot parse guid from: {s!r}")
    d1 = parse_int_auto(m.group(1)) & 0xFFFFFFFF
    d2 = parse_int_auto(m.group(2)) & 0xFFFFFFFF
    return (d1, d2)

def guid_inline(g: Guid) -> str:
    return f"CKGUID(0x{g[0]:08X},0x{g[1]:08X})"

def c_escape(s: str) -> str:
    return (
        s.replace("\\", "\\\\")
         .replace('"', '\\"')
         .replace("\n", "\\n")
         .replace("\r", "\\r")
         .replace("\t", "\\t")
    )

def clean_ident(name: str) -> str:
    """
    Make a valid C/C++ identifier from arbitrary text.
    """
    n = (name or "").strip()
    if not n:
        return "OpFunc"
    n = re.sub(r'[^A-Za-z0-9_]', '_', n)
    n = re.sub(r'_+', '_', n).strip('_')
    if not n:
        return "OpFunc"
    if re.match(r'^\d', n):
        n = "_" + n
    return n

def undecorate_msvc(name: str) -> str:
    """
    Best-effort MSVC decorated name -> base function identifier.
    Example: ?CKFloatPerSecondFloat@@YAXPAVCKContext@@... -> CKFloatPerSecondFloat
    If it's already undecorated, return it as-is (sanitized).
    """
    if not name:
        return "OpFunc"
    s = name.strip()
    if s.startswith("?"):
        # take between leading '?' and '@@'
        m = re.match(r'^\?([^@]+)@@', s)
        if m:
            return clean_ident(m.group(1))
        # fallback: between '?' and first '@'
        m2 = re.match(r'^\?([^@]+)@', s)
        if m2:
            return clean_ident(m2.group(1))
        return "OpFunc"
    # If it contains namespaces, take tail
    if "::" in s:
        s = s.split("::")[-1]
    return clean_ident(s)

# ---------- Header parsing ----------

def parse_guid_macros_from_header(hpath: Path) -> Dict[Guid, str]:
    """
    Parse header for patterns like:
      #define CKOGUID_MODULO CKGUID(0x...,0x...)
      static const CKGUID CKPGUID_INT = CKGUID(0x...,0x...)
      const CKGUID CKPGUID_INT = CKGUID(...)
    Returns mapping: (d1,d2) -> SYMBOL_NAME
    If duplicates exist, first wins and later are ignored (but you can change policy).
    """
    text = hpath.read_text(encoding="utf-8", errors="ignore")

    # capture: name ... CKGUID(...)
    # We accept both macro and variable forms.
    # Group 1: symbol; group 2/3: d1/d2
    pat = re.compile(
        r'^\s*(?:#\s*define\s+|(?:static\s+)?(?:const\s+)?CKGUID\s+|(?:static\s+)?(?:const\s+)?struct\s+CKGUID\s+|(?:static\s+)?(?:const\s+)?\w+\s+)?'
        r'([A-Za-z_][A-Za-z0-9_]*)'
        r'\s*(?:=\s*)?'
        r'CKGUID\s*\(\s*(0x[0-9A-Fa-f]+|\d+)\s*,\s*(0x[0-9A-Fa-f]+|\d+)\s*\)\s*;?',
        re.MULTILINE
    )

    out: Dict[Guid, str] = {}
    for m in pat.finditer(text):
        sym = m.group(1)
        d1 = parse_int_auto(m.group(2)) & 0xFFFFFFFF
        d2 = parse_int_auto(m.group(3)) & 0xFFFFFFFF
        g = (d1, d2)
        if g not in out:
            out[g] = sym
    return out

# ---------- CSV processing & codegen ----------

def read_csv_rows(csv_path: Path) -> List[dict]:
    rows = []
    with csv_path.open("r", encoding="utf-8-sig", newline="") as fp:
        reader = csv.DictReader(fp)
        required = {
            "call_ea",
            "operation_guid",
            "type_paramres_guid",
            "type_param1_guid",
            "type_param2_guid",
            "opfunc_ea",
            "opfunc_name",
        }
        if not required.issubset(set(reader.fieldnames or [])):
            raise RuntimeError(f"CSV missing required columns. Need {sorted(required)}, got {reader.fieldnames}")

        for r in reader:
            rows.append(r)
    return rows

def parse_hex_field(s: str) -> int:
    s = (s or "").strip()
    if not s:
        return 0
    return int(s, 16) if s.lower().startswith("0x") else int(s, 16)


def _try_import_ida():
    """Return (ida_hexrays, ida_lines) if running under IDA, else (None, None)."""
    try:
        import ida_hexrays  # type: ignore
        import ida_lines  # type: ignore

        return ida_hexrays, ida_lines
    except Exception:
        return None, None


def _strip_ida_tags(s: str, ida_lines_mod) -> str:
    if not s:
        return s
    if ida_lines_mod is None:
        return s
    try:
        return ida_lines_mod.tag_remove(s)
    except Exception:
        return s


def _decompile_body_lines(ea: int, ida_hexrays_mod, ida_lines_mod) -> Optional[List[str]]:
    """Decompile `ea` and return pseudocode body lines including braces, or None on failure."""
    if ida_hexrays_mod is None:
        return None
    try:
        if not ida_hexrays_mod.init_hexrays_plugin():
            return None
        cfunc = ida_hexrays_mod.decompile(ea)
        if not cfunc:
            return None
        pseudo = cfunc.get_pseudocode()
        lines = [_strip_ida_tags(ln.line, ida_lines_mod).rstrip() for ln in pseudo]

        # Extract only the function body (from the first '{' to the matching final '}' line).
        start = None
        for i, ln in enumerate(lines):
            if "{" in ln:
                start = i
                break
        if start is None:
            return None
        body = lines[start:]
        return body
    except Exception:
        return None

def main():
    # Optional flags:
    # When run under IDA (idapython), this will decompile each opfunc_ea and emit a real body.
    # When run as normal Python, it will refuse (no Hex-Rays).
    want_decompile = False
    want_sort_by_call_ea = False
    argv = [a for a in sys.argv[1:]]
    if "--decompile" in argv:
        want_decompile = True
        argv.remove("--decompile")
    if "--sort-by-call-ea" in argv:
        want_sort_by_call_ea = True
        argv.remove("--sort-by-call-ea")

    if len(argv) < 3:
        print(
            "Usage:\n"
            "  gen_register_operation_function_cpp.py [--decompile] [--sort-by-call-ea] ParamOp_RegisterOperationFunction.csv "
            "ParameterOperationTypes.h ParameterTypes.h [out.cpp]\n\n"
            "Notes:\n"
            "  --decompile requires running inside IDA Pro with Hex-Rays (idapython).\n",
            file=sys.stderr
        )
        sys.exit(2)

    csv_path = Path(argv[0])
    op_types_h = Path(argv[1])
    param_types_h = Path(argv[2])
    out_cpp = Path(argv[3]) if len(argv) >= 4 else csv_path.with_suffix(".generated.cpp")

    ida_hexrays, ida_lines = _try_import_ida()
    if want_decompile and ida_hexrays is None:
        raise RuntimeError("--decompile requested but IDA/Hex-Rays modules are not available. Run inside IDA (idapython).")

    # Build GUID -> symbol maps from both headers
    op_guid_map = parse_guid_macros_from_header(op_types_h)
    param_guid_map = parse_guid_macros_from_header(param_types_h)

    # Merge into a single resolver (prefer op map for operation GUIDs; param map for param GUIDs)
    def resolve_guid(g: Guid, kind: str) -> str:
        """
        kind: 'op' or 'param'
        """
        if kind == "op":
            if g in op_guid_map:
                return op_guid_map[g]
            # fallback to param map (sometimes op GUIDs are also present there)
            if g in param_guid_map:
                return param_guid_map[g]
            return guid_inline(g)
        else:
            if g in param_guid_map:
                return param_guid_map[g]
            # fallback to op map (rare, but safe)
            if g in op_guid_map:
                return op_guid_map[g]
            return guid_inline(g)

    rows = read_csv_rows(csv_path)
    if want_sort_by_call_ea:
        # Optional: stable order by call_ea (old behavior)
        def key_call_ea(r: dict) -> int:
            return parse_hex_field(r.get("call_ea", "0"))

        rows.sort(key=key_call_ea)

    # Collect unique function names (first-seen order) and register calls
    # ident -> (original opfunc_name, opfunc_ea)
    funcs: Dict[str, Tuple[str, int]] = {}
    func_order: List[str] = []
    calls: List[str] = []

    unmatched_op: int = 0
    unmatched_param: int = 0

    for r in rows:
        call_ea = parse_hex_field(r["call_ea"])

        op_g = parse_guid_str(r["operation_guid"])
        res_g = parse_guid_str(r["type_paramres_guid"])
        p1_g = parse_guid_str(r["type_param1_guid"])
        p2_g = parse_guid_str(r["type_param2_guid"])

        op_sym = resolve_guid(op_g, "op")
        res_sym = resolve_guid(res_g, "param")
        p1_sym = resolve_guid(p1_g, "param")
        p2_sym = resolve_guid(p2_g, "param")

        if op_sym.startswith("CKGUID("):
            unmatched_op += 1
        if any(x.startswith("CKGUID(") for x in [res_sym, p1_sym, p2_sym]):
            unmatched_param += 1

        opfunc_name_raw = (r.get("opfunc_name") or "").strip()
        opfunc_ident_base = undecorate_msvc(opfunc_name_raw)
        opfunc_ea = parse_hex_field(r.get("opfunc_ea", "0"))

        # Ensure uniqueness in generated C++ even if undecorated names collide.
        opfunc_ident = opfunc_ident_base
        if opfunc_ident in funcs and funcs[opfunc_ident][1] != opfunc_ea:
            opfunc_ident = f"{opfunc_ident_base}_0x{opfunc_ea:X}"

        if opfunc_ident not in funcs:
            funcs[opfunc_ident] = (opfunc_name_raw, opfunc_ea)
            func_order.append(opfunc_ident)

        calls.append(
            f"    pm->RegisterOperationFunction({op_sym}, {res_sym}, {p1_sym}, {p2_sym}, {opfunc_ident});"
            f"  // call_ea=0x{call_ea:X}"
        )

    # Emit implementations (unique)
    stub_lines: List[str] = []
    for ident in func_order:
        raw, fea = funcs[ident]
        stub_lines.append(f"// Original symbol: {raw}" if raw else "// Original symbol: (none)")
        stub_lines.append(f"// opfunc_ea=0x{fea:X}" if fea else "// opfunc_ea=(unknown)")

        if want_decompile and fea:
            body = _decompile_body_lines(fea, ida_hexrays, ida_lines)
        else:
            body = None

        # Always emit a stable signature (like before).
        stub_lines.append(f"void {ident}(CKContext *context, CKParameterOut *res, CKParameterIn *p1, CKParameterIn *p2)")

        if body:
            # `body` already contains braces & statements; emit as-is.
            stub_lines.extend(body)
        else:
            # Fallback: keep old stub.
            stub_lines.append("{")
            stub_lines.append("    // TODO: implement")
            stub_lines.append("    (void)context; (void)res; (void)p1; (void)p2;")
            stub_lines.append("}")

        stub_lines.append("")

    # Compose output C++
    out_lines: List[str] = []
    out_lines.append("// Auto-generated from ParamOp_RegisterOperationFunction.csv")
    out_lines.append("// Do not edit manually.")
    out_lines.append("")
    out_lines.append(f'#include "{op_types_h.name}"')
    out_lines.append(f'#include "{param_types_h.name}"')
    out_lines.append("")
    out_lines.append("// ---- Operation function stubs ----")
    out_lines.extend(stub_lines)
    out_lines.append("")
    out_lines.append("void CKInitializeOperationFunctions(CKContext *context)")
    out_lines.append("{")
    out_lines.append("    CKParameterManager *pm = context->GetParameterManager();")
    out_lines.append("")
    out_lines.extend(calls)
    out_lines.append("}")
    out_lines.append("")
    out_lines.append("// ---- Stats ----")
    out_lines.append(f"// Unmatched operation GUIDs: {unmatched_op}")
    out_lines.append(f"// Unmatched parameter GUIDs: {unmatched_param}")
    out_lines.append("")

    out_cpp.write_text("\n".join(out_lines), encoding="utf-8")
    print(f"Wrote: {out_cpp}")
    print(f"Unmatched operation GUIDs: {unmatched_op}")
    print(f"Unmatched parameter GUIDs: {unmatched_param}")

if __name__ == "__main__":
    main()
