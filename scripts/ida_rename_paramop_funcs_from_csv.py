#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""IDA Python: rename & type param-operation functions based on ParamOp_RegisterOperationFunction.csv.

What it does
- Parses ParamOp_RegisterOperationFunction.csv (exported from IDA).
- Decompiles ParamOp_InitInstance and re-extracts RegisterOperationFunction calls
  (GUIDs + actual funcptr EA) using export_paramops.extract_with_hexrays.
- Matches by the 4 GUIDs (op/res/p1/p2).
- Renames the target function pointer to an undecorated identifier (same logic as
  gen_register_operation_function_cpp.py).
- Applies a uniform prototype and argument names:
	void __cdecl NAME(CKContext *context, CKParameterOut *res, CKParameterIn *p1, CKParameterIn *p2);

Requirements
- Hex-Rays decompiler (this script relies on robust ctree extraction).

Usage (inside IDA)
- File -> Script file... -> select this file.

Configuration
- CSV_PATH defaults to ParamOp_RegisterOperationFunction.csv next to this script.
- TARGET_FUNC_NAME defaults to ParamOp_InitInstance.

You can override via env vars:
- PARAMOP_ROF_CSV
- PARAMOP_TARGET_FUNC
"""

from __future__ import annotations

import csv
import os
import re
from pathlib import Path
from typing import Dict, Tuple

import ida_funcs
import ida_idaapi
import ida_name
import ida_typeinf


Guid = Tuple[int, int]
Guid4Key = Tuple[Guid, Guid, Guid, Guid]

GUID_RE = re.compile(
	r"CKGUID\s*\(\s*(0x[0-9A-Fa-f]+|\d+)\s*,\s*(0x[0-9A-Fa-f]+|\d+)\s*\)"
)


def _log(msg: str) -> None:
	print(f"[ida_rename_paramop_funcs_from_csv] {msg}")


def _parse_int_auto(s: str) -> int:
	s = (s or "").strip()
	if not s:
		raise ValueError("empty int string")
	if s.lower().startswith("0x"):
		return int(s, 16)
	return int(s, 10)


def parse_guid_str(s: str) -> Guid:
	"""Parse 'CKGUID(0x...,0x...)' into (d1,d2)."""
	m = GUID_RE.search(s or "")
	if not m:
		raise ValueError(f"cannot parse guid from: {s!r}")
	d1 = _parse_int_auto(m.group(1)) & 0xFFFFFFFF
	d2 = _parse_int_auto(m.group(2)) & 0xFFFFFFFF
	return (d1, d2)


def clean_ident(name: str) -> str:
	n = (name or "").strip()
	if not n:
		return "OpFunc"
	n = re.sub(r"[^A-Za-z0-9_]", "_", n)
	n = re.sub(r"_+", "_", n).strip("_")
	if not n:
		return "OpFunc"
	if re.match(r"^\d", n):
		n = "_" + n
	return n


def undecorate_msvc(name: str) -> str:
	"""Best-effort MSVC decorated name -> base identifier."""
	if not name:
		return "OpFunc"
	s = name.strip()
	if s.startswith("?"):
		m = re.match(r"^\?([^@]+)@@", s)
		if m:
			return clean_ident(m.group(1))
		m2 = re.match(r"^\?([^@]+)@", s)
		if m2:
			return clean_ident(m2.group(1))
		return "OpFunc"
	if "::" in s:
		s = s.split("::")[-1]
	return clean_ident(s)


def _dynamic_import_export_paramops(script_dir: Path):
	"""Load export_paramops.py from the same folder as this script."""
	export_path = script_dir / "export_paramops.py"
	if not export_path.exists():
		raise RuntimeError(f"Cannot find export_paramops.py next to this script: {export_path}")

	import importlib.util

	spec = importlib.util.spec_from_file_location("export_paramops", str(export_path))
	if spec is None or spec.loader is None:
		raise RuntimeError("Failed to create import spec for export_paramops")
	mod = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(mod)
	return mod


def read_csv_mapping(csv_path: Path) -> Dict[Guid4Key, str]:
	"""Return mapping: (op,res,p1,p2) -> opfunc_name_raw (decorated)."""
	mapping: Dict[Guid4Key, str] = {}

	with csv_path.open("r", encoding="utf-8-sig", newline="") as fp:
		reader = csv.DictReader(fp)
		required = {
			"operation_guid",
			"type_paramres_guid",
			"type_param1_guid",
			"type_param2_guid",
			"opfunc_name",
		}
		fields = set(reader.fieldnames or [])
		if not required.issubset(fields):
			raise RuntimeError(
				f"CSV missing required columns. Need {sorted(required)}, got {sorted(fields)}"
			)

		for row in reader:
			try:
				op = parse_guid_str(row["operation_guid"])
				res = parse_guid_str(row["type_paramres_guid"])
				p1 = parse_guid_str(row["type_param1_guid"])
				p2 = parse_guid_str(row["type_param2_guid"])
			except Exception:
				continue

			key: Guid4Key = (op, res, p1, p2)
			name_raw = (row.get("opfunc_name") or "").strip()
			if key not in mapping:
				mapping[key] = name_raw

	return mapping


def _ensure_forward_types() -> None:
	"""Ensure CKContext/CKParameterOut/CKParameterIn exist as forward decls."""
	decls = "\n".join(
		[
			"struct CKContext;",
			"struct CKParameterOut;",
			"struct CKParameterIn;",
		]
	)

	try:
		ida_typeinf.parse_types(decls, ida_typeinf.PT_SIL)
		return
	except Exception:
		pass

	try:
		import idc

		idc.parse_decls(decls, idc.PT_SIL)
	except Exception:
		pass


def _make_unique_name(base: str, ea: int) -> str:
	base = clean_ident(base)
	if not base:
		base = "OpFunc"

	if ida_name.get_name_ea(ida_idaapi.BADADDR, base) == ida_idaapi.BADADDR:
		return base

	cand = f"{base}_{ea:X}"
	if ida_name.get_name_ea(ida_idaapi.BADADDR, cand) == ida_idaapi.BADADDR:
		return cand

	i = 2
	while True:
		cand2 = f"{base}_{ea:X}_{i}"
		if ida_name.get_name_ea(ida_idaapi.BADADDR, cand2) == ida_idaapi.BADADDR:
			return cand2
		i += 1


def _can_use_name_exact(desired: str, ea: int) -> bool:
	"""Return True if we can set `desired` at `ea` without IDA auto-suffixing.

	IDA requires global uniqueness; if a different address already owns the name,
	we skip renaming rather than allowing an auto-suffixed variant.
	"""
	desired = (desired or "").strip()
	if not desired:
		return False
	other = ida_name.get_name_ea(ida_idaapi.BADADDR, desired)
	return other in (ida_idaapi.BADADDR, ea)


def _ensure_function_at(ea: int) -> bool:
	if ea is None or ea in (0, ida_idaapi.BADADDR):
		return False
	if ida_funcs.get_func(ea):
		return True
	return bool(ida_funcs.add_func(ea))


def _apply_prototype(ea: int, name: str) -> bool:
	_ensure_forward_types()
	# IMPORTANT: do NOT embed the actual function name here.
	# Many targets are renamed to MSVC-mangled identifiers like '?Foo@@YAX...@Z',
	# which are not valid C identifiers for the type parser.
	decl = (
		"void __cdecl __paramop_opfunc(CKContext *context, CKParameterOut *res, "
		"CKParameterIn *p1, CKParameterIn *p2);"
	)

	try:
		tif = ida_typeinf.tinfo_t()
		ok = ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL)
		if ok:
			ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
			return True
	except Exception:
		pass

	try:
		import idc

		return bool(idc.SetType(ea, decl))
	except Exception:
		return False


def rename_and_type_from_csv(csv_path: Path, target_func_name: str = "ParamOp_InitInstance") -> dict:
	script_dir = Path(__file__).resolve().parent if "__file__" in globals() else Path.cwd()
	export_paramops = _dynamic_import_export_paramops(script_dir)

	func_ea = ida_idaapi.BADADDR
	for cand in [target_func_name, f"_{target_func_name}"]:
		try:
			func_ea = export_paramops.get_func_ea_by_name_fuzzy(cand)
		except Exception:
			func_ea = ida_idaapi.BADADDR
		if func_ea != ida_idaapi.BADADDR:
			break
	if func_ea == ida_idaapi.BADADDR:
		raise RuntimeError(f"Cannot find target function by name: {target_func_name!r}")

	_log(f"Target: 0x{func_ea:X} ({ida_funcs.get_func_name(func_ea)})")

	mapping = read_csv_mapping(csv_path)
	_log(f"CSV rows (unique keys): {len(mapping)}")

	_reg_types, reg_funcs = export_paramops.extract_with_hexrays(func_ea)
	_log(f"Hex-Rays extracted RegisterOperationFunction calls: {len(reg_funcs)}")

	renamed = 0
	typed = 0
	missing = 0
	bad_ea = 0
	name_collisions = 0

	for it in reg_funcs:
		op = it.get("operation_guid")
		res = it.get("type_paramres_guid")
		p1 = it.get("type_param1_guid")
		p2 = it.get("type_param2_guid")
		fn_ea = it.get("opfunc_ea")

		if not (op and res and p1 and p2):
			missing += 1
			continue

		key: Guid4Key = (op, res, p1, p2)
		raw = mapping.get(key)
		if not raw:
			missing += 1
			continue

		if not isinstance(fn_ea, int) or fn_ea in (0, ida_idaapi.BADADDR):
			bad_ea += 1
			continue

		# User requirement: rename to the ORIGINAL mangled symbol name from CSV.
		desired_name = (raw or "").strip()

		_ensure_function_at(fn_ea)

		old_name = ida_funcs.get_func_name(fn_ea) or ""
		if desired_name and old_name != desired_name:
			if _can_use_name_exact(desired_name, fn_ea):
				if ida_name.set_name(fn_ea, desired_name, ida_name.SN_FORCE):
					renamed += 1
			else:
				# Do not allow IDA to auto-append suffixes.
				name_collisions += 1

		# Apply the prototype regardless of rename success.
		if _apply_prototype(fn_ea, "__paramop_opfunc"):
			typed += 1

	stats = {
		"target_func_ea": func_ea,
		"csv_unique_keys": len(mapping),
		"hex_calls": len(reg_funcs),
		"renamed": renamed,
		"typed": typed,
		"missing_csv_match": missing,
		"bad_func_ea": bad_ea,
		"name_collisions": name_collisions,
	}

	_log(f"Done. renamed={renamed}, typed={typed}, missing_csv_match={missing}, bad_func_ea={bad_ea}")
	return stats


try:
	_this = Path(__file__).resolve() if "__file__" in globals() else None
except Exception:
	_this = None

SCRIPT_DIR = _this.parent if _this else Path.cwd()
CSV_PATH = Path(os.environ.get("PARAMOP_ROF_CSV", str(SCRIPT_DIR / "ParamOp_RegisterOperationFunction.csv")))
TARGET_FUNC_NAME = os.environ.get("PARAMOP_TARGET_FUNC", "ParamOp_InitInstance")

if __name__ == "__main__":
	st = rename_and_type_from_csv(CSV_PATH, TARGET_FUNC_NAME)
	_log(str(st))
