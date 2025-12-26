# -*- coding: utf-8 -*-
# IDA Python 7.x+
#
# Export:
#  1) CKParameterManager::RegisterOperationType(OpCode GUID, name string)
#  2) CKParameterManager::RegisterOperationFunction(operation GUID&, type_res GUID&, type_p1 GUID&, type_p2 GUID&, opfunc)
#
# Output: CSV + JSON in the same folder as the .idb/.i64.
#
# Notes:
#  - Best results with Hex-Rays (ctree-based extraction).
#  - Fallback mode (no Hex-Rays): x86-only, push-tracing heuristic, limited accuracy.

import os
import json
import csv
import traceback

import idaapi
import idautils
import idc
import ida_name
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_nalt

try:
    import ida_hexrays
    HAS_HEXRAYS = True
except Exception:
    HAS_HEXRAYS = False


# ----------------------------
# Helpers
# ----------------------------

def log(msg):
    ida_kernwin.msg(str(msg) + "\n")

def get_idb_dir():
    p = idc.get_idb_path()
    return os.path.dirname(p) if p else os.getcwd()

def safe_name(ea):
    n = ida_name.get_name(ea)
    if n:
        return n
    fn = ida_funcs.get_func_name(ea)
    return fn or ""

def get_func_ea_by_name_fuzzy(wanted):
    # Try exact first
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, wanted)
    if ea != ida_idaapi.BADADDR:
        f = ida_funcs.get_func(ea)
        return f.start_ea if f else ea

    # Fuzzy search: find any function name containing wanted
    for fea in idautils.Functions():
        nm = ida_funcs.get_func_name(fea) or ""
        if wanted in nm:
            return fea
    return ida_idaapi.BADADDR

def read_c_string(ea, maxlen=4096):
    if ea in (None, ida_idaapi.BADADDR) or ea == 0:
        return None
    # Prefer raw bytes and stop at first NUL. This is more reliable across IDA versions,
    # because get_strlit_contents() can return a flattened buffer with NULs removed.
    bs = None
    try:
        raw = ida_bytes.get_bytes(ea, maxlen)
        if raw:
            bs = bytes(raw).split(b"\x00", 1)[0]
    except Exception:
        bs = None

    if bs is None:
        # IDA API moves STRTYPE_* constants across modules depending on version.
        strtype_c = getattr(ida_bytes, "STRTYPE_C", getattr(ida_nalt, "STRTYPE_C", -1))
        bs = ida_bytes.get_strlit_contents(ea, maxlen, strtype_c)
        if bs is None:
            # Sometimes it's an ASCII literal without STRTYPE_C detection; try generic
            bs = ida_bytes.get_strlit_contents(ea, maxlen, -1)
    if bs is None:
        return None
    try:
        return bs.decode("utf-8", errors="replace")
    except Exception:
        try:
            return bs.decode("latin-1", errors="replace")
        except Exception:
            return repr(bs)

def guid_from_u64(u64v):
    # Decompiler often prints (struct CKGUID)0xD2D2D2D2D1D1D1D1LL.
    # Follow struct order: d1 = low32, d2 = high32
    # Normalize to unsigned 64-bit in case Hex-Rays returns a signed integer.
    u64v &= 0xFFFFFFFFFFFFFFFF
    d1 = u64v & 0xFFFFFFFF
    d2 = (u64v >> 32) & 0xFFFFFFFF
    return d1, d2

def guid_to_str(d1, d2):
    return "CKGUID(0x%08X,0x%08X)" % (d1 & 0xFFFFFFFF, d2 & 0xFFFFFFFF)

def try_read_guid_at(ea):
    if ea in (None, ida_idaapi.BADADDR) or ea == 0:
        return None
    try:
        d1 = idc.get_wide_dword(ea)
        d2 = idc.get_wide_dword(ea + 4)
        return d1, d2
    except Exception:
        return None


# ----------------------------
# Hex-Rays mode
# ----------------------------

def _hr_get_callee_name(call_expr):
    """
    call_expr: cexpr_t with op == cot_call
    Return textual callee name if possible.
    """
    try:
        callee = call_expr.x
        if callee.op == ida_hexrays.cot_obj:
            return safe_name(callee.obj_ea)
        # Sometimes: member call via cot_memptr/cot_memref, or cast
        # Use print1() as a fallback
        try:
            return call_expr.x.print1(None)
        except Exception:
            return ""
    except Exception:
        return ""

def _hr_is_num(e):
    return e is not None and e.op == ida_hexrays.cot_num

def _hr_is_var(e):
    return e is not None and e.op == ida_hexrays.cot_var

def _hr_strip_cast(e):
    while e is not None and e.op == ida_hexrays.cot_cast:
        e = e.x
    return e

def _hr_get_num_value(e):
    e = _hr_strip_cast(e)
    if e is None:
        return None
    if e.op == ida_hexrays.cot_num:
        # IDA/Hex-Rays API differences:
        # - Older versions: cnumber_t.value(NV_*)
        # - Newer versions: cnumber_t.value(tinfo_t)
        # In practice, `_value` is the most robust cross-version access.
        try:
            return int(getattr(e.n, "_value"))
        except Exception:
            pass
        try:
            # Some builds expose value() but require a type; best-effort.
            import ida_typeinf
            tif = ida_typeinf.tinfo_t()
            return int(e.n.value(tif))
        except Exception:
            return None
    return None

def _hr_get_obj_ea(e):
    e = _hr_strip_cast(e)
    if e is None:
        return None
    if e.op == ida_hexrays.cot_obj:
        return e.obj_ea
    return None

def _hr_get_lvar_idx(e):
    """
    Return local var index if expression refers to lvar or &lvar.
    """
    e = _hr_strip_cast(e)
    if e is None:
        return None
    if e.op == ida_hexrays.cot_var:
        return e.v.idx
    if e.op == ida_hexrays.cot_ref and e.x and e.x.op == ida_hexrays.cot_var:
        return e.x.v.idx
    return None

class _GuidInitCollector(ida_hexrays.ctree_visitor_t):
    """
    Collect GUID initializations from patterns like:
      v1606 = CKGUID::CKGUID(&v2729, 0xD1, 0xD2);
    We map both:
      - destination lvar (v1606)   -> (d1,d2)
      - referenced lvar (&v2729)   -> (d1,d2)
    """
    def __init__(self, cfunc):
        super(_GuidInitCollector, self).__init__(ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.guid_by_lvar = {}  # lvar_idx -> (d1,d2)

    def visit_expr(self, e):
        try:
            if e.op != ida_hexrays.cot_asg:
                return 0
            lhs = _hr_strip_cast(e.x)
            rhs = _hr_strip_cast(e.y)
            if rhs is None or rhs.op != ida_hexrays.cot_call:
                return 0

            callee_name = _hr_get_callee_name(rhs) or ""
            # Match constructor name loosely
            if "CKGUID::CKGUID" not in callee_name and "CKGUID" not in callee_name:
                return 0

            # args: (&dst, d1, d2) is the common pattern in your pseudocode
            argc = rhs.a.size()
            if argc < 3:
                return 0

            dst_expr = rhs.a[0]
            d1_expr = rhs.a[1]
            d2_expr = rhs.a[2]

            d1 = _hr_get_num_value(d1_expr)
            d2 = _hr_get_num_value(d2_expr)
            if d1 is None or d2 is None:
                return 0

            # Map &v2729
            idx_ref = _hr_get_lvar_idx(dst_expr)
            if idx_ref is not None:
                self.guid_by_lvar[idx_ref] = (d1 & 0xFFFFFFFF, d2 & 0xFFFFFFFF)

            # Map assignment target v1606
            idx_lhs = _hr_get_lvar_idx(lhs)
            if idx_lhs is not None:
                self.guid_by_lvar[idx_lhs] = (d1 & 0xFFFFFFFF, d2 & 0xFFFFFFFF)

        except Exception:
            pass
        return 0

class _CallExtractor(ida_hexrays.ctree_visitor_t):
    def __init__(self, cfunc, guid_by_lvar):
        super(_CallExtractor, self).__init__(ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.guid_by_lvar = guid_by_lvar

        self.reg_types = []   # list of dict
        self.reg_funcs = []   # list of dict

    def _resolve_guid_expr(self, e):
        """
        Return (d1,d2) if resolvable, else None
        """
        e0 = _hr_strip_cast(e)
        if e0 is None:
            return None

        # Case 1: (struct CKGUID)0x....LL
        nv = _hr_get_num_value(e0)
        if nv is not None:
            # If it's a 64-bit constant, split into 2 dwords
            # Note: If it's actually a 32-bit constant, this still works (d2 becomes 0)
            return guid_from_u64(nv)

        # Case 2: local var representing GUID or pointer to GUID
        idx = _hr_get_lvar_idx(e0)
        if idx is not None and idx in self.guid_by_lvar:
            return self.guid_by_lvar[idx]

        # Case 3: global object address (read from database)
        ea = _hr_get_obj_ea(e0)
        if ea is not None:
            g = try_read_guid_at(ea)
            if g:
                return g

        # Case 4: &global
        if e0.op == ida_hexrays.cot_ref:
            ea2 = _hr_get_obj_ea(e0.x)
            if ea2 is not None:
                g = try_read_guid_at(ea2)
                if g:
                    return g

        return None

    def _resolve_string_expr(self, e):
        e0 = _hr_strip_cast(e)
        if e0 is None:
            return None
        # Usually cot_obj pointing to string literal
        ea = _hr_get_obj_ea(e0)
        if ea is not None:
            return read_c_string(ea)

        # Fallback: printed representation
        try:
            s = e0.print1(None)
            # Hex-Rays print1() returns a tagged string; remove color/control tags.
            try:
                s = ida_lines.tag_remove(s)
            except Exception:
                pass
            return s
        except Exception:
            return None

    def _resolve_funcptr_expr(self, e):
        """
        Return (ea, name) for function pointer argument if resolvable.
        """
        e0 = _hr_strip_cast(e)
        if e0 is None:
            return (None, None)

        ea = _hr_get_obj_ea(e0)
        if ea is not None:
            return (ea, safe_name(ea) or "")

        # Some cases: constant address
        nv = _hr_get_num_value(e0)
        if nv is not None and nv != 0:
            ea2 = nv
            return (ea2, safe_name(ea2) or "")

        # Variable referencing a function pointer could be hard; return textual form
        try:
            return (None, e0.print1(None))
        except Exception:
            return (None, None)

    def visit_expr(self, e):
        try:
            if e.op != ida_hexrays.cot_call:
                return 0

            callee_name = _hr_get_callee_name(e) or ""
            if not callee_name:
                return 0

            ea_call = e.ea

            # ----------------------
            # RegisterOperationType
            # ----------------------
            if "RegisterOperationType" in callee_name:
                argc = e.a.size()
                # Common: (this, guid, name) in pseudocode for member-call wrapper, or direct call.
                # We will take the last two meaningful args as (guid, name).
                if argc < 2:
                    return 0

                guid_expr = e.a[argc - 2]
                name_expr = e.a[argc - 1]

                g = self._resolve_guid_expr(guid_expr)
                s = self._resolve_string_expr(name_expr)

                item = {
                    "call_ea": ea_call,
                    "callee": callee_name,
                    "guid_d1": g[0] if g else None,
                    "guid_d2": g[1] if g else None,
                    "name": s
                }
                self.reg_types.append(item)
                return 0

            # --------------------------
            # RegisterOperationFunction
            # --------------------------
            if "RegisterOperationFunction" in callee_name:
                argc = e.a.size()
                # Expected (this, op, type_res, type_p1, type_p2, func) OR without this depending on signature recognition
                # We will grab the last 5 args as: operation, type_res, type_p1, type_p2, func
                if argc < 5:
                    return 0

                # last 5 arguments
                op_guid_expr   = e.a[argc - 5]
                res_guid_expr  = e.a[argc - 4]
                p1_guid_expr   = e.a[argc - 3]
                p2_guid_expr   = e.a[argc - 2]
                func_expr      = e.a[argc - 1]

                op_guid  = self._resolve_guid_expr(op_guid_expr)
                res_guid = self._resolve_guid_expr(res_guid_expr)
                p1_guid  = self._resolve_guid_expr(p1_guid_expr)
                p2_guid  = self._resolve_guid_expr(p2_guid_expr)

                f_ea, f_name = self._resolve_funcptr_expr(func_expr)

                item = {
                    "call_ea": ea_call,
                    "callee": callee_name,
                    "operation_guid": op_guid,
                    "type_paramres_guid": res_guid,
                    "type_param1_guid": p1_guid,
                    "type_param2_guid": p2_guid,
                    "opfunc_ea": f_ea,
                    "opfunc_name": f_name
                }
                self.reg_funcs.append(item)
                return 0

        except Exception:
            pass
        return 0


def extract_with_hexrays(func_ea):
    if not HAS_HEXRAYS:
        raise RuntimeError("Hex-Rays not available")

    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays plugin init failed")

    f = ida_funcs.get_func(func_ea)
    if not f:
        raise RuntimeError("Function not found at 0x%X" % func_ea)

    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        raise RuntimeError("Decompile failed at 0x%X" % func_ea)

    # Pass 1: collect GUID initializations
    gc = _GuidInitCollector(cfunc)
    gc.apply_to(cfunc.body, None)

    # Pass 2: extract calls
    ce = _CallExtractor(cfunc, gc.guid_by_lvar)
    ce.apply_to(cfunc.body, None)

    return ce.reg_types, ce.reg_funcs


# ----------------------------
# Fallback x86 (no Hex-Rays)
# ----------------------------

def _decode_insn(ea):
    ins = idaapi.insn_t()
    if idaapi.decode_insn(ins, ea) <= 0:
        return None
    return ins

def _prev_insn(ea):
    return idc.prev_head(ea)

def _is_call_insn(ins):
    return ins and ins.itype in (idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni)

def _is_push_insn(ins):
    return ins and ins.itype in (idaapi.NN_push,)

def _op_to_ea_or_imm(ea, op):
    # Best-effort resolve for push operand
    t = idc.get_operand_type(ea, op)
    if t in (idc.o_imm,):
        return idc.get_operand_value(ea, op)
    if t in (idc.o_mem, idc.o_far, idc.o_near, idc.o_displ):
        return idc.get_operand_value(ea, op)
    if t in (idc.o_phrase,):
        return None
    if t in (idc.o_reg,):
        # Could track register definitions, but keep simple
        return None
    return None

def extract_with_x86_push_tracing(func_ea):
    """
    Very limited fallback: scan call sites and backtrack immediate push operands.
    Works only when arguments are pushed as immediates/offsets, not via registers.
    """
    reg_types = []
    reg_funcs = []

    f = ida_funcs.get_func(func_ea)
    if not f:
        raise RuntimeError("Function not found at 0x%X" % func_ea)

    # Try to locate callee addresses by name
    rot_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "CKParameterManager::RegisterOperationType")
    rof_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "CKParameterManager::RegisterOperationFunction")
    # If not found, fallback to any symbol containing names
    if rot_ea == ida_idaapi.BADADDR:
        for ea in idautils.Functions():
            if "RegisterOperationType" in (ida_funcs.get_func_name(ea) or ""):
                rot_ea = ea
                break
    if rof_ea == ida_idaapi.BADADDR:
        for ea in idautils.Functions():
            if "RegisterOperationFunction" in (ida_funcs.get_func_name(ea) or ""):
                rof_ea = ea
                break

    for ea in idautils.FuncItems(f.start_ea):
        ins = _decode_insn(ea)
        if not _is_call_insn(ins):
            continue

        # Identify callee
        callee = idc.get_operand_value(ea, 0)
        callee_name = safe_name(callee)

        is_rot = (callee == rot_ea) or ("RegisterOperationType" in callee_name)
        is_rof = (callee == rof_ea) or ("RegisterOperationFunction" in callee_name)
        if not (is_rot or is_rof):
            continue

        # Collect pushes backwards
        need = 3 if is_rot else 5
        pushes = []
        cur = _prev_insn(ea)
        steps = 0
        while cur != ida_idaapi.BADADDR and steps < 200 and len(pushes) < need:
            ins2 = _decode_insn(cur)
            if _is_push_insn(ins2):
                v = _op_to_ea_or_imm(cur, 0)
                pushes.append((cur, v))
            cur = _prev_insn(cur)
            steps += 1

        if len(pushes) < need:
            continue

        # pushes are collected in reverse order; reverse them to match call arg order (right-to-left push)
        pushes.reverse()
        vals = [v for (_pea, v) in pushes]

        if is_rot:
            # Guess: [guid_low, guid_high, name_ptr]
            guid_low = vals[0]
            guid_high = vals[1]
            name_ptr = vals[2]
            if guid_low is not None and guid_high is not None:
                g1, g2 = guid_low & 0xFFFFFFFF, guid_high & 0xFFFFFFFF
            else:
                g1, g2 = None, None
            s = read_c_string(name_ptr) if name_ptr else None
            reg_types.append({
                "call_ea": ea,
                "callee": callee_name,
                "guid_d1": g1,
                "guid_d2": g2,
                "name": s
            })

        if is_rof:
            # Guess: [&op, &res, &p1, &p2, funcptr]
            op_ptr, res_ptr, p1_ptr, p2_ptr, fn = vals[0], vals[1], vals[2], vals[3], vals[4]
            opg = try_read_guid_at(op_ptr) if op_ptr else None
            rsg = try_read_guid_at(res_ptr) if res_ptr else None
            p1g = try_read_guid_at(p1_ptr) if p1_ptr else None
            p2g = try_read_guid_at(p2_ptr) if p2_ptr else None
            reg_funcs.append({
                "call_ea": ea,
                "callee": callee_name,
                "operation_guid": opg,
                "type_paramres_guid": rsg,
                "type_param1_guid": p1g,
                "type_param2_guid": p2g,
                "opfunc_ea": fn,
                "opfunc_name": safe_name(fn) if fn else None
            })

    return reg_types, reg_funcs


# ----------------------------
# Export
# ----------------------------

def write_csv_types(path, items):
    with open(path, "w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp)
        w.writerow(["call_ea", "guid_d1", "guid_d2", "guid_str", "name", "callee"])
        for it in items:
            d1 = it.get("guid_d1")
            d2 = it.get("guid_d2")
            gstr = guid_to_str(d1, d2) if (d1 is not None and d2 is not None) else ""
            w.writerow([
                "0x%X" % it.get("call_ea", 0),
                ("0x%08X" % d1) if d1 is not None else "",
                ("0x%08X" % d2) if d2 is not None else "",
                gstr,
                it.get("name", "") or "",
                it.get("callee", "") or "",
            ])

def write_csv_funcs(path, items):
    with open(path, "w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp)
        w.writerow([
            "call_ea",
            "operation_guid", "type_paramres_guid", "type_param1_guid", "type_param2_guid",
            "opfunc_ea", "opfunc_name", "callee"
        ])
        for it in items:
            def gfmt(g):
                if not g or g[0] is None or g[1] is None:
                    return ""
                return guid_to_str(g[0], g[1])

            opg = it.get("operation_guid")
            rsg = it.get("type_paramres_guid")
            p1g = it.get("type_param1_guid")
            p2g = it.get("type_param2_guid")

            fea = it.get("opfunc_ea")
            w.writerow([
                "0x%X" % it.get("call_ea", 0),
                gfmt(opg),
                gfmt(rsg),
                gfmt(p1g),
                gfmt(p2g),
                ("0x%X" % fea) if isinstance(fea, int) and fea else "",
                it.get("opfunc_name", "") or "",
                it.get("callee", "") or "",
            ])

def main():
    # Try common names
    func_ea = ida_idaapi.BADADDR
    for cand in ["_ParamOp_InitInstance", "ParamOp_InitInstance"]:
        func_ea = get_func_ea_by_name_fuzzy(cand)
        if func_ea != ida_idaapi.BADADDR:
            break
    if func_ea == ida_idaapi.BADADDR:
        raise RuntimeError("Cannot find ParamOp_InitInstance by name. Please rename the function and re-run.")

    log("[*] Target function: 0x%X (%s)" % (func_ea, ida_funcs.get_func_name(func_ea)))

    # Extract
    try:
        reg_types, reg_funcs = extract_with_hexrays(func_ea)
        log("[*] Extracted with Hex-Rays.")
    except Exception as e:
        log("[!] Hex-Rays mode failed (%s). Falling back to x86 push-tracing." % e)
        reg_types, reg_funcs = extract_with_x86_push_tracing(func_ea)

    out_dir = get_idb_dir()
    path_types = os.path.join(out_dir, "ParamOp_RegisterOperationType.csv")
    path_funcs = os.path.join(out_dir, "ParamOp_RegisterOperationFunction.csv")
    path_json  = os.path.join(out_dir, "ParamOp_All.json")

    write_csv_types(path_types, reg_types)
    write_csv_funcs(path_funcs, reg_funcs)

    with open(path_json, "w", encoding="utf-8") as fp:
        json.dump({
            "function": "0x%X" % func_ea,
            "register_operation_type": reg_types,
            "register_operation_function": reg_funcs
        }, fp, ensure_ascii=False, indent=2)

    log("[+] Done.")
    log("    - %s" % path_types)
    log("    - %s" % path_funcs)
    log("    - %s" % path_json)
    log("    Types: %d, Functions: %d" % (len(reg_types), len(reg_funcs)))


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        log("[X] Failed: %s" % ex)
        log(traceback.format_exc())
        raise
