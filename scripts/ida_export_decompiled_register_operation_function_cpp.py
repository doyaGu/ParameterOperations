#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""IDAPython helper: generate a .cpp with Hex-Rays decompiled opfunc implementations.

This is a thin wrapper around scripts/gen_register_operation_function_cpp.py in --decompile mode.

Run inside IDA:
- File -> Script file... -> choose this file

It writes:
- ParamOp_RegisterOperationFunction.decompiled.cpp next to the CSV (unless overridden).

Env overrides (optional):
- PARAMOP_CSV
- PARAMOP_OP_TYPES_H
- PARAMOP_PARAM_TYPES_H
- PARAMOP_OUT_CPP
"""

from __future__ import annotations

import os
import runpy
from pathlib import Path


def _main():
    here = Path(__file__).resolve().parent

    csv_path = Path(os.environ.get("PARAMOP_CSV", str(here.parent / "ParamOp_RegisterOperationFunction.csv")))
    op_types_h = Path(os.environ.get("PARAMOP_OP_TYPES_H", str(here.parent / "ParameterOperationTypes.h")))
    param_types_h = Path(os.environ.get("PARAMOP_PARAM_TYPES_H", str(here.parent / "ParameterTypes.h")))
    out_cpp = Path(os.environ.get("PARAMOP_OUT_CPP", str(csv_path.with_suffix(".decompiled.cpp"))))

    gen = here / "gen_register_operation_function_cpp.py"
    argv = [
        str(gen),
        "--decompile",
        str(csv_path),
        str(op_types_h),
        str(param_types_h),
        str(out_cpp),
    ]

    import sys

    old_argv = sys.argv
    try:
        sys.argv = argv
        runpy.run_path(str(gen), run_name="__main__")
    finally:
        sys.argv = old_argv


if __name__ == "__main__":
    _main()
