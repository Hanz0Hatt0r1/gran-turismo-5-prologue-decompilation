# Apply a gtdecomp.py index to the currently open Ghidra program.
#@category Gran Turismo Decompilation

from __future__ import print_function

import csv
import os
import re

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

script_args = list(getScriptArgs())
if script_args:
    root = os.path.abspath(script_args[0])
else:
    root = askDirectory("Select gtdecomp index directory", "Open").getAbsolutePath()
listing = currentProgram.getListing()
symbols = currentProgram.getSymbolTable()
functions = currentProgram.getFunctionManager()


def addr(text):
    return toAddr(int(text, 16))


def clean(text, limit=120):
    text = re.sub(r"[^A-Za-z0-9_]", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    if not text:
        text = "unknown"
    if text[0].isdigit():
        text = "n_" + text
    return text[:limit]


def add_label(a, name):
    try:
        current = symbols.getPrimarySymbol(a)
        if current is None:
            symbols.createLabel(a, name, SourceType.USER_DEFINED)
    except Exception:
        pass


def add_comment(a, text):
    try:
        old = listing.getComment(CodeUnit.PLATE_COMMENT, a)
        if old:
            if text in old:
                return
            text = old + "\n" + text
        listing.setComment(a, CodeUnit.PLATE_COMMENT, text)
    except Exception:
        pass


def rows(name):
    path = os.path.join(root, name)
    if not os.path.exists(path):
        return []
    return csv.DictReader(open(path, "r"))


# Materialize high-confidence function starts. This includes OPD entries, direct
# branch-and-link targets, and standard PPC64 stack-prologue discoveries.
function_table = "discovered_functions.csv" if os.path.exists(os.path.join(root, "discovered_functions.csv")) else "functions.csv"
for r in rows(function_table):
    a = addr(r["code_va"])
    fn = functions.getFunctionAt(a)
    if fn is None:
        try:
            disassemble(a)
            fn = createFunction(a, None)
        except Exception:
            fn = None
    target = fn.getEntryPoint() if fn else a
    add_comment(target, "gtdecomp function-id: %s; normalized size=%s" % (r["sha_full"], r["size"]))

# Add aggregated source/vtable evidence before decompilation.
for r in rows("function_hints.csv"):
    a = addr(r["code_va"])
    fn = functions.getFunctionAt(a)
    target = fn.getEntryPoint() if fn else a
    evidence = []
    if r.get("source_files"):
        evidence.append("source: " + r["source_files"])
    if r.get("vtable_types"):
        evidence.append("vtable: " + r["vtable_types"])
    if evidence:
        add_comment(target, "gtdecomp evidence: " + "; ".join(evidence))

# Import stubs. NIDs remain exact identities even when a human-readable API
# name has not yet been resolved by a separate NID database.
for r in rows("imports.csv"):
    a = addr(r["stub_code_va"])
    label = "imp_%s_%s" % (clean(r["library"], 48), r["nid"].replace("0x", ""))
    add_label(a, label)
    add_comment(a, "PS3 import: %s NID %s" % (r["library"], r["nid"]))

# RTTI objects.
seen_names = {}
for r in rows("rtti.csv"):
    a = addr(r["typeinfo_va"])
    base = "typeinfo_" + clean(r["demangled"], 90)
    count = seen_names.get(base, 0)
    seen_names[base] = count + 1
    if count:
        base += "_" + r["typeinfo_va"].replace("0x", "")
    add_label(a, base)
    add_comment(a, "C++ RTTI candidate: %s" % r["demangled"])

# Vtable starts and per-function slot evidence.
seen_vtables = set()
for r in rows("vtables.csv"):
    vt = r["vtable_start"]
    if vt not in seen_vtables:
        seen_vtables.add(vt)
        a = addr(vt)
        add_label(a, "vtable_" + clean(r["demangled"], 90) + "_" + vt.replace("0x", ""))
        add_comment(a, "C++ vtable candidate: %s; typeinfo %s" % (r["demangled"], r["typeinfo_va"]))
    code = addr(r["code_va"])
    fn = functions.getFunctionAt(code)
    target = fn.getEntryPoint() if fn else code
    add_comment(target, "vtable evidence: %s slot %s" % (r["demangled"], r["slot"]))

# Source-file strings are retained as evidence, so label their string address.
for r in rows("source_files.csv"):
    add_label(addr(r["va"]), "src_" + clean(os.path.basename(r["source_file"]), 100))

print("gtdecomp annotations applied; existing function names were preserved.")