# Export local Ghidra decompiler output for functions discovered by gtdecomp.py.
# Output is intentionally local analysis material and should not be committed.
#@category Gran Turismo Decompilation

from __future__ import print_function

import csv
import os

from ghidra.app.decompiler import DecompInterface


script_args = list(getScriptArgs())
if len(script_args) >= 2:
    index_root = os.path.abspath(script_args[0])
    output_root = os.path.abspath(script_args[1])
else:
    index_root = askDirectory("Select gtdecomp index directory", "Open").getAbsolutePath()
    output_root = askDirectory("Select decompilation output directory", "Save").getAbsolutePath()

timeout_seconds = int(script_args[2]) if len(script_args) >= 3 else 90
functions_dir = os.path.join(output_root, "functions")
if not os.path.isdir(functions_dir):
    os.makedirs(functions_dir)


def read_csv(name):
    path = os.path.join(index_root, name)
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return list(csv.DictReader(f))


fingerprints = {}
function_table = "discovered_functions.csv" if os.path.exists(os.path.join(index_root, "discovered_functions.csv")) else "functions.csv"
for row in read_csv(function_table):
    fingerprints[int(row["code_va"], 16)] = row

hints = {}
for row in read_csv("function_hints.csv"):
    hints[int(row["code_va"], 16)] = row

manager = currentProgram.getFunctionManager()
decompiler = DecompInterface()
decompiler.toggleCCode(True)
decompiler.toggleSyntaxTree(True)
if not decompiler.openProgram(currentProgram):
    raise RuntimeError("failed to open current Ghidra program in the decompiler")

manifest_path = os.path.join(output_root, "decompilation_manifest.csv")
fields = [
    "code_va",
    "function_id",
    "ghidra_name",
    "status",
    "source_files",
    "vtable_types",
    "output_file",
    "error",
]
with open(manifest_path, "w") as mf:
    writer = csv.DictWriter(mf, fieldnames=fields)
    writer.writeheader()
    for code_va in sorted(fingerprints):
        if monitor.isCancelled():
            break
        fp = fingerprints[code_va]
        function_id = fp["sha_full"]
        a = toAddr(code_va)
        fn = manager.getFunctionAt(a)
        hint = hints.get(code_va, {})
        row = {
            "code_va": "0x%08x" % code_va,
            "function_id": function_id,
            "ghidra_name": fn.getName() if fn else "",
            "status": "missing-function" if fn is None else "pending",
            "source_files": hint.get("source_files", ""),
            "vtable_types": hint.get("vtable_types", ""),
            "output_file": "",
            "error": "",
        }
        if fn is None:
            writer.writerow(row)
            continue
        try:
            result = decompiler.decompileFunction(fn, timeout_seconds, monitor)
            if not result.decompileCompleted():
                row["status"] = "failed"
                row["error"] = result.getErrorMessage() or "decompilation did not complete"
                writer.writerow(row)
                continue
            decompiled = result.getDecompiledFunction()
            if decompiled is None:
                row["status"] = "failed"
                row["error"] = "Ghidra returned no decompiled function"
                writer.writerow(row)
                continue
            rel = os.path.join("functions", "%08x.c" % code_va)
            dst = os.path.join(output_root, rel)
            with open(dst, "w") as out:
                out.write("/* gtdecomp function-id: %s */\n" % function_id)
                if row["source_files"]:
                    out.write("/* source evidence: %s */\n" % row["source_files"])
                if row["vtable_types"]:
                    out.write("/* vtable evidence: %s */\n" % row["vtable_types"])
                out.write(decompiled.getC())
                if not decompiled.getC().endswith("\n"):
                    out.write("\n")
            row["status"] = "ok"
            row["output_file"] = rel.replace(os.sep, "/")
        except Exception as exc:
            row["status"] = "failed"
            row["error"] = str(exc)
        writer.writerow(row)

try:
    decompiler.dispose()
except Exception:
    pass

print("gtdecomp decompilation export written to %s" % output_root)