#!/usr/bin/env python3
"""Build upstream's CMake source list and breaker plugin without global installs."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("server", type=Path)
parser.add_argument("library", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
server, library, output = (p.resolve() for p in (args.server, args.library, args.output))
output.mkdir(parents=True, exist_ok=True)
prefix = output / "libiec61850"
subprocess.run(["make", "-C", str(library), "-j", "4", "install", f"INSTALL_PREFIX={prefix}"], check=True)
# open_server includes <libiec61850/...>; libiec61850's Make install is flat.
headers = output / "include" / "libiec61850"
headers.mkdir(parents=True, exist_ok=True)
for header in (prefix / "include").glob("*.h"):
    shutil.copy2(header, headers / header.name)

cmake = (server / "CMakeLists.txt").read_text()
match = re.search(r"set\(open_server_SRCS(.*?)\)", cmake, re.S)
if not match:
    raise SystemExit("cannot find upstream open_server_SRCS source list")
sources = match.group(1).split()
if not sources or any(not name.endswith(".c") or not (server / name).is_file() for name in sources):
    raise SystemExit("unexpected upstream open_server source list")
common = ["gcc", "-std=gnu11", "-O1", "-g", f"-I{server / 'inc'}", f"-I{output / 'include'}"]
subprocess.run(common + ["-rdynamic"] + [str(server / name) for name in sources]
               + [str(prefix / "lib/libiec61850.a"), "-pthread", "-ldl", "-lm", "-o", str(output / "open_server")], check=True)
plugins = output / "plugin"
plugins.mkdir(exist_ok=True)
subprocess.run(common + ["-fPIC", "-shared", str(server / "plugin_src/cbr_simulation/cbr_simulation.c"),
                        "-pthread", "-o", str(plugins / "libcbr_simulation.so")], check=True)
