#!/usr/bin/env python3
"""CPU replay for the exact locally preserved TGL driver, without GPU execution."""
from pathlib import Path
import hashlib,subprocess,sys,tempfile
r=Path(__file__).resolve().parents[1]
assert len(sys.argv)==2
donor=Path(sys.argv[1]).resolve()
assert hashlib.sha256(donor.read_bytes()).hexdigest()=='bf35af031a52bfd7417b56147f6d322a8657f46b42385cfa422a364d97865c99'
with tempfile.TemporaryDirectory(prefix='adls-bcs-wait-') as tmp:
    out=Path(tmp)/'replay'
    subprocess.run(['clang++','-arch','x86_64','-std=c++17','-O1','-g',
                    '-fsanitize=address,undefined','-fno-sanitize=function','-fno-omit-frame-pointer',
                    '-I'+str(r/'WhateverXe'),str(r/'tests/adls_bcs_wait_native_fixture.cpp'),'-o',str(out)],check=True)
    subprocess.run([str(out),str(donor)],check=True)
