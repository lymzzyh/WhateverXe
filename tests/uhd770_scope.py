#!/usr/bin/env python3
"""Replay production opt-in bindings, including a missing/failed ABI receipt."""
from pathlib import Path
import subprocess, tempfile

root=Path(__file__).resolve().parents[1]
source=(root/'WhateverXe/kern_xe.cpp').read_text()
start=source.index('const auto localABI=OSDynamicCast(OSBoolean,')
context=source[start:source.index('const bool contextCacheRequested=',start)]
start=source.index('const bool bcsNativeWaitRequested=')
bcs=source[start:source.index('bool bcsNativeWaitOK=',start)]
code=r'''
#include "kern_tgl_context_cache.hpp"
#include "kern_adls_bcs_wait.hpp"
#include <cassert>
#include <cstdio>
struct Object {virtual ~Object()=default;};
struct OSBoolean:Object {bool value;bool isTrue(){return value;}};
#define OSDynamicCast(t,p) dynamic_cast<t *>(p)
static Object wrong;static OSBoolean receipt;static Object *property;
static bool host,contextOpt,bcsOpt;
static bool checkKernelArgument(const char *name) {
 if(!strcmp(name,"-disablegfxfirmware"))return host;
 if(!strcmp(name,"-wex-adls-context-cache"))return contextOpt;
 assert(!strcmp(name,"-wex-adls-bcs-native-wait"));return bcsOpt;
}
struct IORegistryEntry {
 static IORegistryEntry *getRegistryRoot(){static IORegistryEntry root;return &root;}
 Object *getProperty(const char *name){assert(!strcmp(name,"WEXLocalTahoeABIHookReady"));return property;}
};
static void production(XELP::Profile xeProfile,const char *version,bool &context,bool &bcs) {
 CONTEXT
 BCS
 context=adlsContextCacheRequested;bcs=bcsNativeWaitRequested;
}
int main() {
 unsigned cases=0;
 for(unsigned r=0;r<4;++r)for(unsigned bits=0;bits<8;++bits)for(unsigned device=0;device<4;++device) {
  receipt.value=r==3;property=r==0?nullptr:r==1?&wrong:&receipt;
  host=bits&1;contextOpt=bits&2;bcsOpt=bits&4;
  auto profile=XELP::identify(device==1?0x9A498086:0x46808086,device==2?0x0b:0x0c,device==3 || device==1?0x9A498086:0x46808086);
  bool context=false,bcs=false;
  production(profile,"Darwin Kernel Version 25.6.0: test; root:xnu/RELEASE_X86_64",context,bcs);
  const bool admitted=r==3 && host && device==0;
  assert(context==(admitted && contextOpt));assert(bcs==(admitted && bcsOpt));++cases;
 }
 printf("PASS: %u production opt-in/ABI receipt bindings\n",cases);
}
'''.replace('CONTEXT',context).replace('BCS',bcs)
with tempfile.TemporaryDirectory(prefix='uhd770-scope-') as tmp:
    p=Path(tmp);(p/'test.cpp').write_text(code)
    subprocess.run(['clang++','-std=c++17','-O1','-fsanitize=address,undefined',
                    '-I'+str(root/'WhateverXe'),str(p/'test.cpp'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True)
