#!/usr/bin/env python3
"""Replay the production installation block with patch failures and bad donors."""
from pathlib import Path
import subprocess,tempfile
r=Path(__file__).resolve().parents[1]
s=(r/'WhateverXe/kern_xe.cpp').read_text()
a=s.index('            bool bcsNativeWaitOK=!bcsNativeWaitRequested;')
b=s.index('            IORegistryEntry::getRegistryRoot()->setProperty("TGLADLSBCSNativeWaitRequested"',a)
assert '&& semaphoreTLBOK && bcsNativeWaitOK && hangOK' in s
code=r'''
#include "kern_adls_bcs_wait.hpp"
#include <cassert>
#include <vector>
#include <cstdio>
using mach_vm_address_t=uintptr_t;
#define arrsize(a) (sizeof(a)/sizeof((a)[0]))
struct KernelPatcher {
 enum class Error {NoError,Failed};
 Error error=Error::NoError;bool symbolOK=true;
 unsigned failAt=0,failure=0,calls=0;uint8_t *body=nullptr;
 template<typename T> T solveSymbol(unsigned,const char*,uintptr_t address,size_t) {
  return address+ADLSBCSWait::Offset+(symbolOK?0:1);
 }
 void clearError(){error=Error::NoError;} Error getError(){return error;}
 void routeBlock(uintptr_t at,const uint8_t *v,size_t n) {
  ++calls;assert(at==(uintptr_t)(body+ADLSBCSWait::Sites[calls-1]));
  if(calls==failAt && failure==1){error=Error::Failed;return;}
  if(calls==failAt && failure==2)return; // silent failed write
  memcpy((void*)at,v,n);
  if(calls==failAt && failure==3)error=Error::Failed;
  if(calls==failAt && failure==4)body[sizeof(ADLSBCSWait::Body)-1]^=1;
 }
};
static bool install(KernelPatcher &patcher,uintptr_t address,size_t size,
 bool bcsNativeWaitRequested=true,bool hostOK=true,bool semaphoreTLBOK=true) {
 const unsigned index=0;
 ACTUAL_BLOCK
 return bcsNativeWaitOK;
}
int main(){
 std::vector<uint8_t> image(ADLSBCSWait::Offset+sizeof(ADLSBCSWait::Body));
 auto body=image.data()+ADLSBCSWait::Offset;
 auto reset=[&](){memcpy(body,ADLSBCSWait::Body,sizeof(ADLSBCSWait::Body));};
 auto address=(uintptr_t)image.data();unsigned cases=0;
 for(unsigned i=0;i<sizeof(ADLSBCSWait::Body);++i) {
  reset();body[i]^=1;auto before=image;KernelPatcher p;p.body=body;
  assert(!install(p,address,image.size()));assert(!p.calls && image==before);++cases;
 }
 for(unsigned bits=0;bits<8;++bits) {
  reset();KernelPatcher p;p.body=body;
  bool ok=install(p,address,image.size(),bits&1,bits&2,bits&4);
  assert(ok==(!(bits&1)||bits==7));assert(p.calls==(bits==7?2:0));++cases;
 }
 for(size_t n:{size_t(0),size_t(ADLSBCSWait::Offset),image.size()-1}) {
  reset();KernelPatcher p;p.body=body;assert(!install(p,address,n));assert(!p.calls);++cases;
 }
 reset();KernelPatcher wrong;wrong.body=body;wrong.symbolOK=false;
 assert(!install(wrong,address,image.size()) && !wrong.calls);++cases;
 for(unsigned at=1;at<=2;++at)for(unsigned failure=1;failure<=4;++failure) {
  reset();KernelPatcher p;p.body=body;p.failAt=at;p.failure=failure;
  assert(!install(p,address,image.size()));
  if(at==2)assert(!memcmp(body+ADLSBCSWait::Sites[0],ADLSBCSWait::Replace,sizeof(ADLSBCSWait::Replace)));
  ++cases;
 }
 reset();KernelPatcher p;p.body=body;assert(install(p,address,image.size()));
 assert(p.calls==2 && ADLSBCSWait::matches(body,sizeof(ADLSBCSWait::Body),true));++cases;
 printf("PASS: %u production installer cases; mismatches and patch failures prevent admission.\n",cases);
}
'''.replace('ACTUAL_BLOCK',s[a:b])
with tempfile.TemporaryDirectory(prefix='adls-bcs-install-') as tmp:
    p=Path(tmp);(p/'test.cpp').write_text(code)
    subprocess.run(['clang++','-std=c++17','-O1','-g','-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer','-I'+str(r/'WhateverXe'),str(p/'test.cpp'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True)
