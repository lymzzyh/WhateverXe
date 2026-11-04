#!/usr/bin/env python3
"""Replay release admission and capture installation without widening GPU admission."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[1]
s=(root/'WhateverXe/kern_xe.cpp').read_text()
a=s.index('tglReleaseMode=ADLSRCSFlush::requested');b=s.index('// Preserve native submission;',a)
policy=s[a:b]
a=s.index('const char *hangDump=');b=s.index('// r123: the TGL caller',a)
capture=s[a:b]
a=s.index('const bool smpRequested=');b=s.index('IORegistryEntry::getRegistryRoot()->setProperty("TGLResourceDiagnosticsRemoved"',a)
smp=s[a:b]
code=r'''
#include "kern_adls_rcs_flush.hpp"
#include <cassert>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <cstdio>
using mach_vm_address_t=uintptr_t;
#define arrsize(x) (sizeof(x)/sizeof(x[0]))
static bool tglReleaseMode,host=true,optIn=true,tglHangPreStopReady;
static bool tglConcurrencyEnabled;
static void tglConcurrencySerialize(){}
struct OSSerializer {static OSSerializer *forTarget(void *,void(*)()){static OSSerializer x;return &x;}void release(){}};
static bool tglSameTailEnabled=true;static uintptr_t tglPPGTTClass;
static int orgTGLHangRingDump;
static void wrapTGLHangRingDump(){} static void tglHangPreStopBridge(){}
struct {bool nofault=true,enabled=true;} tglVM;
struct Receipt {bool value;bool isTrue(){return value;}};
static bool checkKernelArgument(const char *name){
 if(!strcmp(name,"-disablegfxfirmware"))return host;
 assert(!strcmp(name,"-wex-adls-release") || !strcmp(name,"-wex-adls-smp-trace"));return optIn;
}
struct IORegistryEntry {
 std::map<std::string,bool> props;
 static IORegistryEntry *getRegistryRoot(){static IORegistryEntry r;return &r;}
 void setProperty(const char *name,bool value){props[name]=value;}
 bool setProperty(const char *name,OSSerializer *value){props[name]=value;return value;}
};
struct KernelPatcher {
 enum class Error {NoError,Failed};
 struct RouteRequest {const char *name;void(*hook)();int original;};
 unsigned calls=0;bool wrongSymbol=false,fail=false;Error error=Error::NoError;
 template<class T>T solveSymbol(unsigned,const char *name,uintptr_t base,size_t){
  unsigned offset=strstr(name,"dumpRing")?0x4657c:strstr(name,"PageTable")?0xcc220:0x56978;
  return base+offset+(wrongSymbol && offset==0x4657c);
 }
 bool routeMultiple(unsigned,RouteRequest *,unsigned,uintptr_t,size_t){++calls;return !fail;}
 void routeBlock(uintptr_t at,const void *p,size_t n){++calls;if(fail)error=Error::Failed;else memcpy((void*)at,p,n);}
 void clearError(){error=Error::NoError;}Error getError(){return error;}
};
static bool policy(XELP::Profile xeProfile,const char *version,Receipt *localABI){
 POLICY
 return tglReleaseMode;
}
static bool install(std::vector<unsigned char>&image,KernelPatcher&patcher,size_t size){
 uintptr_t address=(uintptr_t)image.data();unsigned index=0;
 const char *version="Darwin Kernel Version 25.6.0: test; root:xnu/RELEASE_X86_64";
 CAPTURE
 return hangOK;
}
static void installSMP(bool tglAcceleratorReady,Receipt *localABI) {
 auto xeProfile=XELP::identify(0x46808086,0xc);
 const char *version="Darwin Kernel Version 25.6.0: test; root:xnu/RELEASE_X86_64";
 SMP
}
int main(){
 unsigned cases=0;Receipt receipt{true};
 for(unsigned device=0;device<4;++device)for(unsigned bits=0;bits<16;++bits){
  auto profile=XELP::identify(device==1?0x9a498086:0x46808086,device==2?0xb:0xc,device==3?0x9a498086:device==1?0x9a498086:0x46808086);
  host=bits&1;optIn=bits&2;receipt.value=bits&4;
  const char *v=bits&8?"Darwin Kernel Version 25.6.0: test; root:xnu/RELEASE_X86_64":"Darwin Kernel Version 24.6.0: test; root:xnu/RELEASE_X86_64";
  assert(policy(profile,v,&receipt)==(device==0 && bits==15));++cases;
 }
 assert(!policy(XELP::identify(0x46808086,0xc),"Darwin Kernel Version 25.6.0: test; root:xnu/RELEASE_X86_64",nullptr));++cases;
 std::vector<unsigned char> original(0xcc240,0xa5);
 const unsigned char head[]={0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x50};
 const unsigned char before[]={0x41,0x89,0xf6,0x49,0x89,0xff,0x48,0x8b,0x7f,0x10,0xbe,1,0,0,0,0xba,7,0,0,0,0xe8,0x8e,0x22,0xfd,0xff};
 const unsigned char stop[]={0x42,0xc7,0x04,0x20,1,0,1,0};
 memcpy(original.data()+0x4657c,head,sizeof(head));memcpy(original.data()+0x56983,before,sizeof(before));memcpy(original.data()+0x569be,stop,sizeof(stop));
 for(bool release:{false,true})for(unsigned failure=0;failure<5;++failure){
  auto image=original;KernelPatcher p;tglReleaseMode=release;tglVM.nofault=failure!=1;
  if(failure==2)image[0x4657c]^=1;
  p.wrongSymbol=failure==3;p.fail=failure==4;
  auto saved=image;const bool admission=install(image,p,image.size());
  assert(admission==(failure==0 || (release && failure==4)));
  if(release){assert(p.calls==0 && image==saved && !tglHangPreStopReady);
   assert(!IORegistryEntry::getRegistryRoot()->props.at("TGLHangBatchCaptureReady"));
   assert(!IORegistryEntry::getRegistryRoot()->props.at("TGLSubmitHistoryReady"));
  }else if(failure==0){assert(p.calls>=1);assert(IORegistryEntry::getRegistryRoot()->props.at("TGLHangBatchCaptureReady"));}
  ++cases;
 }
 tglVM.nofault=true;
 for(bool release:{false,true})for(size_t size:{0UL,0x46780UL}){
  auto image=original;KernelPatcher p;tglReleaseMode=release;
  assert(!install(image,p,size) && !p.calls);++cases;
 }
 host=optIn=receipt.value=true;
 for(unsigned bits=0;bits<8;++bits){
  tglReleaseMode=bits&1;tglHangPreStopReady=bits&2;
  tglConcurrencyEnabled=true;
  installSMP(bits&4,&receipt);
  assert(tglConcurrencyEnabled==(bits==6));++cases;
 }
 printf("PASS: %u release scope, unchanged native bytes, capture routing and admission rejection cases\n",cases);
}
'''.replace('POLICY',policy).replace('CAPTURE',capture).replace(' SMP\n',smp+'\n')
with tempfile.TemporaryDirectory(prefix='adls-release-') as tmp:
 p=Path(tmp);(p/'test.cpp').write_text(code)
 subprocess.run(['clang++','-std=c++17','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I'+str(root/'WhateverXe'),str(p/'test.cpp'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
