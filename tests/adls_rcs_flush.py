#!/usr/bin/env python3
"""Replay production flush installation; optionally run exact native emitters on CPU."""
from pathlib import Path
import hashlib, subprocess, sys, tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'WhateverXe/kern_xe.cpp').read_text()
a = source.index('const uint32_t flushSites[]')
b = source.index('// The outer RCS completion emitter', a)
block = source[a:b]
assert '&& cpsOK && flushOK && tlbPreparserOK' in source
native = len(sys.argv) == 2
if native:
    data = Path(sys.argv[1]).read_bytes()
    assert hashlib.sha256(data).hexdigest() in {
        'bf35af031a52bfd7417b56147f6d322a8657f46b42385cfa422a364d97865c99',
        '890735a93a19d3ddda24ff31bda3075dbd145fb7b26c11769f33c4564a8027ac',
        'bd1a21f5e622aadabdab6441f6b5c38ed73fa3053c783fdf0fb7e4b309f273d0',
    }, 'unqualified accelerator; do not broaden without code comparison'
code = r'''
#include "kern_adls_rcs_flush.hpp"
#include <sys/mman.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
#include <map>
#include <string>
using mach_vm_address_t=uintptr_t;
#define arrsize(a) (sizeof(a)/sizeof((a)[0]))
struct Object {virtual ~Object()=default;};
struct OSBoolean:Object {bool value=true;bool isTrue(){return value;}};
#define OSDynamicCast(t,p) dynamic_cast<t *>(p)
static OSBoolean receipt;static Object wrong;static Object *property=&receipt;
static bool host=true,optIn=true;
static bool checkKernelArgument(const char *s) {
 if(!strcmp(s,"-disablegfxfirmware"))return host;
 assert(!strcmp(s,"-wex-adls-rcs-flush"));return optIn;
}
struct IORegistryEntry {
 std::map<std::string,bool> props;
 static IORegistryEntry *getRegistryRoot(){static IORegistryEntry r;return &r;}
 Object *getProperty(const char *s){assert(!strcmp(s,"WEXLocalTahoeABIHookReady"));return property;}
 void setProperty(const char *s,bool v){props[s]=v;}
};
struct KernelPatcher {
 enum class Error {NoError,Failed};
 struct LookupPatch {void *kext;const uint8_t *find,*replace;size_t size,count;};
 Error error=Error::NoError;
 unsigned wrongSymbol=0,symbols=0,failAt=0,failure=0,calls=0;
 template<class T> T solveSymbol(unsigned,const char *name,uintptr_t address,size_t) {
  ++symbols;unsigned offset=0;
  if(strstr(name,"commitStampCommand"))offset=0x84DC8;
  else if(strstr(name,"writeFlush"))offset=0x853A6;
  else {assert(strstr(name,"IntelMTLRenderFunctions"));offset=0x4F1F0;}
  return address+offset+(symbols==wrongSymbol);
 }
 void clearError(){error=Error::NoError;} Error getError(){return error;}
 void applyLookupPatch(const LookupPatch *p,uint8_t *at,size_t available) {
  ++calls;assert(p->size==10 && available==11 && p->count==1);
  assert(!memcmp(at,p->find,p->size));
  if(calls==failAt && failure==1){error=Error::Failed;return;}
  if(calls==failAt && failure==2)return;
  memcpy(at,p->replace,p->size);
  if(calls==failAt && failure==3)error=Error::Failed;
  if(calls==failAt && failure==4)at[9]^=1;
 }
};
static bool install(KernelPatcher &patcher,uintptr_t address,size_t size,
 XELP::Profile xeProfile=XELP::identify(0x46808086,0x0C),
 const char *version="Darwin Kernel Version 25.6.0: test; root:xnu/RELEASE_X86_64") {
 const unsigned index=0;void *currentGraphics=nullptr;
 ACTUAL_BLOCK
 return flushOK;
}
static void installerTests() {
 // Independent native immediate fixture. No Apple executable is needed.
 const unsigned sites[]={0x84e5d,0x85406,0x51a20,0x51a3a};
 const uint8_t native[][10]={
  {0x48,0xb8,4,0,0,0x7a,0x21,0x50,0x10,0x40},
  {0x48,0xb9,4,0,0,0x7a,0x21,0x50,0x10,0x40},
  {0x48,0xbf,4,0,0,0x7a,0x21,0x52,0x10,0x40},
  {0x48,0xbb,4,0,0,0x7a,0x98,0x44,0x10,0}};
 std::vector<uint8_t> original(0x85420,0xa5);
 for(unsigned i=0;i<4;++i)memcpy(original.data()+sites[i],native[i],10);
 unsigned cases=0;
 for(unsigned r=0;r<4;++r)for(unsigned bits=0;bits<4;++bits)
 for(unsigned device=0;device<4;++device)for(unsigned os=0;os<2;++os) {
  auto image=original;KernelPatcher p;
  receipt.value=r==3;property=r==0?nullptr:r==1?&wrong:&receipt;
  host=bits&1;optIn=bits&2;
  auto profile=XELP::identify(device==1?0x9a498086:0x46808086,
    device==2?0xb:0xc,device==3?0x9a498086:device==1?0x9a498086:0x46808086);
  const bool enabled=r==3 && bits==3 && device==0 && os==0;
  assert(install(p,(uintptr_t)image.data(),image.size(),profile,
   os?"Darwin Kernel Version 24.6.0: test; root:xnu/RELEASE_X86_64":
      "Darwin Kernel Version 25.6.0: test; root:xnu/RELEASE_X86_64"));
  assert(p.calls==4);
  auto &props=IORegistryEntry::getRegistryRoot()->props;
  assert(props["TGLADLSRCSFlushRequested"]==enabled && props["TGLADLSRCSFlushReady"]==enabled);
  for(unsigned i=0;i<2;++i) {
   uint32_t dw0,dw1;memcpy(&dw0,image.data()+sites[i]+2,4);memcpy(&dw1,image.data()+sites[i]+6,4);
   assert(dw0==0x7a000204);
   // Write fence: HDC, depth stall, CS stall, post-sync and (opt-in) tile.
   assert(dw1== (enabled?0x50107021U:0x40107021U));
  }
  assert(image[0x51a29]==0x50 && image[0x51a43]==0x20);++cases;
 }
 receipt.value=true;property=&receipt;host=optIn=true;
 for(auto site:sites)for(unsigned n=0;n<10;++n) {
  auto image=original;image[site+n]^=1;auto before=image;KernelPatcher p;
  assert(!install(p,(uintptr_t)image.data(),image.size()));
  assert(!p.calls && image==before);++cases;
 }
 for(unsigned n=1;n<=3;++n) {
  auto image=original;KernelPatcher p;p.wrongSymbol=n;
  assert(!install(p,(uintptr_t)image.data(),image.size()) && !p.calls);++cases;
 }
 for(size_t size:{size_t(0),size_t(0x51a44),size_t(0x85410)}) {
  auto image=original;KernelPatcher p;
  assert(!install(p,(uintptr_t)image.data(),size) && !p.calls);++cases;
 }
 for(unsigned at=1;at<=4;++at)for(unsigned failure=1;failure<=4;++failure) {
  auto image=original;KernelPatcher p;p.failAt=at;p.failure=failure;
  assert(!install(p,(uintptr_t)image.data(),image.size()));
  assert(!IORegistryEntry::getRegistryRoot()->props["TGLADLSRCSFlushReady"]);++cases;
 }
 printf("PASS: %u production scope, donor-guard and write-failure cases\n",cases);
}
static uint64_t scratch,guard=0xfeed12345678ULL;
static unsigned mode;
static std::vector<uint32_t> output,lengths;
extern "C" uint32_t gtt(void*){return mode;}
extern "C" uint64_t address(void*){return scratch;}
extern "C" void writebuf(void*,uint32_t *p,unsigned n){assert(n<64);lengths.push_back(n);output.insert(output.end(),p,p+n);}
static void jump(uint8_t *p,void *f){p[0]=0x48;p[1]=0xb8;memcpy(p+2,&f,8);p[10]=0xff;p[11]=0xe0;}
template<class T>void put(uint8_t *p,unsigned off,T v){memcpy(p+off,&v,sizeof(v));}
static void nativeTests(const char *path) {
 std::ifstream f(path,std::ios::binary);
 std::vector<char> d((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());
 auto mem=(uint8_t*)mmap(nullptr,d.size(),PROT_READ|PROT_WRITE|PROT_EXEC,MAP_ANON|MAP_PRIVATE,-1,0);
 assert(mem!=MAP_FAILED);
 uint8_t self[0x100]={},owner[0x1200]={},context[0x100]={},task[0x100]={};
 put(self,0x10,owner);put(self,0x20,context);put(context,0x58,task);
 put(self,0x28,uint64_t(0x123456780040ULL));put(self,0x38,uint32_t(17));
 const uint64_t addresses[]={0x40000010ULL,0x123400001010ULL,0x123456789abfULL,0xfffffffffffcULL};
 unsigned cases=0,changed=0,unchanged=0;
 for(auto s:addresses)for(mode=0;mode<2;++mode)for(unsigned pathMode=0;pathMode<2;++pathMode)
 for(unsigned notify=0;notify<2;++notify)for(unsigned extra=0;extra<2;++extra)for(unsigned which=0;which<2;++which) {
  scratch=s;owner[0x1190]=pathMode?0x40:0;put(owner,0xf4a,uint32_t(extra<<20));
  std::vector<uint32_t> a,al,b,bl;
  for(unsigned variant=0;variant<2;++variant) {
   memcpy(mem,d.data(),d.size());KernelPatcher p;optIn=variant;
   assert(install(p,(uintptr_t)mem,d.size()));
   jump(mem+0x42364,(void*)gtt);jump(mem+0x8224,(void*)address);jump(mem+0x41e7a,(void*)writebuf);put(mem,0xc8200,&guard);
   output.clear();lengths.clear();
   if(which)((void(*)(void*))(mem+0x853a6))(self);
   else ((void(*)(void*,uint32_t,bool))(mem+0x84dc8))(self,0x1234abcd,notify);
   if(!variant){a=output;al=lengths;}else{b=output;bl=lengths;}
  }
  assert(a.size()==b.size() && al==bl && al[0]==6);
  assert(b[0]==0x7a000204 && b[1]==(a[1]|(1U<<28)));
  assert(b[2]==(uint32_t(s)&~3U) && b[3]==uint32_t(s>>32));
  for(unsigned i=0;i<a.size();++i)if(i!=1)assert(a[i]==b[i]);
  if(which)assert(b.size()==12+extra*40);
  else {assert(b[8]==uint32_t(0x123456780040ULL+17*64));assert(b[9]==0x1234);assert(b[10]==0x1234abcd);assert(b.size()==(pathMode&&notify?22:12));}
  if(a[1]==b[1])++unchanged;else ++changed;++cases;
 }
 printf("PASS: %u paired native emitter cases (%u tile additions, %u already set); addresses/stamps/notification/order preserved\n",cases,changed,unchanged);
 munmap(mem,d.size());
}
int main(int argc,char **argv){installerTests();if(argc==2)nativeTests(argv[1]);}
'''.replace('ACTUAL_BLOCK', block)
with tempfile.TemporaryDirectory(prefix='adls-rcs-flush-') as tmp:
    p = Path(tmp)
    (p / 'test.cpp').write_text(code)
    subprocess.run(['clang++', '-std=c++17', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', '-I'+str(root/'WhateverXe'),
                    str(p/'test.cpp'), '-o', str(p/'test')], check=True)
    subprocess.run([str(p/'test')] + ([sys.argv[1]] if native else []), check=True)
