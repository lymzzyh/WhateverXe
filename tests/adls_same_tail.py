#!/usr/bin/env python3
"""Replay the production admission block and the native one-shot descriptor path."""
from pathlib import Path
import hashlib, subprocess, sys, tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'WhateverXe/kern_xe.cpp').read_text()
a = source.index('const uint8_t sameTailFlag[]')
b = source.index('// The public TGL register definition', a)
block = source[a:b]
code = r'''
#include "kern_adls_rcs_flush.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <fstream>
#include <sys/mman.h>
using mach_vm_address_t=uintptr_t;
static bool host=true,optIn=true;
static bool checkKernelArgument(const char *s) {
 if(!strcmp(s,"-disablegfxfirmware"))return host;
 assert(!strcmp(s,"-wex-adls-same-tail"));return optIn;
}
struct Receipt {bool value;bool isTrue(){return value;}};
struct IORegistryEntry {
 std::map<std::string,unsigned> props;
 static IORegistryEntry *getRegistryRoot(){static IORegistryEntry r;return &r;}
 void setProperty(const char *s,unsigned v,unsigned=0){props[s]=v;}
};
struct Patcher {
 bool wrong=false;
 template<class T>T solveSymbol(unsigned,const char *s,uintptr_t base,size_t) {
  assert(!strcmp(s,"__ZN17IGHardwareContext14updateRingTailEj"));return base+0x7c5b6+wrong;
 }
 void clearError(){}
};
bool install(std::vector<unsigned char> &image,XELP::Profile xeProfile,bool tahoeTrialScope,
 bool hostOK,bool wrongSymbol,Receipt *localABI,bool adlsContextCacheRequested,size_t size) {
 const auto address=reinterpret_cast<uintptr_t>(image.data());Patcher patcher{wrongSymbol};
 unsigned index=0;const unsigned tglTahoeDisabledTrials=31;
 bool tglSameTailEnabled=false,tglSameTailRestoreEnabled=false;
 const char *version=tahoeTrialScope?"Darwin Kernel Version 25.6.0: test; root:xnu/RELEASE_X86_64":
  "Darwin Kernel Version 24.6.0: test; root:xnu/RELEASE_X86_64";
 ACTUAL_BLOCK
 return tglSameTailRestoreEnabled;
}
int main(int argc,char **argv) {
 const unsigned char fixture[]={0x41,0x80,0xbd,0xc9,0,0,0,0,0x74,0x10,0x41,0xc6,0x85,0xc9,0,0,0,0,0x89,0xc8,0x83,0xc8,4,0x89,0x45,0xc0};
 std::vector<unsigned char> image(0x7c600,0xa5);
 memcpy(image.data()+0x3a7b6,fixture,sizeof(fixture));unsigned cases=0;
 for(unsigned device=0;device<4;++device)for(unsigned bits=0;bits<128;++bits) {
  auto p=XELP::identify(device==1?0x9a498086:0x46808086,device==2?0xb:0xc,
   device==3?0x9a498086:device==1?0x9a498086:0x46808086);
  host=bits&1;optIn=bits&2;Receipt receipt{bool(bits&4)};
  const bool os=bits&8,native=bits&16,wrong=bits&32,cache=bits&64;
  const bool expected=device==0 && (bits&31)==31 && !wrong;
  assert(install(image,p,os,native,wrong,&receipt,cache,image.size())==expected);
  const auto &props=IORegistryEntry::getRegistryRoot()->props;
  assert(props.at("TGLSameTailRestoreReady")==expected);
  assert(props.at("TGLTahoeDisabledTrials")==unsigned(31 & ~(cache?2:0) & ~(expected?4:0)));
  ++cases;
 }
 auto p=XELP::identify(0x46808086,0xc);host=optIn=true;Receipt receipt{true};
 assert(!install(image,p,true,true,false,nullptr,true,image.size()));++cases;
 assert(!install(image,p,true,true,false,&receipt,true,0x7c5d7));++cases;
 for(unsigned i=0;i<sizeof(fixture);++i) {
  image[0x3a7b6+i]^=1;assert(!install(image,p,true,true,false,&receipt,true,image.size()));
  image[0x3a7b6+i]^=1;++cases;
 }
 printf("PASS: %u production admission, layout and receipt cases\n",cases);
 if(argc==2) {
  std::ifstream f(argv[1],std::ios::binary);std::vector<unsigned char> native((std::istreambuf_iterator<char>(f)),{});
  assert(native.size()>0x3a7d0 && !memcmp(native.data()+0x3a7b6,fixture,sizeof(fixture)));
  auto mem=(unsigned char *)mmap(nullptr,4096,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_ANON|MAP_PRIVATE,-1,0);
  assert(mem!=MAP_FAILED);
  // SysV wrapper around the exact native descriptor load, flag clear and OR.
  const unsigned char prefix[]={0x55,0x48,0x89,0xe5,0x41,0x55,0x48,0x83,0xec,0x48,0x49,0x89,0xfd};
  const unsigned char suffix[]={0x48,0x8b,0x45,0xc0,0x48,0x83,0xc4,0x48,0x41,0x5d,0x5d,0xc3};
  memcpy(mem,prefix,sizeof(prefix));memcpy(mem+sizeof(prefix),native.data()+0x3a7ab,0x25);
  memcpy(mem+sizeof(prefix)+0x25,suffix,sizeof(suffix));
  for(uint64_t desc:{0x10040334319ULL,0x9804166a319ULL,0x1234abcdfffe0319ULL})for(unsigned flag:{0,1}) {
   unsigned char ctx[256]{};memcpy(ctx+0x89,&desc,8);ctx[0xc9]=flag;
   auto got=((uint64_t(*)(void *))mem)(ctx);assert(got==(desc|(flag?4:0)) && ctx[0xc9]==0);
   uint64_t saved;memcpy(&saved,ctx+0x89,8);assert(saved==desc);
   assert(((uint64_t(*)(void *))mem)(ctx)==desc);
  }
  munmap(mem,4096);puts("PASS: exact native one-shot sets only FORCE_RESTORE, clears flag and preserves stored identity");
 }
}
'''.replace('ACTUAL_BLOCK', block)
native = len(sys.argv) == 2
if native:
    assert hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest() == 'bf35af031a52bfd7417b56147f6d322a8657f46b42385cfa422a364d97865c99'
with tempfile.TemporaryDirectory(prefix='adls-same-tail-') as tmp:
    p = Path(tmp)
    (p/'test.cpp').write_text(code)
    subprocess.run(['clang++','-std=c++17','-O1','-g','-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer','-I'+str(root/'WhateverXe'),str(p/'test.cpp'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')] + ([sys.argv[1]] if native else []),check=True)
