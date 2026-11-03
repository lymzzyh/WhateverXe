#!/usr/bin/env python3
"""Replay the production validator with synthetic pages or hash-qualified private inputs."""
from pathlib import Path
import subprocess, tempfile, json, argparse, hashlib, re

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--source-dir', type=Path, default=root/'WhateverXe')
parser.add_argument('--output', type=Path, default=root/'build/tests/uhd770-callback.json')
parser.add_argument('--reference-pages', type=Path, help='optional private metal.bin, video.bin, gva.bin; exactly 4096 bytes each')
options = parser.parse_args()
src = (options.source_dir/'kern_host.cpp').read_text()
production = src[src.index('static mach_vm_address_t localTahoeOriginalPage;'):src.index('XeHost *XeHost::callbackHost;')]
assert all(x not in src for x in ['FileIO::', 'Crypto::', 'onProcLoad'])
fixture = r'''
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cassert>
#include <cstdio>
#include <vector>
#include <type_traits>
#include "reference_pages.hpp"
#include "kern_local_tahoe_abi.hpp"
#include "kern_xelp_platform.hpp"
using mach_vm_address_t=uintptr_t;
struct vnode{};using vnode_t=vnode *;
using memory_object_t=void *;using memory_object_offset_t=uint64_t;using boolean_t=int;
// Independent contract from XNU ubc_subr.c and the actual 25G332 kernel:
// R8=validated, R9=tainted, [RBP+16]=nx; outputs are 0xf/0/0.
using ActualKernelPageValidator=void (*)(vnode_t,memory_object_t,memory_object_offset_t,const void *,int *,int *,int *);
static constexpr size_t PAGE_SIZE=4096;
static constexpr int KERN_SUCCESS=0;
enum KernelVersion{Tahoe=25,Other=24};
static KernelVersion currentKernel=Tahoe;
static KernelVersion getKernelVersion(){return currentKernel;}
static bool requested=true;
static bool checkKernelArgument(const char *){return requested;}
static const char *qualified="Darwin Kernel Version 25.6.0: Mon Oct 12 00:33:09 PDT 2026; root:xnu-12377.161.15.701.48~2/RELEASE_X86_64";
static const char *version=qualified;
struct IOPCIDevice{uint32_t id=0x46808086;uint8_t revision=0x0c;bool overrideID=false;uint32_t configRead32(int){return id;}uint8_t configRead8(int){return revision;}void *getProperty(const char *){return overrideID?this:nullptr;}};
struct OSSerialize{};
struct OSData{static OSData *withBytes(const void *,size_t){static OSData d;return &d;}bool serialize(OSSerialize *){return true;}void release(){}};
struct OSSerializer{static OSSerializer *forTarget(void *,bool(*)(void *,void *,OSSerialize *)){static OSSerializer d;return &d;}void release(){}};
struct IORegistryEntry{
 bool armed=false;
 static IORegistryEntry *getRegistryRoot(){static IORegistryEntry r;return &r;}
 void setProperty(const char *,bool q){armed=q;}
 void setProperty(const char *,OSSerializer *){}
};
static bool writeAllowed=true,writing=false,race=false;
static void *racePage;
namespace MachInfo{int setKernelWriting(bool b,int){if(b && !writeAllowed)return 1;writing=b;if(b && race)LocalTahoeABI::apply(racePage);return 0;}}
static bool routeAllowed=true;
static int originalCalls=0;
static int statusValidated=15,statusTainted=0,statusNX=0;
static vnode expectedNode;static int expectedPager;
static const void *expectedData;
static uint64_t expectedOffset;
static int *expectedValidated,*expectedTainted,*expectedNX;
static void original(vnode_t node,memory_object_t pager,memory_object_offset_t offset,const void *data,int *validated,int *tainted,int *nx){
 ++originalCalls;
 assert(node==&expectedNode && pager==&expectedPager && offset==expectedOffset && data==expectedData);
 assert(validated==expectedValidated && tainted==expectedTainted && nx==expectedNX);
 if(validated)*validated=statusValidated;if(tainted)*tainted=statusTainted;if(nx)*nx=statusNX;
}
#define FunctionCast(fn,addr) reinterpret_cast<decltype(&fn)>(addr)
struct KernelPatcher {
 static constexpr int KernelID=0,kernelWriteLock=1;
 struct RouteRequest{template<class F>RouteRequest(const char *,F,mach_vm_address_t &addr){addr=(uintptr_t)&original;}};
 bool routeMultipleLong(int,RouteRequest *,int){return routeAllowed;}
 void clearError(){}
};
// PRODUCTION
static_assert(std::is_same<decltype(&localTahoeValidatePage),ActualKernelPageValidator>::value,"actual kernel has seven arguments and void return");
int main(){
 std::vector<uint8_t> page(localTahoeReferencePage,localTahoeReferencePage+4096);
 unsigned cases=0;
 assert(LocalTahoeABI::matches(page.data(),4096,0,true,false));++cases;
 for(size_t i=0;i<4096;++i){page[i]^=1;assert(!LocalTahoeABI::matches(page.data(),4096,0,true,false));page[i]^=1;++cases;}
 for(auto size:{size_t(0),size_t(4095),size_t(4097)}){assert(!LocalTahoeABI::matches(page.data(),size,0,true,false));++cases;}
 assert(!LocalTahoeABI::matches(nullptr,4096,0,true,false));++cases;
 assert(!LocalTahoeABI::matches(page.data(),4096,4096,true,false));++cases;
 assert(!LocalTahoeABI::matches(page.data(),4096,0,false,false));++cases;
 assert(!LocalTahoeABI::matches(page.data(),4096,0,true,true));++cases;
 KernelPatcher patcher;IOPCIDevice gpu;
 for(unsigned condition=0;condition<8;++condition){
  requested=true;currentKernel=Tahoe;gpu.id=0x46808086;gpu.revision=0x0c;gpu.overrideID=false;version=qualified;routeAllowed=true;localTahoeHookReady=false;
  if(condition==0)requested=false;
  if(condition==1)currentKernel=Other;
  if(condition==2)gpu.id=0xA7808086;
  if(condition==3)version="different kernel";
  if(condition==4)routeAllowed=false;
  if(condition==6)gpu.revision=0x0b;
  if(condition==7)gpu.overrideID=true;
  prepareLocalTahoeABI(patcher,condition==5?nullptr:&gpu,XELP::identify(gpu.id,gpu.revision,gpu.overrideID?0x9A498086:gpu.id));assert(!localTahoeHookReady);++cases;
 }
 requested=true;currentKernel=Tahoe;gpu.id=0x46808086;gpu.revision=0x0c;gpu.overrideID=false;version=qualified;routeAllowed=true;
 prepareLocalTahoeABI(patcher,&gpu,XELP::identify(gpu.id,gpu.revision));assert(localTahoeHookReady);++cases;
 int validated=123,tainted=124,nx=125;
 ActualKernelPageValidator hooked=&localTahoeValidatePage;
 for(unsigned condition=0;condition<14;++condition){
  page.assign(localTahoeReferencePage,localTahoeReferencePage+4096);localTahoePagesPatched=0;originalCalls=0;
  localTahoeHookReady=condition!=0;statusValidated=condition==1?0:condition==2?1:15;
  statusTainted=condition==3?15:0;statusNX=condition==4?15:0;
  writeAllowed=condition!=5;race=condition==6;racePage=page.data();writing=false;
  if(condition==7)page[0x200]^=1;
  expectedData=condition==8?nullptr:page.data();expectedOffset=condition==9?4096:0;
  expectedValidated=condition==10?nullptr:&validated;
  expectedTainted=condition==11?nullptr:&tainted;
  expectedNX=condition==12?nullptr:&nx;
  hooked(&expectedNode,&expectedPager,expectedOffset,expectedData,expectedValidated,expectedTainted,expectedNX);
  assert(originalCalls==1 && !writing);
  if(expectedValidated)assert(validated==statusValidated);
  if(expectedTainted)assert(tainted==statusTainted);
  if(expectedNX)assert(nx==statusNX);
  assert(localTahoePagesPatched==(condition==13?1U:0U));++cases;
 }
 unsigned changed=0;for(size_t i=0;i<4096;++i)changed+=page[i]!=localTahoeReferencePage[i];assert(changed==8);++cases;
 // Repeat-validation input is already patched: leave it and all outputs intact.
 originalCalls=0;hooked(&expectedNode,&expectedPager,0,page.data(),&validated,&tainted,&nx);
 assert(originalCalls==1 && localTahoePagesPatched==1 && validated==15 && tainted==0 && nx==0);++cases;

 // Replay the real TGLVA page through the same seven-argument production hook.
 page.assign(localVideoReferencePage,localVideoReferencePage+4096);
 assert(LocalVideoABI::matches(page.data(),4096,LocalVideoABI::FileOffset,true,false));++cases;
 for(size_t i=0;i<4096;++i){page[i]^=1;assert(!LocalVideoABI::matches(page.data(),4096,LocalVideoABI::FileOffset,true,false));page[i]^=1;++cases;}
 for(auto off:{uint64_t(0),uint64_t(4096),LocalVideoABI::FileOffset+1}){assert(!LocalVideoABI::matches(page.data(),4096,off,true,false));++cases;}
 for(unsigned state=0;state<4;++state){
  page.assign(localVideoReferencePage,localVideoReferencePage+4096);
  localTahoeHookReady=true;writeAllowed=true;race=false;writing=false;
  localVideoPagesPatched=0;statusValidated=state==1?0:15;statusTainted=state==2?1:0;statusNX=state==3?1:0;
  expectedData=page.data();expectedOffset=LocalVideoABI::FileOffset;
  expectedValidated=&validated;expectedTainted=&tainted;expectedNX=&nx;originalCalls=0;
  hooked(&expectedNode,&expectedPager,expectedOffset,expectedData,&validated,&tainted,&nx);
  assert(originalCalls==1 && !writing && validated==statusValidated && tainted==statusTainted && nx==statusNX);
  assert(localVideoPagesPatched==(state==0?1U:0U));
  unsigned changed=0;for(size_t i=0;i<4096;++i)changed+=page[i]!=localVideoReferencePage[i];assert(changed==(state==0?3U:0U));++cases;
 }
 page.assign(localVideoReferencePage,localVideoReferencePage+4096);LocalVideoABI::apply(page.data());
 assert(!memcmp(page.data()+LocalVideoABI::PatchOffset,"25G332",7));
 assert(!LocalVideoABI::matches(page.data(),4096,LocalVideoABI::FileOffset,true,false));++cases;

 page.assign(localGVAReferencePage,localGVAReferencePage+4096);
 assert(LocalGVA::matches(page.data(),4096,LocalGVA::FileOffset,true,false));++cases;
 for(size_t i=0;i<4096;++i){page[i]^=1;assert(!LocalGVA::matches(page.data(),4096,LocalGVA::FileOffset,true,false));page[i]^=1;++cases;}
 for(auto off:{uint64_t(0),uint64_t(4096),LocalGVA::FileOffset+1}){assert(!LocalGVA::matches(page.data(),4096,off,true,false));++cases;}
 for(unsigned state=0;state<10;++state){
  page.assign(localGVAReferencePage,localGVAReferencePage+4096);
  localTahoeHookReady=state!=4;writeAllowed=state!=5;race=false;writing=false;
  localGVAPagesPatched=0;statusValidated=state==1?0:15;statusTainted=state==2?1:0;statusNX=state==3?1:0;
  expectedData=page.data();expectedOffset=LocalGVA::FileOffset;
  expectedValidated=state==6?nullptr:&validated;expectedTainted=state==7?nullptr:&tainted;expectedNX=state==8?nullptr:&nx;
  if(state==9)page[44]^=1;
  originalCalls=0;hooked(&expectedNode,&expectedPager,expectedOffset,expectedData,expectedValidated,expectedTainted,expectedNX);
  assert(originalCalls==1 && !writing);
  if(expectedValidated)assert(validated==statusValidated);
  if(expectedTainted)assert(tainted==statusTainted);
  if(expectedNX)assert(nx==statusNX);
  assert(localGVAPagesPatched==(state==0?1U:0U));
  unsigned changed=0;for(size_t i=0;i<4096;++i)changed+=page[i]!=localGVAReferencePage[i];assert(changed==((state==0||state==9)?1U:0U));++cases;
 }
 page.assign(localGVAReferencePage,localGVAReferencePage+4096);LocalGVA::apply(page.data());
 assert(!LocalGVA::matches(page.data(),4096,LocalGVA::FileOffset,true,false));++cases;
 printf("%u production cases passed; independent seven-argument ABI; all three validator outputs preserved\n",cases);
}
'''.replace('// PRODUCTION', production)

with tempfile.TemporaryDirectory(prefix='wex-uhd770-page-') as temp:
    p = Path(temp)
    references=[]
    for kind,header,var,offset,original in [
        ('metal','kern_local_tahoe_abi.hpp','localTahoeReferencePage',0xdb7,
         bytes.fromhex('b8 32 35 47 32 33 45 b0 b9 32 34 31 00 33 4d b3 09 c1 75 b4')),
        ('video','kern_local_video_abi.hpp','localVideoReferencePage',0xd73,b'25G241\0'),
        ('gva','kern_local_gva.hpp','localGVAReferencePage',2216,b'M')]:
        text=(options.source_dir/header).read_text()
        match=re.search(r'ReferenceSHA256\[\]\{([^}]+)\}',text)
        expected=bytes(int(v.strip(),0) for v in match[1].split(','))
        if options.reference_pages:
            data=(options.reference_pages/(kind+'.bin')).read_bytes()
            assert len(data)==4096 and hashlib.sha256(data).digest()==expected, kind
        else:
            data=bytearray((i*37+17)%256 for i in range(4096))
            data[offset:offset+len(original)]=original
            if kind=='metal':
                data[0xaea:0xaea+20]=bytes.fromhex('b8 32 35 47 32 33 45 d0 b9 32 34 31 00 33 4d d3 09 c1 75 a9')
            # Only the identity is substituted in this temporary test header.
            # The matching, patching and production callback code are unchanged.
            digest=','.join(hex(v) for v in hashlib.sha256(data).digest())
            text=text[:match.start(1)]+digest+text[match.end(1):]
        (p/header).write_text(text)
        references.append('static const uint8_t '+var+'[4096]{'+','.join(str(v) for v in data)+'};')
    (p/'reference_pages.hpp').write_text('\n'.join(references))
    (p/'test.cpp').write_text(fixture)
    subprocess.run(['clang++','-std=c++17','-O1','-g','-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer','-I'+str(options.source_dir),
                    str(p/'test.cpp'),'-o',str(p/'test')],check=True)
    run=subprocess.run([str(p/'test')],capture_output=True,text=True,timeout=60)
    result={'fixture':'private-exact' if options.reference_pages else 'synthetic',
            'exit_code':run.returncode,'stdout':run.stdout,'stderr':run.stderr}
    options.output.parent.mkdir(parents=True,exist_ok=True)
    options.output.write_text(json.dumps(result,indent=2)+'\n')
    assert run.returncode==0,result
    print(json.dumps(result,indent=2))
