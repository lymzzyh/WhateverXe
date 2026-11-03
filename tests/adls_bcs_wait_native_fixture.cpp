// Execute the exact donor BCS emitter on the CPU. External callees are mocks;
// mapped machine code and GPU execution are outside sanitizer coverage.
#include "kern_adls_bcs_wait.hpp"
#include <sys/mman.h>
#include <cassert>
#include <fstream>
#include <vector>
#include <string>
#include <cstdio>
struct Result { std::vector<uint32_t> words; std::string order; unsigned reserved=0,submit=0; };
static Result result;
static unsigned mode,extra;static bool optional;
template<typename T> static void put(uint8_t *p,size_t at,T v){memcpy(p+at,&v,sizeof(v));}
static unsigned getMode(void*) {result.order+='G';return mode;}
static unsigned space(void*,int index) {result.order+='S';return optional && index<=59?extra:0;}
static unsigned serializeSpace(void*) {result.order+='C';return 1;}
static void reserve(void*,unsigned n) {result.order+='W';assert(!result.reserved);result.reserved=n;}
static void serialize(void*) {result.order+='Z';result.words.push_back(0xFEED0001);}
static bool insert(void*,unsigned,int index) {
 result.order+='I';if(!optional || index>59)return false;
 for(unsigned i=0;i<9;++i)result.words.push_back(0xBACE0000+i);return true;
}
static bool write(void*,uint32_t *words,unsigned n) {
 result.order+='M';assert(n==4 || n==5);result.words.insert(result.words.end(),words,words+n);return true;
}
static void submit(void*) {result.order+='U';++result.submit;}
static void jump(uint8_t *p,size_t off,uintptr_t target) {
 uint8_t j[14]={0xFF,0x25,0,0,0,0};memcpy(j+6,&target,8);memcpy(p+off,j,14);
}
int main(int argc,char **argv) {
 assert(argc==2);std::ifstream f(argv[1],std::ios::binary);
 std::vector<char> d((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());
 assert(d.size()>0xC8210 && ADLSBCSWait::matches(d.data()+ADLSBCSWait::Offset,d.size()-ADLSBCSWait::Offset));
 auto mem=(uint8_t*)mmap(nullptr,d.size(),PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANON,-1,0);
 assert(mem!=MAP_FAILED);memcpy(mem,d.data(),d.size());
 uint64_t cookie=0x12345678ABCDEF00ULL;put(mem,0xC8200,(uintptr_t)&cookie);
 jump(mem,0x42364,(uintptr_t)getMode);jump(mem,0x425F8,(uintptr_t)space);
 jump(mem,0x4266A,(uintptr_t)serializeSpace);jump(mem,0x416C8,(uintptr_t)reserve);
 jump(mem,0x42692,(uintptr_t)serialize);jump(mem,0x4260A,(uintptr_t)insert);
 jump(mem,0x41E7A,(uintptr_t)write);
 uintptr_t vtable[64]={};vtable[0x138/8]=(uintptr_t)submit;
 auto wait=(void(*)(void*,unsigned,unsigned))(mem+ADLSBCSWait::Offset);
 unsigned cases=0;
 for(mode=0;mode<2;++mode)for(unsigned serial=0;serial<2;++serial)
 for(unsigned self:{0U,8U,63U})for(unsigned index:{0U,1U,8U,32U,59U,60U,63U})
 for(unsigned stamp:{0U,1U,0x7FFFFFFFU,0x80000000U,0xFFFFFFFFU})
 for(uint64_t base:{0x40000000ULL,0x123456780000ULL,0xFFFFFFFFE000ULL})
 for(unsigned reserveExtra:{9U,16U,21U}) {
  extra=reserveExtra;Result native;
  for(unsigned variant=0;variant<4;++variant) {
   // 0: native optional path declines; 1: accepts; 2: full patch;
   // 3: emission disabled first, before reservation patch succeeds.
   optional=variant!=0;result={};
   uint8_t ring[0x100]={},owner[0x1300]={},scheduler[0x20]={};
   put(ring,0,(uintptr_t)vtable);put(ring,0x10,(uintptr_t)owner);
   put(ring,0x28,base);put(ring,0x38,self);put(ring,0x4C,0xFFFFFFFFU);
   put(owner,0x1250,(uintptr_t)scheduler);scheduler[0xC]=serial?16:0;
   memcpy(mem+ADLSBCSWait::Offset,ADLSBCSWait::Body,sizeof(ADLSBCSWait::Body));
   if(variant>=2)memcpy(mem+ADLSBCSWait::Offset+ADLSBCSWait::Sites[0],ADLSBCSWait::Replace,sizeof(ADLSBCSWait::Replace));
   if(variant==2)memcpy(mem+ADLSBCSWait::Offset+ADLSBCSWait::Sites[1],ADLSBCSWait::Replace,sizeof(ADLSBCSWait::Replace));
   wait(ring,stamp,index);++cases;
   unsigned events;memcpy(&events,ring+0x4C,4);assert(events==0 && result.submit==1);
   assert(result.words.size()<=result.reserved);
   const unsigned optionalReservation=(variant==1 || variant==3) && index<=59?extra:0;
   assert(result.reserved==9+serial+optionalReservation);
   if(variant==0) {
    native=result;assert(result.words.size()==9+serial);
    const auto *w=result.words.data()+serial;
    const uint64_t metadata=(base+uint64_t(self+64)*64)&0xFFFFFFFFFFFFULL;
    const uint64_t dependency=(base+uint64_t(index)*64)&0xFFFFFFFFFFFCULL;
    assert(w[0]==0x13004003 && w[1]==(uint32_t(metadata)&~7U | mode*4));
    assert(w[2]==uint32_t(metadata>>32) && w[3]==stamp && w[4]==(index&0xFFFF));
    assert(w[5]==(0x0E009002U | (mode?0x400000U:0U)) && w[6]==stamp);
    assert(w[7]==uint32_t(dependency) && w[8]==uint32_t(dependency>>32));
   } else {
    auto mandatory=result.words;
    if(variant==1 && index<=59)mandatory.erase(mandatory.begin()+serial,mandatory.begin()+serial+9);
    assert(mandatory==native.words);
    auto normalize=[](std::string s){for(char c:{'S','I'}){auto p=s.find(c);if(p!=std::string::npos)s.erase(p,1);}return s;};
    assert(normalize(result.order)==normalize(native.order));
    if(variant==2)assert(result.order.find('S')==std::string::npos && result.order.find('I')==std::string::npos);
   }
  }
 }
 assert(!munmap(mem,d.size()));
 printf("PASS: %u native BCS emitter replays; unchanged hardware waits, stamps, addresses and submit order; full and partial patch reservation checked. No GPU execution.\n",cases);
}
