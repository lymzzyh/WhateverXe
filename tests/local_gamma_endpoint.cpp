#include "kern_local_gamma_endpoint.hpp"
#include <assert.h>
#include <stdio.h>
using LocalGammaEndpoint::Stream;
static void samples(Stream &s,uint32_t last=0x3fffffff) {
 for(unsigned i=0;i<1024;++i){uint32_t v=i==1023?last:i*(1U+(1U<<10)+(1U<<20));const auto old=v;assert(!s.write(1,s.index+4,v) && v==old);}
}
int main(){
 unsigned cases=0;
 for(unsigned pipe=0;pipe<3;++pipe)for(unsigned x=0;x<1024;++x){
  Stream s;s.begin(true,1,pipe,0x4a400+0x800*pipe,0x4a404+0x800*pipe,true);
  samples(s,x*(1U+(1U<<10)+(1U<<20)));
  for(unsigned j=0;j<6;++j){uint32_t v=x;assert(s.write(1,s.index+(j<3?0x20:0x30)+4*(j%3),v));assert(v==(uint64_t(x)*65536+511)/1023);}
  assert(s.mask==63 && !s.rejected);++cases;
 }
 for(unsigned condition=0;condition<10;++condition){
  Stream s;s.begin(condition!=0,condition==1?0:1,condition==2?3:0,0x4a400,condition==3?0x4a408:0x4a404,condition!=4);
  if(condition<5){uint32_t v=1023;assert(!s.eligible && !s.write(1,0x4a420,v) && v==1023);}
  else {
   samples(s);
   uint32_t v=condition==5?0x30000:condition==6?1022:1023;
   const auto reg=condition==7?0x4a424:condition==8?0x4ac20:0x4a420;
   const auto old=v;assert(!s.write(condition==9?2:1,reg,v) && v==old);
  }++cases;
 }
 Stream partial;partial.begin(true,1,0,0x4a400,0x4a404,true);uint32_t v=0;
 partial.write(1,0x4a404,v);v=1023;assert(!partial.write(1,0x4a420,v) && v==1023);++cases;
 Stream overflow;overflow.begin(true,1,0,0x4a400,0x4a404,true);samples(overflow);v=0;
 overflow.write(1,0x4a404,v);v=1023;assert(!overflow.write(1,0x4a420,v) && v==1023);++cases;
 Stream bad;bad.begin(true,1,0,0x4a400,0x4a404,true);v=0xc0000000;bad.write(1,0x4a404,v);assert(!bad.eligible);++cases;
 Stream custom;custom.begin(true,1,0,0x4a400,0x4a404,true);samples(custom,(255U<<20)|(512U<<10)|1023U);
 const uint32_t channels[]={255,512,1023};
 for(unsigned j=0;j<6;++j){v=channels[j%3];assert(custom.write(1,0x4a400+(j<3?0x20:0x30)+4*(j%3),v));assert(v==(uint64_t(channels[j%3])*65536+511)/1023);}
 assert(custom.actual[2]==65536);++cases;
 printf("%u gamma endpoint cases passed: all 10-bit endpoints/three pipes, ownership, preset, partial, order and custom channels\n",cases);
}
