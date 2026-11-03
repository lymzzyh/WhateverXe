#pragma once
#include "kern_display13_color.hpp"
namespace LocalGammaEndpoint {
// Normalize only a completed native user-gamma upload's six endpoints.
// Palette samples stay in 10-bit units; EXT/EXT2_GC_MAX use u3.16.
// Linux v6.12 intel_color.c: ivb_load_lut_ext_max/glk_load_lut_ext2_max.
struct Stream {
 bool eligible {};
 uintptr_t access {};
 uint32_t index {},samples {},last {},mask {},rejected {};
 uint32_t original[6] {},actual[6] {};
 void begin(bool qualified,uintptr_t owner,unsigned pipe,uint32_t i,uint32_t d,bool userGamma) {
  *this={};access=owner;index=i;
  eligible=qualified && owner && userGamma && Display13Color::registerPair(pipe,i,d,false);
 }
 bool write(uintptr_t owner,uint64_t reg,uint32_t &value) {
  if(!eligible || owner!=access)return false;
  if(reg==index+4) {
   if(samples>=1024 || (value&0xc0000000U)){eligible=false;++rejected;return false;}
   last=value;++samples;return false;
  }
  const auto channel=Display13Color::maxChannel(index,reg);
  if(channel>=6)return false;
  if(samples!=1024 || mask!=(1U<<channel)-1){eligible=false;++rejected;return false;}
  const auto endpoint=(last>>(20-10*(channel%3)))&1023U;
  if(value>1023 || value!=endpoint){eligible=false;++rejected;return false;}
  original[channel]=value;
  value=Display13Color::gamma10MaxToU16(value);
  actual[channel]=value;mask|=1U<<channel;return true;
 }
};
}
