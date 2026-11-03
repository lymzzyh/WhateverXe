#include "kern_tgl_context_cache.hpp"
#include <cassert>
#include <array>
int main() {
 const auto admitted=XELP::identify(0x46808086,0x0C);
 assert(TGLContextCache::adlsRequested(admitted,XELP::OS::Tahoe,true,true,true));
 // Selection must fail closed across every other physical device/stepping,
 // even if its device-id override asks for the admitted donor family.
 for(const auto &device:XELP::DeviceTable) for(unsigned revision=0;revision<=255;++revision) {
  const uint32_t identity=(uint32_t(device.device)<<16)|0x8086;
  const auto physical=XELP::identify(identity,revision);
  const bool expected=identity==0x46808086 && revision==0x0C;
  assert(TGLContextCache::adlsRequested(physical,XELP::OS::Tahoe,true,true,true)==expected);
  if(!expected) {
   const auto spoofed=XELP::identify(identity,revision,0x46808086);
   assert(!TGLContextCache::adlsRequested(spoofed,XELP::OS::Tahoe,true,true,true));
  }
 }
 for(auto os:{XELP::OS::Unknown,XELP::OS::Donor,XELP::OS::BigSur,XELP::OS::Monterey,
              XELP::OS::Ventura,XELP::OS::Sonoma,XELP::OS::Sequoia})
  assert(!TGLContextCache::adlsRequested(admitted,os,true,true,true));
 assert(!TGLContextCache::adlsRequested(admitted,XELP::OS::Tahoe,false,true,true));
 assert(!TGLContextCache::adlsRequested(admitted,XELP::OS::Tahoe,true,true,false));
 assert(!TGLContextCache::adlsRequested(admitted,XELP::OS::Tahoe,true,false,true));
 auto altered=admitted;altered.gt=XELP::GT::Unknown;
 assert(!TGLContextCache::adlsRequested(altered,XELP::OS::Tahoe,true,true,true));
 std::array<uint8_t,81920> image{},before{};std::array<uint8_t,8192> page{};
 const uint64_t gpu=0x402b3000;const uint32_t fields[]={0x21C0,uint32_t(gpu|5),0x21C4,0,0x21C8,0};
 memcpy(image.data()+0x1048,fields,sizeof(fields));before=image;
 assert(TGLContextCache::install(image.data(),image.size(),gpu));
 for(size_t i=0;i<image.size();++i)if((i<0x1054||i>=0x1058)&&(i<0x105C||i>=0x1060))assert(image[i]==before[i]);
 auto installed=image;assert(TGLContextCache::install(image.data(),image.size(),gpu));assert(image==installed);
 for(unsigned field:{0U,1U,2U,3U,4U,5U}) {
  image=before;uint32_t bad=0x12345678;memcpy(image.data()+0x1048+field*4,&bad,4);auto copy=image;
  assert(!TGLContextCache::install(image.data(),image.size(),gpu));assert(image==copy);
 }
 for(uint64_t bad:{0ULL,0x402b3001ULL,0xFFFFF000ULL,0x100000000ULL})assert(!TGLContextCache::install(before.data(),before.size(),bad));
 assert(!TGLContextCache::install(before.data(),0x105F,gpu));
 page.fill(0xA5);TGLContextCache::batch(page.data());uint32_t words[16];memcpy(words,page.data()+4096,64);
 assert(words[0]==0x11000001 && words[1]==0x20D8 && words[2]==0x00400040);
 for(unsigned i=3;i<16;++i)assert(!words[i]);
 for(unsigned i=0;i<8192;++i)if(i<4096||i>=4160)assert(page[i]==0xA5);
 for(uint32_t old=0;old<65536;++old)assert(((old&~(words[2]>>16))|(words[2]&0xffff))==(old|0x40));
}
