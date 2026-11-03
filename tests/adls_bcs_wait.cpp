#include "kern_adls_bcs_wait.hpp"
#include <array>
#include <cassert>
int main() {
 const auto admitted=XELP::identify(0x46808086,0x0C);
 assert(ADLSBCSWait::requested(admitted,XELP::OS::Tahoe,true,true,true));
 for(const auto &device:XELP::DeviceTable) for(unsigned rev=0;rev<=256;++rev) {
  const uint32_t id=(uint32_t(device.device)<<16)|0x8086;
  const bool expected=id==0x46808086 && rev==0x0C;
  assert(ADLSBCSWait::requested(XELP::identify(id,rev),XELP::OS::Tahoe,true,true,true)==expected);
  if(!expected) assert(!ADLSBCSWait::requested(XELP::identify(id,rev,0x46808086),XELP::OS::Tahoe,true,true,true));
 }
 for(auto os:{XELP::OS::Unknown,XELP::OS::Donor,XELP::OS::BigSur,XELP::OS::Monterey,
              XELP::OS::Ventura,XELP::OS::Sonoma,XELP::OS::Sequoia})
  assert(!ADLSBCSWait::requested(admitted,os,true,true,true));
 for(unsigned bits=0;bits<8;++bits)
  assert(ADLSBCSWait::requested(admitted,XELP::OS::Tahoe,bits&1,bits&2,bits&4)==(bits==7));
 auto bad=admitted;bad.gt=XELP::GT::Unknown;
 assert(!ADLSBCSWait::requested(bad,XELP::OS::Tahoe,true,true,true));
 assert(!ADLSBCSWait::requested(XELP::identify(0x46808086,0x0C,0x9A498086),XELP::OS::Tahoe,true,true,true));
 std::array<uint8_t,sizeof(ADLSBCSWait::Body)> original{},patched{};
 memcpy(original.data(),ADLSBCSWait::Body,original.size());patched=original;
 assert(!ADLSBCSWait::matches(nullptr,original.size()));
 for(size_t n=0;n<original.size();++n)assert(!ADLSBCSWait::matches(original.data(),n));
 assert(ADLSBCSWait::matches(original.data(),original.size()));
 // Apply emission first. A stopped installation may overreserve, never underreserve.
 assert(ADLSBCSWait::Sites[0]==0x125 && ADLSBCSWait::Sites[1]==0xD2);
 for(auto at:ADLSBCSWait::Sites) {
  assert(at+sizeof(ADLSBCSWait::Replace)<=patched.size() && original[at]==0xE8);
  memcpy(patched.data()+at,ADLSBCSWait::Replace,sizeof(ADLSBCSWait::Replace));
  assert(!ADLSBCSWait::matches(patched.data(),patched.size()));
  assert(ADLSBCSWait::matches(patched.data(),patched.size(),true)==(at==0xD2));
 }
 // Every byte in the complete original and patched body is guarded, not only CALLs.
 for(size_t i=0;i<original.size();++i) {
  original[i]^=1;assert(!ADLSBCSWait::matches(original.data(),original.size()));original[i]^=1;
  patched[i]^=1;assert(!ADLSBCSWait::matches(patched.data(),patched.size(),true));patched[i]^=1;
 }
}
