// Qualified donor submission contract; caller retains native streamer serialization.
#ifndef kern_tgl_same_tail_hpp
#define kern_tgl_same_tail_hpp
#include <stdint.h>
#include <string.h>
namespace TGLSameTail {
struct Entry {
 uint64_t owner,streamer,generation,item,context,descriptor,image,tail;
};
struct State {
 Entry previous{},first{};
 // schema, attempts, valid, retained active item, same tail, forced, native forced, rejected
 uint64_t counts[8] {1};
};
// Bookkeeping only: never hold this guard over a native GPU submission or
// wait for another CPU. A contended diagnostic read is explicitly unavailable.
struct Tracker {
 State state{};
 uint32_t busy{};
 uint64_t skipped{};
 uint64_t invalidations{},seenInvalidations{};
 bool acquire() {
  uint32_t free=0;
  if(__atomic_compare_exchange_n(&busy,&free,1U,false,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED))return true;
  __atomic_fetch_add(&skipped,1ULL,__ATOMIC_RELAXED);return false;
 }
 void release() {__atomic_store_n(&busy,0U,__ATOMIC_RELEASE);}
 bool begin() {
  if(!acquire()) {
   __atomic_fetch_add(&invalidations,1ULL,__ATOMIC_RELEASE);return false;
  }
  const auto epoch=__atomic_load_n(&invalidations,__ATOMIC_ACQUIRE);
  if(epoch!=seenInvalidations) {state.previous={};seenInvalidations=epoch;}
  return true;
 }
 bool snapshot(State &out) {
  if(!acquire())return false;
  out=state;release();return true;
 }
 void invalidate() {
  if(!begin())return;
  state.previous={};release();
 }
};
// Linux execlists_update_context avoids equal TAIL lite restores. Apply only
// to an unchanged active first work item whose prior submission we witnessed.
// A new item/context, advanced tail, reset generation or failed read declines.
// This deliberately does not implement Linux's broader rewind/WA-tail policy.
template<class Read,class Force>
void prepare(State &s,uint64_t owner,uint64_t streamer,uint64_t generation,Read read,Force force) {
 ++s.counts[1];Entry e{owner,streamer,generation};
 auto field=[&](uint64_t p,unsigned off,void *out,unsigned n) {
  return p && p+off+n>=p && read(p+off,out,n)==n;
 };
 uint64_t actualOwner=0,desc=0,activeItem=0,buffer=0,length=0;
 uint32_t bank=2,tail=0;uint8_t engine=255,forced=0;
 bool ok=field(streamer,0x10,&actualOwner,8) && actualOwner==owner &&
  field(streamer,0x28,&desc,8) && field(desc,0,&engine,1) && engine==0 &&
  field(streamer,0x50,&bank,4) && bank<2 &&
  field(streamer,0x30+bank*16,&activeItem,8) &&
  field(streamer,0x30+(1-bank)*16,&e.item,8) && field(e.item,0,&e.context,8) &&
  field(e.context,0x50,&actualOwner,8) && actualOwner==owner &&
  field(e.context,0x6c,&engine,1) && engine==0 &&
  field(e.context,0x89,&e.descriptor,8) && (e.descriptor&1) &&
  field(e.context,0x98,&buffer,8) && field(buffer,0x20,&length,8) && length==81920 &&
  field(buffer,0x38,&e.image,8) && field(e.image,0x101c,&tail,4) && !(tail&7) &&
  field(e.context,0xc9,&forced,1);
 if(!ok) {++s.counts[7];s.previous={};return;}
 e.tail=tail;++s.counts[2];
 if(activeItem==e.item) {
  ++s.counts[3];
  if(!memcmp(&e,&s.previous,sizeof(e))) {
   ++s.counts[4];
   if(forced)++s.counts[6];
   else {
    force(e.context+0xc9);
    if(!s.counts[5])s.first=e;
    ++s.counts[5];
   }
  }
 }
 s.previous=e;
}
template<class Read,class Force>
void prepare(Tracker &tracker,uint64_t owner,uint64_t streamer,uint64_t generation,Read read,Force force) {
 if(!tracker.begin())return;
 prepare(tracker.state,owner,streamer,generation,read,force);
 tracker.release();
}
}
#endif
