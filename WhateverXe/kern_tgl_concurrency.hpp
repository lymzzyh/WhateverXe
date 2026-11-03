// Bounded diagnostic records; no allocation, waiting, driver locks or MMIO.
#ifndef kern_tgl_concurrency_hpp
#define kern_tgl_concurrency_hpp
#include <stdint.h>

namespace TGLConcurrency {
enum Kind : uint64_t { Submit=1, CSB, Reset, Wait, Recovery, ForceWake, BlitSubmit };
struct Record {
 // span, phase (0 enter / 1 return), ns, thread, kind, object, engine,
 // argument0, argument1, result, entry ns, active slot, entry/return CPU,
 // entry/return interrupt-enabled state. CPU is observational, not an affinity.
 uint64_t q[16] {};
};
struct Row { uint64_t sequence {}; Record record {}; };
struct Token { uint64_t span {}; unsigned slot {}; };
static_assert(__atomic_always_lock_free(sizeof(uint64_t),nullptr),"native 64-bit atomics required");

template<unsigned Active=64,unsigned Recent=1024> struct Trace {
 struct Slot { uint32_t owned {}; uint64_t sequence {}; Record record {}; };
 struct Snapshot {
  uint64_t header[12] {};
  Row active[Active] {},firstActive[Active] {},recent[Recent] {};
 };
 Slot active[Active] {},recent[Recent] {};
 Row firstActive[Active] {};
 uint64_t spans {},returns {},activeDrops {},events {},eventDrops {},frozenAt {};
 uint32_t freezeState {};

 static bool read(const Slot &s,Row &out) {
  const auto before=__atomic_load_n(&s.sequence,__ATOMIC_ACQUIRE);
  if(!before)return false;
  Record r;
  // Payload words are atomic too: a rejected optimistic snapshot must not
  // contain a C++ data race with a reused slot. Release/acquire payload pairs
  // also order a later generation's invalidation before the final sequence read.
  for(unsigned j=0;j<16;++j)r.q[j]=__atomic_load_n(s.record.q+j,__ATOMIC_ACQUIRE);
  if(before!=__atomic_load_n(&s.sequence,__ATOMIC_ACQUIRE))return false;
  out.sequence=before;out.record=r;return true;
 }
 static void publish(Slot &s,uint64_t sequence,const Record &r) {
  __atomic_store_n(&s.sequence,0ULL,__ATOMIC_RELEASE);
  for(unsigned j=0;j<16;++j)__atomic_store_n(s.record.q+j,r.q[j],__ATOMIC_RELEASE);
  __atomic_store_n(&s.sequence,sequence,__ATOMIC_RELEASE);
 }
 bool frozen() const {return __atomic_load_n(&freezeState,__ATOMIC_ACQUIRE)!=0;}
 void append(const Record &r) {
  if(frozen())return;
  const auto n=__atomic_fetch_add(&events,1ULL,__ATOMIC_RELAXED);
  auto &s=recent[n%Recent];uint32_t free=0;
  if(!__atomic_compare_exchange_n(&s.owned,&free,1U,false,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED)) {
   __atomic_fetch_add(&eventDrops,1ULL,__ATOMIC_RELAXED);return;
  }
  if(!frozen())publish(s,n+1,r);
  __atomic_store_n(&s.owned,0U,__ATOMIC_RELEASE);
 }
 Token enter(uint64_t ns,uint64_t thread,Kind kind,uint64_t object,uint64_t engine,uint64_t a=0,uint64_t b=0,uint64_t cpu=UINT64_MAX,uint64_t irq=UINT64_MAX) {
  if(frozen())return {};
  const auto span=__atomic_fetch_add(&spans,1ULL,__ATOMIC_RELAXED)+1;
  for(unsigned i=0;i<Active;++i) {
   auto &s=active[i];uint32_t free=0;
   if(!__atomic_compare_exchange_n(&s.owned,&free,1U,false,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED))continue;
   if(frozen()) {__atomic_store_n(&s.owned,0U,__ATOMIC_RELEASE);return {};}
   Record r{{span,0,ns,thread,kind,object,engine,a,b,0,ns,i,cpu,UINT64_MAX,irq,UINT64_MAX}};
   publish(s,span,r);append(r);return {span,i};
  }
  __atomic_fetch_add(&activeDrops,1ULL,__ATOMIC_RELAXED);return {};
 }
 void leave(Token t,uint64_t ns,uint64_t result=0,uint64_t cpu=UINT64_MAX,uint64_t irq=UINT64_MAX) {
  if(!t.span || t.slot>=Active)return;
  auto &s=active[t.slot];Row row;
  if(!read(s,row) || row.sequence!=t.span)return;
  row.record.q[1]=1;row.record.q[2]=ns;row.record.q[9]=result;row.record.q[13]=cpu;row.record.q[15]=irq;
  append(row.record);
  __atomic_store_n(&s.sequence,0ULL,__ATOMIC_RELEASE);
  __atomic_store_n(&s.owned,0U,__ATOMIC_RELEASE);
  __atomic_fetch_add(&returns,1ULL,__ATOMIC_RELAXED);
 }
 void freeze(uint64_t ns) {
  uint32_t empty=0;
  if(!__atomic_compare_exchange_n(&freezeState,&empty,1U,false,__ATOMIC_ACQ_REL,__ATOMIC_RELAXED))return;
  __atomic_store_n(&frozenAt,ns,__ATOMIC_RELEASE);
  // A changing/busy observation is absent, never guessed or waited for.
  for(unsigned i=0;i<Active;++i)read(active[i],firstActive[i]);
  __atomic_store_n(&freezeState,2U,__ATOMIC_RELEASE);
 }
 void snapshot(Snapshot &out) const {
  out.header[0]=1;out.header[1]=Active;out.header[2]=Recent;out.header[3]=sizeof(Row);
  out.header[4]=__atomic_load_n(&spans,__ATOMIC_ACQUIRE);
  out.header[5]=__atomic_load_n(&returns,__ATOMIC_ACQUIRE);
  out.header[6]=__atomic_load_n(&activeDrops,__ATOMIC_ACQUIRE);
  out.header[7]=__atomic_load_n(&events,__ATOMIC_ACQUIRE);
  out.header[8]=__atomic_load_n(&eventDrops,__ATOMIC_ACQUIRE);
  out.header[10]=__atomic_load_n(&freezeState,__ATOMIC_ACQUIRE);
  out.header[9]=__atomic_load_n(&frozenAt,__ATOMIC_ACQUIRE);out.header[11]=0;
  for(unsigned i=0;i<Active;++i) {
   out.active[i]={};read(active[i],out.active[i]);
   out.firstActive[i]=out.header[10]==2?firstActive[i]:Row{};
  }
  for(unsigned i=0;i<Recent;++i){out.recent[i]={};read(recent[i],out.recent[i]);}
 }
};
}
#endif
