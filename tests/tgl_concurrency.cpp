#include "kern_tgl_concurrency.hpp"
#include <atomic>
#include <cassert>
#include <cstdio>
#include <thread>
#include <vector>
using namespace TGLConcurrency;
int main() {
 {
  Trace<2,4> t;Trace<2,4>::Snapshot s;
  auto a=t.enter(10,11,Submit,101,0,123,456),b=t.enter(20,12,CSB,101,0);
  assert(a.span && b.span && !t.enter(30,13,Wait,102,0).span);
  t.snapshot(s);assert(s.header[6]==1 && s.active[0].record.q[3]==11 && s.active[1].record.q[3]==12);
  t.leave(a,40,7);t.snapshot(s);assert(!s.active[0].sequence && s.active[1].sequence);
  for(unsigned i=0;i<10;++i){auto c=t.enter(50+i,14,Submit,103,2);t.leave(c,100+i,9);}
  t.freeze(200);t.freeze(300);t.leave(b,400);
  t.snapshot(s);assert(s.header[9]==200 && s.header[10]==2 && !s.active[1].sequence);
  assert(s.firstActive[1].sequence==b.span && s.firstActive[1].record.q[3]==12);
  assert(!t.enter(500,15,Wait,103,0).span);
  for(auto &r:s.recent)assert(r.sequence>=s.header[7]-3 && r.record.q[3]==14);
 }
 // Force reuse while snapshots run. Every visible payload must belong to one
 // writer generation; pending native calls remain visible beyond ring wrap.
 Trace<32,64> t;std::atomic<bool> done{false};std::atomic<unsigned> scans{0};
 auto check=[](const Row &row) {
  if(!row.sequence)return;
  const auto *q=row.record.q;
  assert(q[3]>=1 && q[3]<=8 && q[4]==Submit && q[5]==0x1000+q[3]);
  assert(q[6]==q[3]%4 && q[7]==q[3]*17 && q[8]==(q[7]^0xabcdef));
  assert(q[1]<=1 && q[10]>0 && (q[1]==0 ? q[2]==q[10] && q[9]==0 : q[2]==q[10]+1 && q[9]==q[3]+100));
 };
 std::thread reader([&] {
  Trace<32,64>::Snapshot s;
  do {t.snapshot(s);for(auto &r:s.active)check(r);for(auto &r:s.recent)check(r);++scans;} while(!done.load());
 });
 std::vector<std::thread> workers;
 for(uint64_t id=1;id<=8;++id)workers.emplace_back([&,id] {
  for(uint64_t i=1;i<=4000;++i) {
   auto token=t.enter(i*2,id,Submit,0x1000+id,id%4,id*17,(id*17)^0xabcdef);
   assert(token.span);if(!(i%17))std::this_thread::yield();t.leave(token,i*2+1,id+100);
  }
 });
 for(auto &w:workers)w.join();done=true;reader.join();
 Trace<32,64>::Snapshot s;t.snapshot(s);assert(scans && s.header[4]==32000 && s.header[5]==32000 && !s.header[6]);
 for(auto &r:s.active)assert(!r.sequence);
 puts("PASS: bounded active calls, ring wrap, overflow, immutable freeze and 32000 concurrent spans with live snapshots");
}
